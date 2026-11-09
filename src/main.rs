// zeno — локальный аналог VirusTotal с открытым кодом.
//
// Модули:
//   config   — конфигурация (zeno.toml / ~/.zeno/config.toml)
//   hashes   - потоковые MD5/SHA1/SHA256
//   lookups  - открытые базы: CIRCL HashLookup, MalwareBazaar (только SHA-256, файлы не покидают ПК)
//   clamd    - сканирование через ClamAV clamd (TCP INSTREAM)
//   engines  - внешние движки (clamscan, YARA-X и любые другие)

mod archives;
mod clamd;
mod config;
mod engines;
mod hashes;
mod lookups;
mod run;

use clap::{Parser, Subcommand, ValueEnum};
use config::Config;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use walkdir::{DirEntry, WalkDir};

// ---------- результат одного файла ----------

#[derive(Serialize, Default, Debug)]
struct FileResult {
    path: String,
    size: u64,
    md5: String,
    sha1: String,
    sha256: String,
    /// файл известен чистым (есть в hashlookup как известный, без детектов)
    known_clean: bool,
    /// найденные детекты движками/базами
    detections: Vec<String>,
    /// ошибки при обработке файла (недоступность сети, clamd, движка...)
    errors: Vec<String>,
}

impl FileResult {
    fn verdict(&self) -> &'static str {
        if !self.detections.is_empty() {
            "MALICIOUS"
        } else if !self.errors.is_empty() && self.sha256.is_empty() {
            "ERROR"
        } else if self.known_clean {
            "KNOWN-CLEAN"
        } else {
            "CLEAN"
        }
    }
}

// ---------- CLI ----------

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Out {
    Table,
    Json,
}

#[derive(Parser)]
#[command(
    name = "zeno",
    version,
    about = "Локальный аналог VirusTotal на открытых движках: хэши + открытые базы (CIRCL HashLookup, MalwareBazaar) + ClamAV / YARA-X."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Просканировать файл или папку
    Scan {
        /// файл или папка для проверки
        path: PathBuf,
        /// формат вывода
        #[arg(value_enum, default_value = "table")]
        out: Out,
        /// не ходить в сеть (только локальные движки)
        #[arg(long)]
        offline: bool,
        /// не сканировать через clamd даже если настроен
        #[arg(long)]
        no_clamd: bool,
        /// переопределить лимит размера файла для хэширования, МБ
        #[arg(long)]
        max_size_mb: Option<u64>,
        /// не заглядывать внутрь архивов (.zip/.tar/.tar.gz)
        #[arg(long)]
        no_archives: bool,
    },
    /// Проверить доступность открытых баз и движков
    Check,
    /// Показать настроенные движки
    Engines,
    /// Запустить файл в изолированной среде (РЕАЛЬНОЕ выполнение, см. docs/emulation.md)
    Run {
        /// файл для запуска
        file: PathBuf,
        /// цель: alpine (Linux ELF в Docker) | windows (Cuckoo3) | macos (OSX-KVM, только проверка)
        #[arg(long)]
        target: String,
        /// таймаут выполнения, секунд
        #[arg(long, default_value_t = 60)]
        timeout: u64,
        /// вывод в JSON
        #[arg(long)]
        json: bool,
        /// подтвердить, что вы понимаете риск реального выполнения кода
        #[arg(long)]
        yes: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let cfg = Config::load();
    match cli.cmd {
        Cmd::Scan { path, out, offline, no_clamd, max_size_mb, no_archives } => {
            let mut cfg = cfg.clone();
            if no_clamd {
                cfg.clamd_host = None;
            }
            if let Some(mb) = max_size_mb {
                cfg.max_file_size_mb = mb;
            }
            command_scan(&cfg, &path, out == Out::Json, offline, no_archives)
        }
        Cmd::Check => command_check(&cfg),
        Cmd::Engines => command_engines(&cfg),
        Cmd::Run { file, target, timeout, json, yes } => command_run(&cfg, &file, &target, timeout, json, yes),
    }
}

// ---------- сбор списка файлов ----------

fn collect_files(root: &Path, cfg: &Config) -> Vec<PathBuf> {
    if root.is_file() {
        return vec![root.to_path_buf()];
    }
    let ignored: Vec<String> = cfg.ignore_dirs.clone();
    let walker = WalkDir::new(root).follow_links(false).into_iter().filter_entry(|e: &DirEntry| {
        if e.depth() == 0 {
            return true;
        }
        if !e.file_type().is_dir() {
            return true;
        }
        let name = e.file_name().to_string_lossy().to_string();
        !ignored.contains(&name)
    });
    let mut files = Vec::new();
    for entry in walker.flatten() {
        if entry.file_type().is_file() {
            files.push(entry.into_path());
        }
    }
    files.sort();
    files
}

// ---------- скан одного файла ----------

fn scan_one(path: &Path, cfg: &Config, offline: bool) -> FileResult {
    let mut res = FileResult {
        path: path.display().to_string(),
        ..Default::default()
    };

    // 1) хэши (потоково, с лимитом)
    let max_bytes = cfg.max_file_size_mb.saturating_mul(1024 * 1024);
    match hashes::compute(path, max_bytes) {
        Ok(h) => {
            res.size = h.size;
            res.md5 = h.md5;
            res.sha1 = h.sha1;
            res.sha256 = h.sha256;
            if h.truncated {
                res.errors
                    .push(format!("file larger than {} MB, hashes are truncated", cfg.max_file_size_mb));
            }
        }
        Err(e) => {
            res.errors.push(format!("{e:#}"));
            return res; // без хэшей нет смысла идти дальше
        }
    }

    // 2) открытые базы (только SHA-256)
    if !offline {
        match lookups::hashlookup_circl(&res.sha256) {
            Ok(lookups::LookupHit::Malicious(labels)) => {
                for l in labels {
                    res.detections.push(l);
                }
            }
            Ok(lookups::LookupHit::KnownClean) => res.known_clean = true,
            Ok(lookups::LookupHit::Unknown) => {}
            Err(e) => res.errors.push(format!("{e:#}")),
        }
        match lookups::malwarebazaar_known(&res.sha256, cfg.malwarebazaar_auth_key.as_deref()) {
            Ok(true) => res.detections.push("malwarebazaar: known sample".to_string()),
            Ok(false) => {}
            Err(e) => res.errors.push(format!("{e:#}")),
        }
    }

    // 3) ClamAV clamd
    if let Some(host) = cfg.clamd_host.clone() {
        match clamd::scan(path, &host, cfg.clamd_port) {
            Ok(Some(hit)) => res.detections.push(hit),
            Ok(None) => {}
            Err(e) => res.errors.push(format!("{e:#}")),
        }
    }

    // 4) внешние движки
    for (name, engine) in &cfg.engines {
        match engines::run(engine, path) {
            Ok(hits) => {
                for hit in hits {
                    res.detections.push(format!("{name}: {hit}"));
                }
            }
            Err(e) => res.errors.push(format!("{e:#}")),
        }
    }

    res
}

// ---------- раскрытие архивов ----------

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Сканирует цель: обычный файл либо архив (.zip/.tar/.tar.gz) с содержимым.
/// Для архива каждый файл внутри сканируется как отдельная запись,
/// метка пути — "archive.zip!inner/path".
fn scan_target(path: &Path, cfg: &Config, offline: bool, no_archives: bool) -> Vec<FileResult> {
    let max_bytes = cfg.max_file_size_mb.saturating_mul(1024 * 1024);
    if !no_archives && archives::detect_kind(path).is_some() {
        match archives::read_entries(path, max_bytes) {
            Ok(entries) if !entries.is_empty() => {
                let tmpdir = std::env::temp_dir().join(format!(
                    "zeno-arc-{}-{}",
                    std::process::id(),
                    TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
                ));
                if let Err(e) = std::fs::create_dir_all(&tmpdir) {
                    let mut r = scan_one(path, cfg, offline);
                    r.errors.push(format!("archive: temp dir {}: {e:#}", tmpdir.display()));
                    return vec![r];
                }
                let mut out = Vec::with_capacity(entries.len());
                for (i, entry) in entries.into_iter().enumerate() {
                    let name = entry.name.clone();
                    let truncated = entry.truncated;
                    let tmp = tmpdir.join(format!("entry-{i}.bin"));
                    let r = match std::fs::write(&tmp, &entry.data) {
                        Ok(()) => {
                            let mut r = scan_one(&tmp, cfg, offline);
                            r.path = format!("{}!{}", path.display(), name);
                            if truncated {
                                r.errors.push(format!(
                                    "archive entry larger than {} MB, hashes are truncated",
                                    cfg.max_file_size_mb
                                ));
                            }
                            r
                        }
                        Err(e) => FileResult {
                            path: format!("{}!{}", path.display(), name),
                            errors: vec![format!("extract: {e:#}")],
                            ..Default::default()
                        },
                    };
                    std::fs::remove_file(&tmp).ok();
                    out.push(r);
                }
                std::fs::remove_dir_all(&tmpdir).ok();
                return out;
            }
            Ok(_) => {} // архив без файлов — трактуем как непрозрачный файл
            Err(e) => {
                // не парсится как архив — сканируем как непрозрачный файл, с пометкой
                let mut r = scan_one(path, cfg, offline);
                r.errors.push(format!("archive: {e:#}"));
                return vec![r];
            }
        }
    }
    vec![scan_one(path, cfg, offline)]
}

// ---------- команды ----------

fn command_scan(cfg: &Config, path: &Path, json: bool, offline: bool, no_archives: bool) -> ExitCode {
    if !path.exists() {
        eprintln!("[zeno] path not found: {}", path.display());
        return ExitCode::from(2);
    }
    let files = collect_files(path, cfg);
    let mut results = Vec::new();
    let mut malicious = 0usize;
    let mut errored = 0usize;
    let mut scanned = 0usize;

    for f in &files {
        for r in scan_target(f, cfg, offline, no_archives) {
            scanned += 1;
            match r.verdict() {
                "MALICIOUS" => malicious += 1,
                "ERROR" => errored += 1,
                _ => {}
            }
            if json {
                results.push(r);
            } else {
                print_result(&r);
            }
        }
    }

    if json {
        match serde_json::to_string_pretty(&results) {
            Ok(out) => println!("{out}"),
            Err(e) => {
                eprintln!("[zeno] failed to serialize JSON: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        println!(
            "\n[zeno] scanned: {} file(s), malicious: {}, errored: {}{}",
            scanned,
            malicious,
            errored,
            if offline { " (offline mode)" } else { "" }
        );
    }
    // для скриптов: MALICIOUS -> код 1
    if malicious > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn print_result(r: &FileResult) {
    let short = if r.sha256.len() >= 16 { &r.sha256[..16] } else { &r.sha256[..] };
    println!(
        "{short}  {:>12} B  {:<11}  {}",
        r.size,
        r.verdict(),
        r.path
    );
    for d in &r.detections {
        println!("           ! {d}");
    }
    for e in &r.errors {
        println!("           ? {e}");
    }
}

fn command_check(cfg: &Config) -> ExitCode {
    println!("[zeno] engine version: {}", env!("CARGO_PKG_VERSION"));

    println!("[zeno] checking CIRCL hashlookup...");
    match lookups::hashlookup_circl(lookups::TEST_SHA256) {
        Ok(_) => println!("  ok: hashlookup is reachable"),
        Err(e) => println!("  FAIL: {e:#}"),
    }

    match &cfg.clamd_host {
        Some(host) => match clamd::ping(host, cfg.clamd_port) {
            Ok(true) => println!("  ok: clamd {host}:{} responds PONG", cfg.clamd_port),
            _ => println!("  FAIL: clamd {host}:{} is not reachable", cfg.clamd_port),
        },
        None => println!("[zeno] clamd: not configured (clamd_host in zeno.toml)"),
    }

    if cfg.malwarebazaar_auth_key.is_some() {
        println!("[zeno] malwarebazaar auth key: set");
    } else {
        println!("[zeno] malwarebazaar auth key: not set (API requires a free key, see https://bazaar.abuse.ch)");
    }

    ExitCode::SUCCESS
}

fn command_run(cfg: &Config, file: &Path, target: &str, timeout: u64, json: bool, yes: bool) -> ExitCode {
    if !file.exists() {
        eprintln!("[zeno-run] path not found: {}", file.display());
        return ExitCode::from(2);
    }
    if !yes {
        eprintln!("[zeno-run] ВНИМАНИЕ: 'zeno run' РЕАЛЬНО ВЫПОЛНЯЕТ (или отправляет на выполнение) файл.");
        eprintln!("  alpine:  файл запустится в контейнере alpine (--network=none, без capabilities)");
        eprintln!("  windows: файл отправится на анализ в Cuckoo3 (Windows-VM)");
        eprintln!("  macos:   только проверка окружения, файл НЕ запускается");
        eprintln!("  Перезапустите с --yes, если понимаете риск (см. docs/emulation.md).");
        return ExitCode::from(2);
    }
    match run::run(file, target, timeout, cfg) {
        Ok(report) => {
            let code = match (report.executed, report.exit_code) {
                (_, Some(0)) => ExitCode::SUCCESS,
                (true, Some(_)) => ExitCode::from(1),
                _ => ExitCode::SUCCESS,
            };
            if json {
                match serde_json::to_string_pretty(&report) {
                    Ok(out) => println!("{out}"),
                    Err(e) => {
                        eprintln!("[zeno-run] failed to serialize JSON: {e}");
                        return ExitCode::from(2);
                    }
                }
            } else {
                run::print_report(&report);
            }
            code
        }
        Err(e) => {
            eprintln!("[zeno-run] {e:#}");
            ExitCode::from(2)
        }
    }
}

fn command_engines(cfg: &Config) -> ExitCode {
    if cfg.engines.is_empty() {
        println!("[zeno] no external engines configured (see zeno.toml.example)");
    }
    for (name, e) in &cfg.engines {
        println!("{name}: {} {}", e.cmd, e.args.join(" "));
    }
    match &cfg.clamd_host {
        Some(h) => println!("clamd: {h}:{}", cfg.clamd_port),
        None => println!("clamd: not configured"),
    }
    ExitCode::SUCCESS
}
