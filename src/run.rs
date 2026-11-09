// run — динамический запуск файла в изолированных средах.
//
// ВАЖНО: это РЕАЛЬНОЕ выполнение кода на вашем компьютере.
// Всегда убедитесь, что понимаете риск, см. docs/emulation.md.
//
// Цели (target):
//   alpine  — Linux ELF в контейнере alpine + docker (--network=none, без capabilities)
//   windows — отправка файла в локальный Cuckoo3 (Windows-гости, KVM), ожидание отчёта
//   macos   — проверка готовности macOS-окружения через OSX-KVM (запуск/мониторинг вручную)

use crate::config::Config;
use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static RUN_TEMP: AtomicUsize = AtomicUsize::new(0);

#[derive(Serialize)]
pub struct CreatedFile {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Serialize)]
pub struct RunReport {
    pub tool: String,
    pub target: String,
    pub file: String,
    pub sha256: String,
    /// выполнялся ли файл (alpine/windows) или только проверка окружения (macos)
    pub executed: bool,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub stdout: String,
    pub stderr: String,
    pub created_files: Vec<CreatedFile>,
    pub strace_tail: Option<String>,
    pub notes: Vec<String>,
}

impl RunReport {
    fn base(tool: &str, target: &str, file: &Path) -> Self {
        RunReport {
            tool: tool.to_string(),
            target: target.to_string(),
            file: file.display().to_string(),
            sha256: String::new(),
            executed: false,
            exit_code: None,
            duration_ms: 0,
            stdout: String::new(),
            stderr: String::new(),
            created_files: Vec::new(),
            strace_tail: None,
            notes: Vec::new(),
        }
    }
}

pub fn run(file: &Path, target: &str, timeout_secs: u64, cfg: &Config) -> Result<RunReport> {
    if !file.is_file() {
        bail!("not a file: {}", file.display());
    }
    let sha256 = crate::hashes::compute(file, u64::MAX)?.sha256;
    match target {
        "alpine" => run_alpine(file, timeout_secs, cfg, sha256),
        "windows" => run_cuckoo(file, timeout_secs, cfg, sha256),
        "macos" => check_macos(file, cfg, sha256),
        other => bail!("unknown target '{other}' (alpine|windows|macos)"),
    }
}

pub fn print_report(r: &RunReport) {
    println!("[zeno-run] target={} tool={} file={}", r.target, r.tool, r.file);
    println!("  sha256:  {}", r.sha256);
    println!("  executed: {}", r.executed);
    if let Some(code) = r.exit_code {
        println!("  exit_code: {code}");
    }
    println!("  duration: {} ms", r.duration_ms);
    let sep = |s: &str| if s.contains('\n') { "\n" } else { " " };
    if !r.stdout.is_empty() {
        println!("  stdout:{}\n{}", sep(&r.stdout), r.stdout);
    }
    if !r.stderr.is_empty() {
        println!("  stderr:{}\n{}", sep(&r.stderr), r.stderr);
    }
    if !r.created_files.is_empty() {
        println!("  created files:");
        for f in &r.created_files {
            println!("    {:>10} B  {}  {}", f.size, &f.sha256[..16], f.name);
        }
    }
    if let Some(s) = &r.strace_tail {
        println!("  strace (tail):\n{s}");
    }
    for n in &r.notes {
        println!("  * {n}");
    }
}

// ---------- alpine (docker) ----------

fn docker_available() -> bool {
    Command::new("docker").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
}

fn run_alpine(file: &Path, timeout_secs: u64, cfg: &Config, sha256: String) -> Result<RunReport> {
    let mut r = RunReport::base("docker/alpine", "alpine", file);
    r.sha256 = sha256;

    if !docker_available() {
        bail!("docker не найден в PATH. Установите Docker (docker.com) и убедитесь, что демон запущен");
    }
    let image = cfg.zeno_alpine_image.clone().unwrap_or_else(|| "alpine:latest".to_string());

    // рабочий каталог: копия сэмпла + место для файлов, которые создаст образец
    let work = std::env::temp_dir().join(format!(
        "zeno-run-{}-{}",
        std::process::id(),
        RUN_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&work).with_context(|| format!("create {}", work.display()))?;
    struct TmpDir(PathBuf);
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = TmpDir(work.clone());

    let sample_copy = work.join("sample");
    std::fs::copy(file, &sample_copy).with_context(|| format!("copy {}", file.display()))?;

    let script = format!(
        "cp /work/sample /tmp/.s && chmod 755 /tmp/.s && cd /work && \\
         if command -v strace >/dev/null 2>&1; then \\
           timeout {timeout_secs} strace -f -o /work/strace.log /tmp/.s >/work/stdout.log 2>/work/stderr.log; \\
         else \\
           timeout {timeout_secs} /tmp/.s >/work/stdout.log 2>/work/stderr.log; \\
         fi; echo $? >/work/exit_code"
    );

    let start = Instant::now();
    let out = Command::new("docker")
        .args([
            "run", "--rm",
            "--network=none",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=64",
            "--memory=256m",
            "-v", &format!("{}:/work", work.display()),
            &image,
            "sh", "-c", &script,
        ])
        .output()
        .context("docker run failed to start")?;
    r.duration_ms = start.elapsed().as_millis() as u64;
    r.executed = true;

    // читаем результаты из workdir
    r.exit_code = std::fs::read_to_string(work.join("exit_code")).ok().and_then(|s| s.trim().parse::<i32>().ok());
    r.stdout = tail_str(&work.join("stdout.log"), 8192);
    r.stderr = tail_str(&work.join("stderr.log"), 8192);
    if work.join("strace.log").exists() {
        r.strace_tail = Some(tail_str(&work.join("strace.log"), 4096));
    } else {
        r.notes.push("strace недоступен в образе (установите zeno-alpine-stace или используйте образ со strace)".into());
    }

    let ignore = ["sample", "stdout.log", "stderr.log", "exit_code", "strace.log"];
    let mut created = walk_created_files(&work);
    created.retain(|f| !ignore.contains(&f.name.as_str()));
    r.created_files = created;

    if !out.status.success() && r.exit_code.is_none() {
        r.notes.push(format!("docker exited with {}: {}", out.status, String::from_utf8_lossy(&out.stderr).trim()));
    }
    r.notes.push("образ alpine запускался с --network=none и без capabilities; это не замена выделенной VM для неизвестных образцов".into());
    r.notes.push("образцы Linux/ELF; PE/исполняемые .exe не запустятся (нужен Windows, см. --target windows)".into());
    Ok(r)
}

fn tail_str(path: &Path, max_bytes: usize) -> String {
    let Ok(bytes) = std::fs::read(path) else { return String::new() };
    let start = bytes.len().saturating_sub(max_bytes);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

fn walk_created_files(root: &Path) -> Vec<CreatedFile> {
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(root).into_iter().filter_entry(|e| e.depth() == 0 || !e.file_name().to_string_lossy().starts_with('.')) {
        let Ok(e) = entry else { continue };
        if !e.file_type().is_file() {
            continue;
        }
        let rel = e.path().strip_prefix(root).unwrap_or(e.path()).display().to_string();
        let size = e.metadata().map(|m| m.len()).unwrap_or(0);
        let sha256 = if size <= 64 * 1024 * 1024 {
            crate::hashes::compute(e.path(), u64::MAX).map(|h| h.sha256).unwrap_or_default()
        } else {
            String::new()
        };
        out.push(CreatedFile { name: rel, size, sha256 });
    }
    out
}

// ---------- windows (Cuckoo3) ----------

const DEFAULT_CUCKOO_URL: &str = "http://127.0.0.1:8090";
const MAX_SUBMIT_BYTES: u64 = 200 * 1024 * 1024;

fn run_cuckoo(file: &Path, timeout_secs: u64, cfg: &Config, sha256: String) -> Result<RunReport> {
    let mut r = RunReport::base("cuckoo3", "windows", file);
    r.sha256 = sha256;

    let url = cfg.cuckoo_url.clone().unwrap_or_else(|| DEFAULT_CUCKOO_URL.to_string());
    let url = url.trim_end_matches('/').to_string();
    let token = cfg
        .cuckoo_token
        .clone()
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| anyhow!("cuckoo_token не задан в конфиге (см. docs/emulation.md; команды: cuckoo api token --list)"))?;

    let size = std::fs::metadata(file)?.len();
    if size > MAX_SUBMIT_BYTES {
        bail!("файл {} MB больше лимита отправки в Cuckoo ({} MB)", size / 1024 / 1024, MAX_SUBMIT_BYTES / 1024 / 1024);
    }
    let bytes = std::fs::read(file).with_context(|| format!("read {}", file.display()))?;
    let file_name = file.file_name().and_then(|n| n.to_str()).unwrap_or("sample").to_string();

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent(concat!("zeno/", env!("CARGO_PKG_VERSION")))
        .build()?;

    let start = Instant::now();

    // 1) отправка
    let part = reqwest::blocking::multipart::Part::bytes(bytes).file_name(file_name);
    let form = reqwest::blocking::multipart::Form::new()
        .part("file", part)
        .text("settings", json!({ "timeout": timeout_secs }).to_string());
    let resp = client
        .post(format!("{url}/submit/file"))
        .header("Authorization", format!("token {token}"))
        .multipart(form)
        .send()
        .with_context(|| format!("не удаётся подключиться к Cuckoo3 по адресу {url}"))?;
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    if !status.is_success() {
        bail!("Cuckoo3 ответил HTTP {status}: {body}");
    }
    let v: serde_json::Value = serde_json::from_str(&body).context("Cuckoo3: невалидный JSON ответа")?;
    let analysis_id = v.get("analysis_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
    if analysis_id.is_empty() {
        bail!("Cuckoo3: в ответе нет analysis_id: {body}");
    }
    r.executed = true;
    r.notes.push(format!("analysis_id: {analysis_id}"));
    r.notes.push(format!("веб-отчёт: {url}/analysis/{analysis_id}"));

    // 2) ожидание (state: finished/reported)
    let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(60) + 600);
    let mut state = String::from("pending");
    let mut score: Option<u64> = None;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_secs(5));
        let resp = match client
            .get(format!("{url}/analysis/{analysis_id}"))
            .header("Authorization", format!("token {token}"))
            .send()
        {
            Ok(r) => r,
            Err(e) => {
                r.notes.push(format!("poll: {e:#}"));
                continue;
            }
        };
        let v: serde_json::Value = match resp.json() {
            Ok(v) => v,
            Err(e) => {
                r.notes.push(format!("poll: invalid JSON: {e}"));
                continue;
            }
        };
        state = v.get("state").and_then(|x| x.as_str()).unwrap_or("unknown").to_string();
        score = v.get("score").and_then(|x| x.as_u64()).or(score);
        if state == "finished" || state == "reported" {
            break;
        }
    }
    r.duration_ms = start.elapsed().as_millis() as u64;
    r.notes.push(format!("final state: {state}{}", score.map(|s| format!(", score: {s}")).unwrap_or_default()));
    if state != "finished" && state != "reported" {
        r.notes.push("таймаут ожидания — анализ ещё выполняется; смотрите веб-отчёт".into());
    }
    Ok(r)
}

// ---------- macos (OSX-KVM) ----------

fn check_macos(file: &Path, cfg: &Config, sha256: String) -> Result<RunReport> {
    let mut r = RunReport::base("osx-kvm", "macos", file);
    r.sha256 = sha256;

    let kvm = Path::new("/dev/kvm").exists();
    let qemu = Command::new("qemu-system-x86_64").arg("--version").output().map(|o| o.status.success()).unwrap_or(false);
    let kvm_dir = cfg.osx_kvm_path.clone().map(PathBuf::from).unwrap_or_else(|| {
        std::env::var("HOME").map(|h| PathBuf::from(h).join("OSX-KVM")).unwrap_or_else(|_| PathBuf::from("OSX-KVM"))
    });
    let img = kvm_dir.join("mac_hdd_ng.img");
    let headless = kvm_dir.join("boot-macOS-headless.sh");

    r.notes.push(format!("KVM (/dev/kvm): {}", if kvm { "ok" } else { "НЕДОСТУПЕН (нужно железо с VT-x/SVM и модуль kvm)" }));
    r.notes.push(format!("qemu-system-x86_64: {}", if qemu { "ok" } else { "НЕ НАЙДЕН (sudo apt-get install qemu-system)" }));
    r.notes.push(format!("OSX-KVM ({}): {}", kvm_dir.display(), if kvm_dir.exists() { "ok" } else { "не найден (git clone https://github.com/kholia/OSX-KVM)" }));
    r.notes.push(format!("диск mac_hdd_ng.img: {}", if img.exists() { format!("ok ({})", img.display()) } else { "не создан (./OpenCore-Boot.sh для установки)".to_string() }));
    r.notes.push(format!("headless-загрузка: {}", if headless.exists() { "boot-macOS-headless.sh готов" } else { "boot-macOS-headless.sh не найден" }));
    r.notes.push("автоматического мониторинга поведения в macOS-госте нет: Cuckoo3 поддерживает только Windows-гостей. Практический сценарий: загрузить VM, зайти по VNC (:5901) и прогнать файл вручную, либо анализировать статически".into());
    r.notes.push("запуск macOS вне железа Apple — на ваш риск (лицензионные ограничения Apple)".into());
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_serializes_to_json() {
        let r = RunReport::base("docker/alpine", "alpine", Path::new("/tmp/x"));
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["target"], "alpine");
        assert_eq!(v["executed"], false);
        assert!(v["created_files"].is_array());
    }

    #[test]
    fn base_defaults_are_empty() {
        let r = RunReport::base("cuckoo3", "windows", Path::new("f.exe"));
        assert!(r.stdout.is_empty() && r.stderr.is_empty() && r.created_files.is_empty());
        assert_eq!(r.exit_code, None);
    }
}
