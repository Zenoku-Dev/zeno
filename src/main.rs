// zeno — локальный аналог VirusTotal с открытым кодом.
// Хэши файла + проверка по открытым базам (CIRCL HashLookup, MalwareBazaar)
// + сканирование открытыми движками (ClamAV clamd/clamscan, YARA-X).

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use md5::Md5;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use walkdir::WalkDir;

// ---------- Конфигурация ----------

#[derive(Debug, Clone, Default)]
struct Config {
    clamd_host: Option<String>,
    clamd_port: u16,
    engines: BTreeMap<String, EngineCfg>,
    mb_auth_key: Option<String>,
    te_threshold: u8,
}

const DEFAULT_CLAMD_PORT: u16 = 3310;

impl Config {
    fn load() -> Self {
        let mut cfg = Config { clamd_port: DEFAULT_CLAMD_PORT, te_threshold: 5, ..Default::default() };
        // ~/.zeno/config.toml или ./zeno.toml
        let paths = [
            dirs_config().join("config.toml"),
            PathBuf::from("zeno.toml"),
        ];
        for p in paths.iter() {
            if let Ok(s) = std::fs::read_to_string(p) {
                if let Ok(v) = s.parse::<toml::Table>() {
                    if let Some(h) = v.get("clamd_host").and_then(|x| x.as_str()) {
                        cfg.clamd_host = Some(h.to_string());
                    }
                    if let Some(p) = v.get("clamd_port").and_then(|x| x.as_integer()) {
                        cfg.clamd_port = p as u16;
                    }
                    if let Some(k) = v.get("malwarebazaar_auth_key").and_then(|x| x.as_str()) {
                        cfg.mb_auth_key = Some(k.to_string());
                    }
                    if let Some(t) = v.get("tor_expert_threshold").and_then(|x| x.as_integer()) {
                        cfg.te_threshold = t as u8;
                    }
                    if let Some(eng) = v.get("engine").and_then(|x| x.as_table()) {
                        for (name, e) in eng {
                            let args: Vec<String> = e
                                .get("args")
                                .and_then(|x| x.as_array())
                                .map(|a| a.iter().filter_map(|i| i.as_str().map(String::from)).collect())
                                .unwrap_or_default();
                            cfg.engines.insert(
                                name.clone(),
                                EngineCfg {
                                    cmd: e.get("cmd").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                                    args,
                                },
                            );
                        }
                    }
                }
                break;
            }
        }
        cfg
    }
}

fn dirs_config() -> PathBuf {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(|h| PathBuf::from(h).join(".zeno"))
        .unwrap_or_else(|| PathBuf::from("."))
}

#[derive(Debug, Clone)]
struct EngineCfg {
    cmd: String,
    args: Vec<String>,
}

impl EngineCfg {
    fn run(&self, path: &Path) -> Result<Vec<String>> {
        let args: Vec<String> = self
            .args
            .iter()
            .map(|a| if a == "{path}" { path.display().to_string() } else { a.clone() })
            .collect();
        let out = Command::new(&self.cmd)
            .args(&args)
            .output()
            .with_context(|| format!("работа движка {}", self.cmd))?;
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        let hits: Vec<String> = text
            .lines()
            .filter(|l| l.to_uppercase().contains("FOUND") || l.contains("matches:") || l.to_uppercase().contains("HIT:"))
            .filter(|l| !l.contains("No matches"))
            .map(|l| l.trim().to_string())
            .collect();
        Ok(hits)
    }
}

// ---------- Результаты ----------

#[derive(Debug, Serialize, Default)]
struct ScanResult {
    path: String,
    size: u64,
    md5: String,
    sha1: String,
    sha256: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    malicious_apis: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    engine_hits: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    clamd_hit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl ScanResult {
    fn verdict(&self) -> &'static str {
        let n = self.malicious_apis.len()
            + self.engine_hits.len()
            + if self.clamd_hit.is_some() { 1 } else { 0 };
        if n != 0 {
            "MALICIOUS"
        } else {
            "CLEAN"
        }
    }
}

// ---------- Хэши ----------

fn hash_file(path: &Path, limit: u64) -> Result<(u64, String, String, String)> {
    let f = std::fs::File::open(path).with_context(|| format!("открытие {}", path.display()))?;
    let mut f = f.take(limit);
    let mut buf = Vec::with_capacity(64 * 1024);
    f.read_to_end(&mut buf)?;
    let md5 = hex::encode(Md5::digest(&buf));
    let sha1 = hex::encode(Sha1::digest(&buf));
    let sha256 = hex::encode(Sha256::digest(&buf));
    let sz = buf.len() as u64;
    Ok((sz, md5, sha1, sha256))
}

// ---------- Открытые базы ----------

fn circl_lookup(sha256: &str) -> Result<Option<Vec<String>>> {
    let url = format!("https://api.hashlookup.ch/lookup/sha256/{sha256}");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("zeno/0.2")
        .build()?;
    let resp = client.get(&url).send()?;
    match resp.status().as_u16() {
        200 => {
            let v: serde_json::Value = resp.json()?;
            let fam = v
                .get("KnownMalicious")
                .and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|i| i.as_str().map(String::from)).collect::<Vec<_>>())
                .unwrap_or_default();
            if fam.is_empty() && v.get("hashlookup:parent").is_some() {
                Ok(Some(vec!["known-file (hashlookup parent)".into()]))
            } else if fam.is_empty() {
                Ok(Some(vec![]))
            } else {
                Ok(Some(format!("hashlookup: {fam:?}").lines().map(String::from).collect()))
            }
        }
        404 => Ok(Some(vec![])),
        _ => Err(anyhow!("hashlookup: HTTP {}", resp.status())),
    }
}

fn malwarebazaar(sha256: &str, auth: Option<&String>) -> Result<bool> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("zeno/0.2")
        .build()?;
    let mut req = client
        .post("https://mb-api.abuse.ch/api/v1/")
        .form(&[("query", "get_info"), ("hash", sha256)]);
    if let Some(k) = auth {
        req = req.header("Auth-Key", k);
    }
    let resp = req.send()?.json::<serde_json::Value>()?;
    Ok(resp.get("query_status").and_then(|x| x.as_str()) == Some("ok"))
}

// ---------- ClamAV clamd (INSTREAM) ----------

fn clamd_scan(path: &Path, host: &str, port: u16) -> Result<Option<String>> {
    let path_str = path.as_os_str().to_string_lossy().to_string();
    if path_str.contains('\u{0}') {
        return Err(anyhow!("путь содержит NUL"));
    }
    let mut stream = TcpStream::connect((host, port)).with_context(|| format!("подключение к clamd {host}:{port}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(300)))?;
    stream.write_all(b"zINSTREAM\0")?;
    let data = std::fs::read(path)?;
    for chunk in data.chunks(64 * 1024) {
        let len = (chunk.len() as u32).to_be_bytes();
        stream.write_all(&len)?;
        stream.write_all(chunk)?;
    }
    stream.write_all(&0u32.to_be_bytes())?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp)?;
    let resp = resp.trim_end_matches('\0');
    if resp.is_empty() {
        return Err(anyhow!("пустой ответ clamd"));
    }
    if resp.to_uppercase().contains("FOUND") {
        Ok(Some(resp.to_string()))
    } else {
        Ok(None)
    }
}

// ---------- Скан одного файла ----------

fn scan_file(path: &Path, cfg: &Config) -> ScanResult {
    let mut r = ScanResult { path: path.display().to_string(), ..Default::default() };
    match hash_file(path, 200 * 1024 * 1024) {
        Ok((sz, md5, sha1, sha256)) => {
            r.size = sz;
            r.sha256 = sha256.clone();
            r.sha1 = sha1;
            r.md5 = md5;
            if let Ok(Some(fam)) = circl_lookup(&sha256) {
                r.malicious_apis.extend(fam);
            }
            if malwarebazaar(&sha256, cfg.mb_auth_key.as_ref()).unwrap_or(false) {
                r.malicious_apis.push("malwarebazaar: sample known".into());
            }
        }
        Err(e) => r.error = Some(format!("{e:#}")),
    }
    for (name, eng) in &cfg.engines {
        match eng.run(path) {
            Ok(hits) if !hits.is_empty() => {
                r.engine_hits.push(format!("{name}: {}", hits.join(" | ")));
            }
            Ok(_) => {}
            Err(e) => r.error = Some(format!("{e:#}")),
        }
    }
    if let Some(host) = cfg.clamd_host.clone() {
        match clamd_scan(path, &host, cfg.clamd_port) {
            Ok(Some(hit)) => r.clamd_hit = Some(hit),
            Ok(None) => {}
            Err(e) => r.error = Some(format!("{e:#}")),
        }
    }
    r
}

fn collect_files(p: &Path) -> Vec<PathBuf> {
    if p.is_file() {
        return vec![p.to_path_buf()];
    }
    WalkDir::new(p)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect()
}

// ---------- CLI ----------

#[derive(Parser)]
#[command(
    name = "zeno",
    version,
    about = "Локальный аналог VirusTotal: открытые базы + открытые движки (ClamAV, YARA-X)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Просканировать файл/папку
    Scan {
        path: PathBuf,
        /// Вывести результат в JSON
        #[arg(long)]
        json: bool,
    },
    /// Настроить список внешних AV/YARA движков в zeno.toml
    Engines,
    /// Проверить доступность открытых баз
    Check,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = Config::load();
    match cli.cmd {
        Cmd::Scan { path, json } => {
            let files = collect_files(&path);
            let mut results = Vec::new();
            for f in files {
                let r = scan_file(&f, &cfg);
                if !json {
                    println!(
                        "{} {} {}",
                        hex::encode(&r.sha256[..8.min(r.sha256.len())]),
                        r.verdict(),
                        r.path
                    );
                }
                results.push(r);
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&results)?);
            } else {
                let bad = results.iter().filter(|r| r.verdict() != "CLEAN").count();
                println!("\nИтого: {} файлов, malicious: {}", results.len(), bad);
            }
        }
        Cmd::Engines => {
            for (n, e) in &cfg.engines {
                println!("{n}: {} {}", e.cmd, e.args.join(" "));
            }
            match cfg.clamd_host {
                Some(h) => println!("clamd: {h}:{}", cfg.clamd_port),
                None => println!("clamd: не настроен (clamd_host в zeno.toml)"),
            }
            println!("hashlookup: включён всегда (CIRCL, без ключа)");
        }
        Cmd::Check => {
            let test = [0u8; 8];
            let h = hex::encode(Sha256::digest(test));
            match circl_lookup(&h) {
                Ok(_) => println!("CIRCL hashlookup: доступен"),
                Err(e) => println!("CIRCL hashlookup: недоступен ({e:#})"),
            }
            if let Some(host) = cfg.clamd_host {
                match clamd_scan(Path::new(".zzz-nonexistent"), &host, cfg.clamd_port) {
                    Ok(_) => println!("clamd {host}: доступен"),
                    Err(_) => println!("clamd {host}: недоступен/не рассылает ответ на такой файл"),
                }
            } else {
                println!("clamd: не настроен");
            }
        }
    }
    Ok(())
}
