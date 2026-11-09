// config — конфигурация (zeno.toml / ~/.zeno/config.toml)

use std::collections::BTreeMap;
use std::path::PathBuf;

pub const DEFAULT_CLAMD_PORT: u16 = 3310;
pub const DEFAULT_MAX_FILE_SIZE_MB: u64 = 200;

#[derive(Debug, Clone)]
pub struct EngineCfg {
    pub cmd: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// clamd_host не задан => clamd не используется
    pub clamd_host: Option<String>,
    pub clamd_port: u16,
    /// бесплатный Auth-Key с bazaar.abuse.ch; без него MalwareBazaar пропускается
    pub malwarebazaar_auth_key: Option<String>,
    /// лимит размера файла для хэширования/отправки, МБ
    pub max_file_size_mb: u64,
    /// имена директорий, которые пропускать при сканировании папки
    pub ignore_dirs: Vec<String>,
    /// внешние движки из таблицы [engine.<name>]
    pub engines: BTreeMap<String, EngineCfg>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            clamd_host: None,
            clamd_port: DEFAULT_CLAMD_PORT,
            malwarebazaar_auth_key: None,
            max_file_size_mb: DEFAULT_MAX_FILE_SIZE_MB,
            ignore_dirs: vec![
                ".git".to_string(),
                ".svn".to_string(),
                ".hg".to_string(),
                "node_modules".to_string(),
                "target".to_string(),
                "__pycache__".to_string(),
            ],
            engines: BTreeMap::new(),
        }
    }
}

impl Config {
    /// ~/.zeno/config.toml, иначе ./zeno.toml; первый читаемый файл выигрывает.
    /// Ошибки чтения/парсинга не фатальны — печатаем предупреждение и берём дефолты.
    pub fn load() -> Self {
        let mut cfg = Config::default();
        for p in config_paths() {
            let Ok(s) = std::fs::read_to_string(&p) else {
                continue;
            };
            match s.parse::<toml::Table>() {
                Ok(v) => cfg.apply(&v),
                Err(e) => eprintln!("[zeno] warning: {}: invalid TOML: {e}", p.display()),
            }
            break;
        }
        cfg
    }

    fn apply(&mut self, v: &toml::Table) {
        if let Some(h) = v.get("clamd_host").and_then(|x| x.as_str()).filter(|s| !s.trim().is_empty()) {
            self.clamd_host = Some(h.to_string());
        }
        if let Some(p) = v.get("clamd_port").and_then(|x| x.as_integer()) {
            if (1..=65535).contains(&p) {
                self.clamd_port = p as u16;
            } else {
                eprintln!("[zeno] warning: clamd_port {p} out of range, using {DEFAULT_CLAMD_PORT}");
            }
        }
        if let Some(k) = v.get("malwarebazaar_auth_key").and_then(|x| x.as_str()).filter(|s| !s.trim().is_empty()) {
            self.malwarebazaar_auth_key = Some(k.to_string());
        }
        if let Some(m) = v.get("max_file_size_mb").and_then(|x| x.as_integer()) {
            if m > 0 {
                self.max_file_size_mb = m as u64;
            }
        }
        if let Some(a) = v.get("ignore_dirs").and_then(|x| x.as_array()) {
            self.ignore_dirs = a.iter().filter_map(|i| i.as_str().map(String::from)).collect();
        }
        if let Some(eng) = v.get("engine").and_then(|x| x.as_table()) {
            for (name, e) in eng {
                let Some(t) = e.as_table() else {
                    eprintln!("[zeno] warning: [engine.{name}] is not a table, skipped");
                    continue;
                };
                let cmd = t.get("cmd").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let args: Vec<String> = t
                    .get("args")
                    .and_then(|x| x.as_array())
                    .map(|a| a.iter().filter_map(|i| i.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                if cmd.trim().is_empty() {
                    eprintln!("[zeno] warning: [engine.{name}] has no cmd, skipped");
                    continue;
                }
                self.engines.insert(name.clone(), EngineCfg { cmd, args });
            }
        }
    }
}

fn config_paths() -> Vec<PathBuf> {
    vec![dirs_config().join("config.toml"), PathBuf::from("zeno.toml")]
}

fn dirs_config() -> PathBuf {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(|h| PathBuf::from(h).join(".zeno"))
        .unwrap_or_else(|_| PathBuf::from("."))
}
