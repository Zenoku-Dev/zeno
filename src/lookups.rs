// lookups — открытые базы по SHA-256 (наружу уходит только хэш, не файл)

use anyhow::{anyhow, Context, Result};
use std::time::Duration;

/// SHA-256 строки "hello": заведомо присутствует в CIRCL HashLookup
/// (listing от malshare), используется в `zeno check` как пробник.
pub const TEST_SHA256: &str =
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

const HASHLOOKUP_URL: &str = "https://hashlookup.circl.lu/lookup/sha256";
const MALWAREBAZAAR_URL: &str = "https://mb-api.abuse.ch/api/v1/";
const TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
pub enum LookupHit {
    /// известен как вредоносный; метки — кто так считает (например "malshare.com")
    Malicious(Vec<String>),
    /// известен базам (NSRL и т.п.), но не помечен вредоносным
    KnownClean,
    /// в базах не найден
    Unknown,
}

fn client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(TIMEOUT)
        .user_agent(concat!("zeno/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

/// CIRCL HashLookup (hashlookup.circl.lu), ключ не нужен.
pub fn hashlookup_circl(sha256: &str) -> Result<LookupHit> {
    let url = format!("{HASHLOOKUP_URL}/{sha256}");
    let resp = client()?
        .get(&url)
        .send()
        .context("hashlookup: network error")?;
    let status = resp.status();
    if status.as_u16() == 404 {
        return Ok(LookupHit::Unknown);
    }
    if !status.is_success() {
        return Err(anyhow!("hashlookup: HTTP {status}"));
    }
    let v: serde_json::Value = resp.json().context("hashlookup: invalid JSON")?;

    // KnownMalicious: строка ("malshare.com") либо массив строк
    let labels: Vec<String> = match v.get("KnownMalicious") {
        Some(serde_json::Value::String(s)) if !s.trim().is_empty() => vec![s.trim().to_string()],
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .filter_map(|i| i.as_str().map(str::trim).map(String::from))
            .filter(|s| !s.is_empty())
            .collect(),
        _ => Vec::new(),
    };

    if labels.is_empty() {
        Ok(LookupHit::KnownClean)
    } else {
        Ok(LookupHit::Malicious(
            labels.into_iter().map(|l| format!("hashlookup: {l}")).collect(),
        ))
    }
}

/// MalwareBazaar (abuse.ch). С 2024 года API требует бесплатный Auth-Key
/// (выдаётся на bazaar.abuse.ch). Без ключа запрос молча пропускается.
pub fn malwarebazaar_known(sha256: &str, auth_key: Option<&str>) -> Result<bool> {
    let Some(key) = auth_key.filter(|k| !k.trim().is_empty()) else {
        return Ok(false);
    };
    let resp = client()?
        .post(MALWAREBAZAAR_URL)
        .header("Auth-Key", key)
        .form(&[("query", "get_info"), ("hash", sha256)])
        .send()
        .context("malwarebazaar: network error")?;
    let status = resp.status();
    if !status.is_success() {
        // 401/403 — неверный или отсутствующий ключ
        return Err(anyhow!("malwarebazaar: HTTP {status} (check Auth-Key)"));
    }
    let v: serde_json::Value = resp.json().context("malwarebazaar: invalid JSON")?;
    match v.get("query_status").and_then(|x| x.as_str()) {
        Some("ok") => Ok(true),
        Some("hash_not_found") => Ok(false),
        Some(other) => Err(anyhow!("malwarebazaar: {other}")),
        None => Err(anyhow!("malwarebazaar: unexpected response shape")),
    }
}
