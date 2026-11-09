// engines — внешние движки (clamscan, YARA-X и любые другие CLI)

use crate::config::EngineCfg;
use anyhow::{anyhow, Context, Result};
use std::path::Path;
use std::process::Command;

/// Запускает движок на файле; возвращает строки, похожие на вердикты (FOUND / matches: / HIT:).
pub fn run(engine: &EngineCfg, path: &Path) -> Result<Vec<String>> {
    if engine.cmd.trim().is_empty() {
        return Err(anyhow!("engine without cmd"));
    }
    let args: Vec<String> = engine
        .args
        .iter()
        .map(|a| if a == "{path}" { path.display().to_string() } else { a.clone() })
        .collect();

    let out = Command::new(&engine.cmd)
        .args(&args)
        .output()
        .with_context(|| format!("engine '{}' failed to start (not installed?)", engine.cmd))?;

    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    Ok(hit_lines(&text))
}

fn hit_lines(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| {
            let u = l.to_uppercase();
            (u.contains("FOUND") || l.contains("matches:") || u.contains("HIT:")) && !l.contains("No matches")
        })
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_hit_lines() {
        let out = "/tmp/a.exe: Win.Test.EICAR_HDB-1 FOUND\nnothing here\n/tmp/b: OK\nNo matches found";
        let hits = hit_lines(out);
        assert_eq!(hits, vec!["/tmp/a.exe: Win.Test.EICAR_HDB-1 FOUND"]);
    }

    #[test]
    fn picks_matches_and_hit_colon() {
        let out = "some rule matches: https://example.com\nHIT: sig-123\nNo matches at all";
        let hits = hit_lines(out);
        assert_eq!(hits, vec!["some rule matches: https://example.com", "HIT: sig-123"]);
    }
}
