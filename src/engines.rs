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
