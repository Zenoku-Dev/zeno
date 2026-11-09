// hashes — потоковые MD5/SHA-1/SHA-256 (файл не грузится в память целиком)

use anyhow::{Context, Result};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

const BUF: usize = 64 * 1024;

#[derive(Debug)]
pub struct Hashes {
    /// реальный размер файла в байтах
    pub size: u64,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    /// файл больше max_bytes: хэши посчитаны по первым max_bytes байтам
    pub truncated: bool,
}

pub fn compute(path: &Path, max_bytes: u64) -> Result<Hashes> {
    let size = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .len();
    let truncated = size > max_bytes;

    let f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = f.take(max_bytes);

    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();

    let mut buf = vec![0u8; BUF];
    loop {
        let n = reader.read(&mut buf).with_context(|| format!("read {}", path.display()))?;
        if n == 0 {
            break;
        }
        md5.update(&buf[..n]);
        sha1.update(&buf[..n]);
        sha256.update(&buf[..n]);
    }

    Ok(Hashes {
        size,
        md5: hex::encode(md5.finalize()),
        sha1: hex::encode(sha1.finalize()),
        sha256: hex::encode(sha256.finalize()),
        truncated,
    })
}
