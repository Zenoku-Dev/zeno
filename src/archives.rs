// archives — чтение архивов (zip, tar, tar.gz) и сканирование содержимого.
// Внутри архивов — те же хэши/базы/движки; сами архивные файлы остаются на диске неизменными.

use anyhow::{anyhow, Context, Result};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Тип архива
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Zip,
    Tar,
    TarGz,
}

/// Один файл внутри архива (содержимое в памяти, для сканирования)
#[derive(Debug)]
pub struct Entry {
    /// путь внутри архива (санитизирован, без .. и абсолютных путей)
    pub name: String,
    pub data: Vec<u8>,
    /// размер во вложении больше лимита — хэши/детекты посчитаны по префиксу
    pub truncated: bool,
}

/// Максимум файлов в архиве, которые сканируются
pub const MAX_ENTRIES: usize = 1000;

/// Определяет тип архива по расширению либо по магии (включая ustar по смещению 257)
pub fn detect_kind(path: &Path) -> Option<Kind> {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let n = name.to_lowercase();
        if n.ends_with(".zip") {
            return Some(Kind::Zip);
        }
        if n.ends_with(".tar") {
            return Some(Kind::Tar);
        }
        if n.ends_with(".tar.gz") || n.ends_with(".tgz") {
            return Some(Kind::TarGz);
        }
    }
    // магия
    let mut f = std::fs::File::open(path).ok()?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).ok()?;
    if &magic[..2] == b"PK" {
        return Some(Kind::Zip);
    }
    if magic[0] == 0x1f && magic[1] == 0x8b {
        return Some(Kind::TarGz); // gzip как не-tar обработается при парсинге (Err -> opaque fallback)
    }
    // ustar по смещению 257
    f.seek(SeekFrom::Start(257)).ok()?;
    let mut ustar = [0u8; 5];
    f.read_exact(&mut ustar).ok()?;
    if &ustar == b"ustar" {
        return Some(Kind::Tar);
    }
    None
}

/// Читает все файлы архива в память (по одному за раз, с лимитом max_bytes на файл)
pub fn read_entries(path: &Path, max_bytes: u64) -> Result<Vec<Entry>> {
    match detect_kind(path).ok_or_else(|| anyhow!("not an archive: {}", path.display()))? {
        Kind::Zip => read_zip(path, max_bytes),
        Kind::Tar => {
            let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
            tar_entries(file, max_bytes)
        }
        Kind::TarGz => read_tar_gz(path, max_bytes),
    }
}

fn read_zip(path: &Path, max_bytes: u64) -> Result<Vec<Entry>> {
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut zip = zip::ZipArchive::new(file).with_context(|| format!("read zip {}", path.display()))?;
    let mut out = Vec::new();
    for i in 0..zip.len().min(MAX_ENTRIES) {
        let entry = zip.by_index(i).with_context(|| format!("zip entry #{i}"))?;
        if !entry.is_file() {
            continue;
        }
        let name = sanitize_name(&entry.name()?);
        let truncated = entry.size() > max_bytes;
        let mut limited = entry.take(max_bytes);
        let mut data = Vec::with_capacity(max_bytes.min(64 * 1024 * 1024) as usize);
        limited.read_to_end(&mut data)?;
        out.push(Entry { name, data, truncated });
    }
    if zip.len() > MAX_ENTRIES {
        eprintln!("[zeno] note: archive has {} entries, only first {MAX_ENTRIES} are scanned", zip.len());
    }
    Ok(out)
}

fn tar_entries<R: Read>(reader: R, max_bytes: u64) -> Result<Vec<Entry>> {
    let mut archive = tar::Archive::new(reader);
    let mut out = Vec::new();
    for e in archive.entries()? {
        if out.len() >= MAX_ENTRIES {
            eprintln!("[zeno] note: archive has more than {MAX_ENTRIES} files, extra entries are skipped");
            break;
        }
        let mut e = e?;
        if !e.header().entry_type().is_file() {
            continue;
        }
        let name = sanitize_name(&e.path()?.display().to_string());
        let truncated = e.size() > max_bytes;
        let mut limited = Read::by_ref(&mut e).take(max_bytes);
        let mut data = Vec::with_capacity(max_bytes.min(64 * 1024 * 1024) as usize);
        limited.read_to_end(&mut data)?;
        out.push(Entry { name, data, truncated });
    }
    Ok(out)
}

fn read_tar_gz(path: &Path, max_bytes: u64) -> Result<Vec<Entry>> {
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let decoder = flate2::read::GzDecoder::new(file);
    tar_entries(decoder, max_bytes).with_context(|| format!("read tar.gz {}", path.display()))
}

/// Приводит путь из архива к безопасному виду для записи во временный файл
/// и к читабельной метке в выводе: убирает "..", ведущие слэши и диски
fn sanitize_name(name: &str) -> String {
    let normalized = name.replace('\\', "/");
    let parts: Vec<&str> = normalized
        .split('/')
        .map(str::trim)
        .filter(|p| !p.is_empty() && *p != "." && *p != ".." && !p.contains(':'))
        .collect();
    if parts.is_empty() {
        "unnamed".to_string()
    } else {
        parts.join("/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_zip(path: &Path, files: &[(&str, &[u8])]) {
        let f = std::fs::File::create(path).unwrap();
        let mut zw = zip::ZipWriter::new(f);
        for (name, data) in files {
            zw.start_file(*name, zip::write::FileOptions::<()>::default()).unwrap();
            zw.write_all(data).unwrap();
        }
        zw.finish().unwrap();
    }

    #[test]
    fn detects_zip_by_ext_and_magic() {
        let tmp = std::env::temp_dir().join(format!("zeno-arc-detect-{}.zip", std::process::id()));
        write_zip(&tmp, &[("hello.txt", b"hello")]);
        assert_eq!(detect_kind(&tmp), Some(Kind::Zip));
        // переименуем в расширение, которое ничего не говорит — магия должна сработать
        let tmp2 = tmp.with_extension("bin");
        std::fs::rename(&tmp, &tmp2).unwrap();
        assert_eq!(detect_kind(&tmp2), Some(Kind::Zip));
        let entries = read_entries(&tmp2, 1024).unwrap();
        std::fs::remove_file(&tmp2).ok();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hello.txt");
        assert_eq!(entries[0].data, b"hello");
        assert!(!entries[0].truncated);
    }

    #[test]
    fn reads_tar_and_truncates() {
        let tmp = std::env::temp_dir().join(format!("zeno-arc-{}.tar", std::process::id()));
        {
            let f = std::fs::File::create(&tmp).unwrap();
            let mut tb = tar::Builder::new(f);
            let data = vec![0x41u8; 10_000];
            let mut header = tar::Header::new_gnu();
            header.set_size(10_000);
            header.set_mode(0o644);
            header.set_cksum();
            tb.append_data(&mut header, "big.bin", &data[..]).unwrap();
            tb.finish().unwrap();
        }
        let entries = read_entries(&tmp, 100).unwrap();
        std::fs::remove_file(&tmp).ok();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data.len(), 100);
        assert!(entries[0].truncated);
    }

    #[test]
    fn sanitizes_traversal_names() {
        assert_eq!(sanitize_name("../../etc/passwd"), "etc/passwd");
        assert_eq!(sanitize_name("C:\\Windows\\system32\\x.dll"), "Windows/system32/x.dll");
        assert_eq!(sanitize_name("a/./b//c.txt"), "a/b/c.txt");
    }
}
