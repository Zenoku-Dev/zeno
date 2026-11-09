// clamd — сканирование через ClamAV clamd (TCP INSTREAM / PING)

use anyhow::{anyhow, Context, Result};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const SCAN_TIMEOUT: Duration = Duration::from_secs(300);
const CHUNK: usize = 64 * 1024;

fn connect(host: &str, port: u16) -> Result<TcpStream> {
    let addr = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolve clamd {host}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("resolve clamd {host}:{port}: no addresses"))?;
    let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .with_context(|| format!("connect clamd {host}:{port}"))?;
    stream.set_read_timeout(Some(SCAN_TIMEOUT))?;
    stream.set_write_timeout(Some(SCAN_TIMEOUT))?;
    Ok(stream)
}

/// отвечает ли clamd (PING -> PONG)
pub fn ping(host: &str, port: u16) -> Result<bool> {
    let mut stream = connect(host, port)?;
    stream.set_read_timeout(Some(CONNECT_TIMEOUT))?;
    stream.write_all(b"zPING\0")?;
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf[..n]).contains("PONG"))
}

/// INSTREAM: отправляет файл чанками; Ok(Some(hit)) если FOUND, Ok(None) если чисто
pub fn scan(path: &Path, host: &str, port: u16) -> Result<Option<String>> {
    let mut stream = connect(host, port)?;
    stream.write_all(b"zINSTREAM\0")?;

    let mut file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut chunk = vec![0u8; CHUNK];
    loop {
        let n = file.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        stream.write_all(&(n as u32).to_be_bytes())?;
        stream.write_all(&chunk[..n])?;
    }
    stream.write_all(&0u32.to_be_bytes())?;

    let mut resp = String::new();
    stream.read_to_string(&mut resp)?; // clamd сам закрывает соединение после ответа
    let resp = resp.trim_end_matches('\0').trim().to_string();
    if resp.is_empty() {
        return Err(anyhow!("clamd: empty response"));
    }
    if resp.to_uppercase().contains("FOUND") {
        Ok(Some(resp))
    } else {
        Ok(None)
    }
}
