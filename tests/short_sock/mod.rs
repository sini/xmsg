//! Test socket paths that stay short whatever the id they serve.
//!
//! Portability: macOS caps a unix socket path at 104 bytes (`SUN_LEN`) and its `$TMPDIR` is long,
//! so a test socket's file name never embeds a session/instance id or node name.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// `dir/<prefix>-<n>.sock`, with `n` unique within the test binary.
pub fn sock_path(dir: &Path, prefix: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    dir.join(format!(
        "{prefix}-{}.sock",
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

pub fn strip_ansi(input: &str) -> String {
    let mut clean = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            while let Some(&nc) = chars.peek() {
                chars.next();
                if nc.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            clean.push(c);
        }
    }
    clean
}

pub fn parse_logged_listen_addr(line: &str, marker: &str) -> Option<SocketAddr> {
    let clean = strip_ansi(line);
    if !clean.contains(marker) {
        return None;
    }
    let idx = clean.find("listen=")?;
    let rest = &clean[idx + "listen=".len()..];
    let tok = rest.split_whitespace().next()?;
    tok.parse().ok()
}

#[derive(Clone)]
pub struct StdoutCapture {
    buf: Arc<Mutex<String>>,
}

impl StdoutCapture {
    pub fn from_tokio(out: tokio::process::ChildStdout) -> Self {
        let std_out = out
            .into_owned_fd()
            .expect("convert tokio ChildStdout into OwnedFd");
        Self::from_file(std::fs::File::from(std_out))
    }

    pub fn from_std(out: std::process::ChildStdout) -> Self {
        use std::os::unix::io::OwnedFd;
        let fd: OwnedFd = out.into();
        Self::from_file(std::fs::File::from(fd))
    }

    fn from_file(mut file: std::fs::File) -> Self {
        let buf = Arc::new(Mutex::new(String::new()));
        let buf_clone = buf.clone();
        std::thread::spawn(move || {
            use std::io::Read;
            let mut chunk = [0u8; 1024];
            while let Ok(n) = file.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                buf_clone
                    .lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&chunk[..n]));
            }
        });
        Self { buf }
    }

    pub fn try_wait_for_addr(&self, marker: &str, timeout: Duration) -> Option<SocketAddr> {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let out = self.buf.lock().unwrap();
                for line in out.lines() {
                    if let Some(addr) = parse_logged_listen_addr(line, marker) {
                        return Some(addr);
                    }
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn wait_for_addr(&self, marker: &str, timeout: Duration) -> SocketAddr {
        self.try_wait_for_addr(marker, timeout).unwrap_or_else(|| {
            let out = self.snapshot();
            panic!("timed out waiting for '{marker}' listen= address in child stdout within {timeout:?}; stdout:\n{out}")
        })
    }

    pub fn wait_for_port(&self, marker: &str, timeout: Duration) -> u16 {
        self.wait_for_addr(marker, timeout).port()
    }

    pub fn try_wait_for_port(&self, marker: &str, timeout: Duration) -> Option<u16> {
        self.try_wait_for_addr(marker, timeout).map(|a| a.port())
    }

    pub fn line_count_containing(&self, needle: &str) -> usize {
        let out = self.buf.lock().unwrap();
        out.lines()
            .filter(|line| strip_ansi(line).contains(needle))
            .count()
    }

    pub fn wait_for_line_count(&self, needle: &str, min_count: usize, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.line_count_containing(needle) >= min_count {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn snapshot(&self) -> String {
        self.buf.lock().unwrap().clone()
    }
}
