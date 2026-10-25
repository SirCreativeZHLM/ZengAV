use std::io::Read;
use std::path::Path;

fn entropy(data: &[u8]) -> f64 {
    let mut c = [0u64; 256];
    data.iter().for_each(|&b| c[b as usize] += 1);
    let n = data.len() as f64;
    c.iter().filter(|&&x| x > 0).map(|&x| { let p = x as f64 / n; -p * p.log2() }).sum()
}

pub fn is_executable(head: &[u8]) -> bool {
    head.starts_with(b"MZ")
        || head.starts_with(b"\x7fELF")
        || head.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || head.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || head.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
}

/// Opt-in, weak signal: an executable that is almost entirely high-entropy (packed/encrypted)
/// and sits in a temp or downloads-style location.
pub fn suspicious(path: &Path, head: &[u8]) -> Option<&'static str> {
    if !is_executable(head) || head.len() < 64 * 1024 {
        return None;
    }
    let p = path.to_string_lossy().to_ascii_lowercase();
    let odd_place = ["/tmp/", "\\temp\\", "/var/tmp/", "/dev/shm/", "\\appdata\\local\\temp"].iter().any(|s| p.contains(s));
    (odd_place && entropy(head) > 7.5).then_some("packed executable in temp location")
}

pub fn read_head(path: &Path) -> Vec<u8> {
    let mut buf = vec![0u8; 256 * 1024];
    let n = std::fs::File::open(path).and_then(|mut f| f.read(&mut buf)).unwrap_or(0);
    buf.truncate(n);
    buf
}

/// Cheap filter so YARA only runs on executables, scripts and document-like files.
pub fn worth_rules(path: &Path, head: &[u8]) -> bool {
    if is_executable(head) || head.starts_with(b"#!") || head.starts_with(b"PK") || head.starts_with(b"%PDF") || head.starts_with(&[0xd0, 0xcf, 0x11, 0xe0]) {
        return true;
    }
    const EXT: &[&str] = &["ps1", "vbs", "js", "jse", "bat", "cmd", "sh", "py", "php", "jar", "hta", "lnk", "scr", "dll", "exe", "doc", "docm", "xls", "xlsm", "rtf", "pl", "rb"];
    path.extension().and_then(|e| e.to_str()).is_some_and(|e| EXT.contains(&e.to_ascii_lowercase().as_str()))
}
