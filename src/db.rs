use memmap2::Mmap;
use std::collections::HashSet;
use std::fs::{self, File};
use std::path::PathBuf;

pub type Hash = [u8; 32];

/// SHA-256 of the standard EICAR antivirus test file, always known.
const EICAR: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

pub fn data_dir() -> PathBuf {
    if let Ok(p) = std::env::var("ZENGAV_HOME") {
        return PathBuf::from(p);
    }
    dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("zengav")
}

pub fn to_hex(h: &Hash) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn from_hex(s: &str) -> Option<Hash> {
    let s = s.trim();
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// One hex SHA-256 per line; `#` starts a comment.
fn load_set(name: &str) -> HashSet<Hash> {
    let text = fs::read_to_string(data_dir().join(name)).unwrap_or_default();
    text.lines().filter_map(|l| from_hex(l.split('#').next().unwrap_or(""))).collect()
}

pub struct Db {
    /// Sorted, packed 32-byte hashes produced by `--update`; memory-mapped so RAM stays flat.
    big: Option<Mmap>,
    small: HashSet<Hash>,
    allow: HashSet<Hash>,
}

impl Db {
    pub fn load() -> Self {
        let big = File::open(data_dir().join("hashes.bin")).ok().and_then(|f| {
            // SAFETY: file is replaced by atomic rename, never modified in place.
            unsafe { Mmap::map(&f).ok() }
        });
        let mut small = load_set("hashes.txt");
        small.insert(from_hex(EICAR).unwrap());
        Db { big, small, allow: load_set("allow.txt") }
    }

    pub fn is_malicious(&self, h: &Hash) -> bool {
        if self.allow.contains(h) {
            return false;
        }
        if self.small.contains(h) {
            return true;
        }
        let Some(m) = &self.big else { return false };
        let n = m.len() / 32;
        let (mut lo, mut hi) = (0, n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            match m[mid * 32..mid * 32 + 32].cmp(&h[..]) {
                std::cmp::Ordering::Equal => return true,
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        false
    }

    pub fn is_allowed(&self, h: &Hash) -> bool {
        self.allow.contains(h)
    }
}

/// Remember a hash as accepted so it is not flagged again.
pub fn accept(hash: &str, path: &str) -> std::io::Result<()> {
    use std::io::Write;
    fs::create_dir_all(data_dir())?;
    let mut f = fs::OpenOptions::new().create(true).append(true).open(data_dir().join("allow.txt"))?;
    writeln!(f, "{hash} # {path}")
}

/// Merge `new` into hashes.bin (sorted, deduplicated) via atomic rename. Returns the new total.
pub fn merge_hashes(new: Vec<Hash>) -> std::io::Result<usize> {
    let dir = data_dir();
    fs::create_dir_all(&dir)?;
    let path = dir.join("hashes.bin");
    let mut all = new;
    if let Ok(old) = fs::read(&path) {
        all.extend(old.chunks_exact(32).map(|c| <Hash>::try_from(c).unwrap()));
    }
    all.sort_unstable();
    all.dedup();
    let tmp = dir.join("hashes.bin.tmp");
    fs::write(&tmp, all.concat())?;
    fs::rename(&tmp, &path)?;
    Ok(all.len())
}
