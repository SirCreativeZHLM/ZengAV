//! Skip files unchanged since the last clean scan. Entries are (path hash, size, mtime) triples,
//! kept sorted in a flat file and binary-searched through a memory map.
use crate::db;
use memmap2::Mmap;
use std::fs::File;
use std::path::Path;
use std::time::UNIX_EPOCH;

const REC: usize = 24;

pub type Entry = (u64, u64, i64);

pub struct Cache {
    map: Option<Mmap>,
}

fn fnv(s: &[u8]) -> u64 {
    s.iter().fold(0xcbf29ce484222325, |h, &b| (h ^ b as u64).wrapping_mul(0x100000001b3))
}

pub fn entry(path: &Path, md: &std::fs::Metadata) -> Option<Entry> {
    let mt = md.modified().ok()?.duration_since(UNIX_EPOCH).ok()?.as_nanos() as i64;
    Some((fnv(path.as_os_str().as_encoded_bytes()), md.len(), mt))
}

fn stamp_len(name: &str) -> (u64, i64) {
    std::fs::metadata(db::data_dir().join(name))
        .ok()
        .and_then(|m| Some((m.len(), m.modified().ok()?.duration_since(UNIX_EPOCH).ok()?.as_nanos() as i64)))
        .unwrap_or((0, 0))
}

/// Changes whenever signatures, rules, the allow-list or heuristics settings change.
fn signature_stamp(heuristics: bool) -> u64 {
    let mut v = Vec::new();
    for n in ["hashes.bin", "hashes.txt", "rules.bin", "allow.txt"] {
        let (l, t) = stamp_len(n);
        v.extend(l.to_le_bytes());
        v.extend(t.to_le_bytes());
    }
    v.push(heuristics as u8);
    fnv(&v)
}

impl Cache {
    pub fn load(heuristics: bool) -> Self {
        let map = File::open(db::data_dir().join("cache.bin"))
            .ok()
            // SAFETY: replaced by atomic rename only.
            .and_then(|f| unsafe { Mmap::map(&f).ok() })
            .filter(|m| m.len() >= 8 && m[..8] == signature_stamp(heuristics).to_le_bytes());
        Cache { map }
    }

    pub fn hit(&self, e: Entry) -> bool {
        let Some(m) = &self.map else { return false };
        let recs = &m[8..];
        let n = recs.len() / REC;
        let key = |i: usize| u64::from_le_bytes(recs[i * REC..i * REC + 8].try_into().unwrap());
        let (mut lo, mut hi) = (0, n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if key(mid) < e.0 { lo = mid + 1 } else { hi = mid }
        }
        while lo < n && key(lo) == e.0 {
            let r = &recs[lo * REC..lo * REC + REC];
            if u64::from_le_bytes(r[8..16].try_into().unwrap()) == e.1
                && i64::from_le_bytes(r[16..24].try_into().unwrap()) == e.2
            {
                return true;
            }
            lo += 1;
        }
        false
    }

    /// Previous entries (valid only when the signature stamp matched), to carry over on save.
    pub fn entries(&self) -> Vec<Entry> {
        let Some(m) = &self.map else { return Vec::new() };
        m[8..]
            .chunks_exact(REC)
            .map(|r| (
                u64::from_le_bytes(r[..8].try_into().unwrap()),
                u64::from_le_bytes(r[8..16].try_into().unwrap()),
                i64::from_le_bytes(r[16..24].try_into().unwrap()),
            ))
            .collect()
    }

    pub fn save(mut entries: Vec<Entry>, heuristics: bool) -> std::io::Result<()> {
        entries.sort_unstable();
        entries.dedup();
        let mut out = Vec::with_capacity(8 + entries.len() * REC);
        out.extend(signature_stamp(heuristics).to_le_bytes());
        for (a, b, c) in entries {
            out.extend(a.to_le_bytes());
            out.extend(b.to_le_bytes());
            out.extend(c.to_le_bytes());
        }
        let dir = db::data_dir();
        std::fs::create_dir_all(&dir)?;
        let tmp = dir.join("cache.bin.tmp");
        std::fs::write(&tmp, out)?;
        std::fs::rename(tmp, dir.join("cache.bin"))
    }
}
