//! Skip files unchanged since the last clean scan. Entries are (path hash, size, mtime) triples,
//! kept sorted in a flat file and binary-searched through a memory map.
use crate::db;
use memmap2::Mmap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

const REC: usize = 16;

/// (path hash, fingerprint of size + modified time)
pub type Entry = (u64, u64);

pub struct Cache {
    map: Option<Mmap>,
}

fn fnv(s: &[u8]) -> u64 {
    s.iter().fold(0xcbf29ce484222325, |h, &b| (h ^ b as u64).wrapping_mul(0x100000001b3))
}

pub fn entry(path: &Path, md: &std::fs::Metadata) -> Option<Entry> {
    let mt = md.modified().ok()?.duration_since(UNIX_EPOCH).ok()?.as_nanos() as u64;
    let mut fp = [0u8; 16];
    fp[..8].copy_from_slice(&md.len().to_le_bytes());
    fp[8..].copy_from_slice(&mt.to_le_bytes());
    Some((fnv(path.as_os_str().as_encoded_bytes()), fnv(&fp)))
}

fn stamp_len(name: &str) -> (u64, i64) {
    std::fs::metadata(db::data_dir().join(name))
        .ok()
        .and_then(|m| Some((m.len(), m.modified().ok()?.duration_since(UNIX_EPOCH).ok()?.as_nanos() as i64)))
        .unwrap_or((0, 0))
}

/// Changes whenever signatures, rules, the allow-list or heuristics settings change.
pub fn signature_stamp(heuristics: bool) -> u64 {
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
            .filter(|m| m.len() >= 16 && m[..8] == signature_stamp(heuristics).to_le_bytes());
        Cache { map }
    }

    fn rec(&self, i: usize) -> Entry {
        let r = &self.map.as_ref().unwrap()[16 + i * REC..16 + (i + 1) * REC];
        (u64::from_le_bytes(r[..8].try_into().unwrap()), u64::from_le_bytes(r[8..].try_into().unwrap()))
    }

    pub fn hit(&self, e: Entry) -> bool {
        let Some(m) = &self.map else { return false };
        let n = (m.len() - 16) / REC;
        let (mut lo, mut hi) = (0, n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.rec(mid) < e { lo = mid + 1 } else { hi = mid }
        }
        lo < n && self.rec(lo) == e
    }

    /// Append the previous entries (valid only if the stamp matched) to the run's spill file.
    pub fn carry_over(&self, out: &mut impl Write) -> std::io::Result<()> {
        if let Some(m) = &self.map {
            out.write_all(&m[16..])?;
        }
        Ok(())
    }
}

/// Clean-file entries are spilled to disk as they are found so memory stays flat on huge disks.
pub struct Spill {
    file: Mutex<BufWriter<File>>,
    path: std::path::PathBuf,
}

pub struct SpillBuf<'a> {
    buf: Vec<u8>,
    spill: &'a Spill,
}

impl Spill {
    pub fn new() -> std::io::Result<Self> {
        let dir = db::data_dir();
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("cache.bin.tmp");
        Ok(Spill { file: Mutex::new(BufWriter::new(std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path)?)), path })
    }

    /// A plain `Write` into the spill file, for bulk copies.
    pub fn writer_raw(&self) -> impl Write + '_ {
        struct W<'a>(&'a Mutex<BufWriter<File>>);
        impl Write for W<'_> {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().write(b)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.0.lock().unwrap().flush()
            }
        }
        W(&self.file)
    }

    pub fn writer(&self) -> SpillBuf<'_> {
        SpillBuf { buf: Vec::with_capacity(64 * 1024), spill: self }
    }

    /// Sort and dedup the spill file in place (file-backed pages, not heap) and install it.
    pub fn finish(self, heuristics: bool) -> std::io::Result<()> {
        use std::io::Seek;
        let mut w = self.file.into_inner().unwrap();
        w.flush()?;
        let mut f = w.into_inner().map_err(|e| e.into_error())?;
        f.seek(std::io::SeekFrom::Start(0))?;
        let len = f.metadata()?.len() as usize / REC;

        {
            // SAFETY: this process is the only user of the temp file.
            let mut mm = unsafe { memmap2::MmapMut::map_mut(&f)? };
            let raw = &mut mm[..len * REC];
            // Records are little-endian on disk; every supported target is little-endian.
            let slice: &mut [Entry] = unsafe { std::slice::from_raw_parts_mut(raw.as_mut_ptr() as *mut Entry, len) };
            slice.sort_unstable();
            // Compact duplicates in place.
            let mut w_i = 0;
            for r in 0..len {
                if w_i == 0 || slice[w_i - 1] != slice[r] {
                    slice[w_i] = slice[r];
                    w_i += 1;
                }
            }
    

            mm.flush()?;
            let body = &mm[..w_i * REC];
            let dir = db::data_dir();
            let final_tmp = dir.join("cache.final.tmp");
            let mut out = BufWriter::new(File::create(&final_tmp)?);
            out.write_all(&signature_stamp(heuristics).to_le_bytes())?;
            out.write_all(&[0u8; 8])?;
            out.write_all(body)?;
            out.flush()?;
            drop(mm);
            std::fs::rename(final_tmp, dir.join("cache.bin"))?;
        }
        let _ = std::fs::remove_file(&self.path);
        Ok(())
    }
}

impl SpillBuf<'_> {
    pub fn push(&mut self, e: Entry) {
        self.buf.extend(e.0.to_le_bytes());
        self.buf.extend(e.1.to_le_bytes());
        if self.buf.len() >= 64 * 1024 {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if let Ok(mut f) = self.spill.file.lock() {
            let _ = f.write_all(&self.buf);
        }
        self.buf.clear();
    }
}

impl Drop for SpillBuf<'_> {
    fn drop(&mut self) {
        self.flush();
    }
}
