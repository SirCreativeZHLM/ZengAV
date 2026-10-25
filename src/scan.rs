use crate::cache::{self, Cache};
use crate::db::{self, Db, Hash};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use walkdir::WalkDir;

pub struct Detection {
    pub path: PathBuf,
    pub hash: String,
    pub reason: String,
}

#[derive(Default)]
pub struct Report {
    pub scanned: u64,
    pub skipped_unchanged: u64,
    pub errors: u64,
    pub detections: Vec<Detection>,
}

pub struct Options {
    pub verbose: bool,
    pub heuristics: bool,
    pub full: bool,
}

/// Pseudo or volatile filesystems that hold no files worth scanning.
fn skipped(p: &Path) -> bool {
    const SKIP: &[&str] = &["/proc", "/sys", "/dev", "/run", "/private/var/vm", "/System/Volumes/VM", "/System/Volumes/Preboot"];
    SKIP.iter().any(|s| p == Path::new(s))
}

pub fn sha256(path: &Path) -> std::io::Result<Hash> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

pub fn roots_for_full_scan() -> Vec<PathBuf> {
    if cfg!(windows) {
        ('A'..='Z').map(|c| PathBuf::from(format!("{c}:\\"))).filter(|p| p.exists()).collect()
    } else {
        vec![PathBuf::from("/")]
    }
}

/// Run at the lowest CPU priority so the machine stays responsive.
pub fn lower_priority() {
    #[cfg(unix)]
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 19);
    }
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Threading::*;
        SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS);
    }
}

const YARA_MAX_SIZE: u64 = 64 << 20;

enum Outcome {
    Clean(Option<cache::Entry>),
    Unchanged,
    Hit(Detection),
    Err,
}

pub fn run(roots: &[PathBuf], db: &Db, opts: &Options) -> Report {
    lower_priority();
    let threads = (std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2) / 2).max(1);
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().expect("thread pool");
    let rules = crate::yara::load();
    let cache = Cache::load(opts.heuristics);
    let seen = AtomicU64::new(0);

    let outcomes: Vec<Outcome> = pool.install(|| {
        let files = roots.iter().flat_map(|r| {
            WalkDir::new(r)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| !skipped(e.path()))
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
        });
        files
            .par_bridge()
            .map_init(
                || rules.as_ref().map(crate::yara::scanner),
                |yscan, e| {
                    let path = e.path();
                    let md = e.metadata().ok();
                    let ce = md.as_ref().and_then(|m| cache::entry(path, m));
                    if !opts.full && ce.is_some_and(|c| cache.hit(c)) {
                        return Outcome::Unchanged;
                    }
                    if opts.verbose {
                        eprintln!("scanning {}", path.display());
                    }
                    seen.fetch_add(1, Relaxed);
                    let hash = match sha256(path) {
                        Ok(h) => h,
                        Err(_) => return Outcome::Err,
                    };
                    let hex = db::to_hex(&hash);
                    let hit = |reason: String| Outcome::Hit(Detection { path: path.to_path_buf(), hash: hex.clone(), reason });
                    if db.is_malicious(&hash) {
                        return hit("known malware hash".into());
                    }
                    if db.is_allowed(&hash) {
                        return Outcome::Clean(ce);
                    }
                    let size = md.as_ref().map_or(0, |m| m.len());
                    if size > 0 && (yscan.is_some() || opts.heuristics) {
                        let head = crate::heur::read_head(path);
                        if let Some(s) = yscan.as_mut().filter(|_| size <= YARA_MAX_SIZE && crate::heur::worth_rules(path, &head)) {
                            let m = crate::yara::matches(s, path);
                            if !m.is_empty() {
                                return hit(format!("YARA rule: {}", m.join(", ")));
                            }
                        }
                        if opts.heuristics {
                            if let Some(r) = crate::heur::suspicious(path, &head) {
                                return hit(format!("suspicious: {r}"));
                            }
                        }
                    }
                    Outcome::Clean(ce)
                },
            )
            .collect()
    });

    let mut report = Report::default();
    let mut clean = Vec::new();
    for o in outcomes {
        match o {
            Outcome::Clean(e) => {
                report.scanned += 1;
                clean.extend(e);
            }
            Outcome::Unchanged => report.skipped_unchanged += 1,
            Outcome::Hit(d) => {
                report.scanned += 1;
                report.detections.push(d);
            }
            Outcome::Err => report.errors += 1,
        }
    }
    clean.extend(cache.entries());
    let _ = Cache::save(clean, opts.heuristics);
    report
}
