use crate::cache::{self, Cache};
use crate::db::{self, Db, Hash};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;
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

#[derive(Default)]
pub struct Options {
    pub verbose: bool,
    pub heuristics: bool,
    pub full: bool,
    /// Live counters and a cancel flag, for interfaces that show progress.
    pub progress: Option<std::sync::Arc<Progress>>,
}

#[derive(Default)]
pub struct Progress {
    pub files: AtomicU64,
    pub current: Mutex<String>,
    pub cancel: std::sync::atomic::AtomicBool,
}

impl Progress {
    fn cancelled(&self) -> bool {
        self.cancel.load(Relaxed)
    }
}

pub fn delete_file(path: &Path) -> std::io::Result<()> {
    std::fs::remove_file(path)
}

/// Pseudo or volatile filesystems that hold no files worth scanning.
fn skipped(p: &Path) -> bool {
    const SKIP: &[&str] = &["/proc", "/sys", "/dev", "/run", "/private/var/vm", "/System/Volumes/VM", "/System/Volumes/Preboot", "/System/Volumes/Data"];
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

const YARA_MAX_SIZE: u64 = 16 << 20;

pub fn run(roots: &[PathBuf], db: &Db, opts: &Options) -> Report {
    lower_priority();
    let threads = (std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2) / 2).max(1);
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().expect("thread pool");
    let rules = crate::yara::load();
    let cache = Cache::load(opts.heuristics);
    let spill = cache::Spill::new().ok();

    let (scanned, unchanged, errors) = (AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0));
    let detections: Mutex<Vec<Detection>> = Mutex::new(Vec::new());

    pool.install(|| {
        let files = roots.iter().flat_map(|r| {
            WalkDir::new(r)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| !skipped(e.path()))
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
        });
        let files = files.take_while(|_| !opts.progress.as_ref().is_some_and(|p| p.cancelled()));
        files.par_bridge().for_each_init(
            || (rules.as_ref().map(crate::yara::scanner), spill.as_ref().map(|s| s.writer())),
            |(yscan, out), e| {
                let path = e.path();
                if let Some(p) = &opts.progress {
                    if p.files.fetch_add(1, Relaxed) % 64 == 0 {
                        *p.current.lock().unwrap() = path.display().to_string();
                    }
                }
                let md = e.metadata().ok();
                let ce = md.as_ref().and_then(|m| cache::entry(path, m));
                if !opts.full && ce.is_some_and(|c| cache.hit(c)) {
                    if let (Some(c), Some(o)) = (ce, out.as_mut()) {
                        o.push(c);
                    }
                    unchanged.fetch_add(1, Relaxed);
                    return;
                }
                if opts.verbose {
                    eprintln!("scanning {}", path.display());
                }
                let hash = match sha256(path) {
                    Ok(h) => h,
                    Err(_) => {
                        errors.fetch_add(1, Relaxed);
                        return;
                    }
                };
                scanned.fetch_add(1, Relaxed);
                let hex = db::to_hex(&hash);
                let found = |reason: String| {
                    detections.lock().unwrap().push(Detection { path: path.to_path_buf(), hash: hex.clone(), reason });
                };
                let mut reason: Option<String> = None;
                if db.is_malicious(&hash) {
                    reason = Some("known malware hash".into());
                } else if !db.is_allowed(&hash) {
                    let size = md.as_ref().map_or(0, |m| m.len());
                    if size > 0 && (yscan.is_some() || opts.heuristics) {
                        let head = crate::heur::read_head(path);
                        if let Some(sc) = yscan.as_mut().filter(|_| size <= YARA_MAX_SIZE && crate::heur::worth_rules(path, &head)) {
                            let m = crate::yara::matches(sc, path);
                            if !m.is_empty() {
                                reason = Some(format!("YARA rule: {}", m.join(", ")));
                            }
                        }
                        if reason.is_none() && opts.heuristics {
                            reason = crate::heur::suspicious(path, &head).map(|r| format!("suspicious: {r}"));
                        }
                    }
                }
                match reason {
                    Some(r) => found(r),
                    None => {
                        if let (Some(c), Some(o)) = (ce, out.as_mut()) {
                            o.push(c);
                        }
                    }
                }
            },
        );
    });

    if let Some(sp) = spill {
        // Entries for files outside this run's roots stay valid, so carry them forward.
        {
            let mut w = sp.writer_raw();
            let _ = cache.carry_over(&mut w);
        }
        let _ = sp.finish(opts.heuristics);
    }
    let mut detections = detections.into_inner().unwrap();
    detections.sort_by(|a, b| a.path.cmp(&b.path));
    Report {
        scanned: scanned.into_inner(),
        skipped_unchanged: unchanged.into_inner(),
        errors: errors.into_inner(),
        detections,
    }
}
