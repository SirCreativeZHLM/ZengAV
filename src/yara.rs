use crate::db;
use std::io::Read;
use yara_x::{Compiler, Rules, Scanner};

pub fn sources_from_zip(bytes: &[u8]) -> Vec<String> {
    let Ok(mut z) = zip::ZipArchive::new(std::io::Cursor::new(bytes)) else { return Vec::new() };
    let mut out = Vec::new();
    for i in 0..z.len() {
        let Ok(mut f) = z.by_index(i) else { continue };
        let name = f.name().map(|n| n.to_ascii_lowercase()).unwrap_or_default();
        if !(name.ends_with(".yar") || name.ends_with(".yara")) || f.size() > 8 << 20 {
            continue;
        }
        let mut s = String::new();
        if f.read_to_string(&mut s).is_ok() {
            out.push(s);
        }
    }
    out
}

/// Compile each source on its own so one incompatible file cannot sink the rest.
pub fn compile_and_save(sources: &[String]) -> std::io::Result<(usize, usize)> {
    let mut compiler = Compiler::new();
    let (mut ok, mut bad) = (0, 0);
    for (i, src) in sources.iter().enumerate() {
        // Probe with a throwaway compiler first; only valid files enter the real one.
        if Compiler::new().add_source(src.as_str()).is_err() {
            bad += 1;
            continue;
        }
        compiler.new_namespace(&format!("f{i}"));
        if compiler.add_source(src.as_str()).is_ok() {
            ok += 1;
        } else {
            bad += 1;
        }
    }
    let bytes = compiler.build().serialize().map_err(|e| std::io::Error::other(e.to_string()))?;
    let dir = db::data_dir();
    std::fs::create_dir_all(&dir)?;
    let tmp = dir.join("rules.bin.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, dir.join("rules.bin"))?;
    Ok((ok, bad))
}

pub fn load() -> Option<Rules> {
    let bytes = std::fs::read(db::data_dir().join("rules.bin")).ok()?;
    Rules::deserialize(bytes).ok()
}

pub fn scanner(rules: &Rules) -> Scanner<'_> {
    let mut s = Scanner::new(rules);
    s.set_timeout(std::time::Duration::from_secs(10));
    s
}

/// Names of rules matching `path`, or empty on any error.
pub fn matches(s: &mut Scanner<'_>, path: &std::path::Path) -> Vec<String> {
    match s.scan_file(path) {
        Ok(r) => r.matching_rules().map(|m| m.identifier().to_string()).collect(),
        Err(_) => Vec::new(),
    }
}
