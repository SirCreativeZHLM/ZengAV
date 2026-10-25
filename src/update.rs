use crate::db;
use std::io::Read;

const MB_URL: &str = "https://mb-api.abuse.ch/v2/files/exports";
// MIT-licensed rules; other feeds can be listed (one URL per line, .zip of .yar files) in feeds.txt.
const DEFAULT_RULES: &str = "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip";

fn get(url: &str, limit: u64) -> Result<Vec<u8>, String> {
    let resp = ureq::get(url).timeout(std::time::Duration::from_secs(120)).call().map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    resp.into_reader().take(limit).read_to_end(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

fn abusech_key() -> Option<String> {
    std::env::var("ZENGAV_ABUSECH_KEY")
        .ok()
        .or_else(|| std::fs::read_to_string(db::data_dir().join("abusech.key")).ok())
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
}

/// Pull every 64-hex SHA-256 out of a CSV/TXT export.
fn parse_hashes(text: &str) -> Vec<db::Hash> {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .flat_map(|l| l.split(',').filter_map(|f| db::from_hex(f.trim().trim_matches('"'))))
        .collect()
}

pub fn run() {
    match abusech_key() {
        Some(k) => match get(&format!("{MB_URL}/{k}/recent.csv"), 512 << 20) {
            Ok(b) => {
                let hashes = parse_hashes(&String::from_utf8_lossy(&b));
                if hashes.is_empty() {
                    eprintln!("MalwareBazaar: no hashes in response (bad key?)");
                } else {
                    let added = hashes.len();
                    match db::merge_hashes(hashes) {
                        Ok(total) => println!("Hashes: merged {added} from MalwareBazaar, {total} total"),
                        Err(e) => eprintln!("Hashes: could not write database: {e}"),
                    }
                }
            }
            Err(e) => eprintln!("MalwareBazaar download failed: {e}"),
        },
        None => eprintln!(
            "No abuse.ch Auth-Key: skipping malware hashes. Get a free key at https://auth.abuse.ch/ \
             and set ZENGAV_ABUSECH_KEY or put it in {}",
            db::data_dir().join("abusech.key").display()
        ),
    }
    let feeds = std::fs::read_to_string(db::data_dir().join("feeds.txt")).unwrap_or_else(|_| DEFAULT_RULES.to_string());
    let mut sources = Vec::new();
    for url in feeds.lines().map(str::trim).filter(|l| l.starts_with("https://")) {
        match get(url, 256 << 20) {
            Ok(b) => sources.extend(crate::yara::sources_from_zip(&b)),
            Err(e) => eprintln!("Rules: {url} failed: {e}"),
        }
    }
    // Your own rules: any .yar/.yara file in <config>/zengav/rules/.
    if let Ok(rd) = std::fs::read_dir(db::data_dir().join("rules")) {
        sources.extend(rd.filter_map(|e| std::fs::read_to_string(e.ok()?.path()).ok()));
    }
    if sources.is_empty() {
        eprintln!("Rules: nothing downloaded; keeping existing rules");
        return;
    }
    match crate::yara::compile_and_save(&sources) {
        Ok((ok, bad)) => println!("Rules: compiled {ok} files ({bad} skipped as incompatible)"),
        Err(e) => eprintln!("Rules: could not save: {e}"),
    }
}
