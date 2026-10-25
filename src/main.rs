use zengav::{db, scan, update};

use clap::{Parser, Subcommand};
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "zengav", version, about = "No-bloat antivirus: scan and check")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Args)]
struct Opts {
    /// Only report; never ask what to do with detections
    #[arg(long)]
    report_only: bool,
    /// Delete every detection without asking
    #[arg(long, conflicts_with = "report_only")]
    delete: bool,
    /// Download the latest malware hashes and YARA rules first
    #[arg(long)]
    update: bool,
    /// Also flag weak signals (packed executables in temp folders)
    #[arg(long)]
    heuristics: bool,
    /// Ignore the unchanged-file cache and rescan everything
    #[arg(long)]
    full: bool,
    /// Print each file as it is scanned
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan the whole computer
    Scan(#[command(flatten)] Opts),
    /// Check individual files or folders
    Check {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[command(flatten)]
        opts: Opts,
    },
}

fn main() -> ExitCode {
    let (roots, opts) = match Cli::parse().cmd {
        Cmd::Scan(o) => (scan::roots_for_full_scan(), o),
        Cmd::Check { paths, opts } => (paths, opts),
    };
    if opts.update {
        for line in update::run() {
            eprintln!("{line}");
        }
    }
    let database = db::Db::load();
    let so = scan::Options { verbose: opts.verbose, heuristics: opts.heuristics, full: opts.full, progress: None };
    let report = scan::run(&roots, &database, &so);
    println!(
        "Scanned {} files ({} unchanged skipped, {} unreadable)",
        report.scanned, report.skipped_unchanged, report.errors
    );
    if report.detections.is_empty() {
        println!("No threats found.");
        return ExitCode::SUCCESS;
    }
    println!("{} threat(s) found:", report.detections.len());
    for d in &report.detections {
        println!("  {}  [{}] {}", d.path.display(), &d.hash[..12], d.reason);
    }
    let interactive = !opts.report_only && !opts.delete && io::stdin().is_terminal();
    for d in &report.detections {
        if opts.delete {
            act_delete(d);
        } else if interactive {
            prompt(d, &mut io::stdin().lock());
        }
    }
    ExitCode::from(1)
}

fn act_delete(d: &scan::Detection) {
    match std::fs::remove_file(&d.path) {
        Ok(()) => println!("Deleted {}", d.path.display()),
        Err(e) => eprintln!("Could not delete {}: {e}", d.path.display()),
    }
}

fn prompt(d: &scan::Detection, input: &mut impl BufRead) {
    loop {
        print!("{} -> [d]elete, [a]ccept (never flag again), [s]kip? ", d.path.display());
        io::stdout().flush().ok();
        let mut line = String::new();
        if input.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "d" => return act_delete(d),
            "a" => {
                match db::accept(&d.hash, &d.path.display().to_string()) {
                    Ok(()) => println!("Accepted; this exact file content won't be flagged again."),
                    Err(e) => eprintln!("Could not save acceptance: {e}"),
                }
                return;
            }
            "s" | "" => return,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_is_remembered() {
        let dir = std::env::temp_dir().join("zengav_accept");
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("ZENGAV_HOME", &dir);
        let hash = "a".repeat(64);
        let d = scan::Detection { path: "x".into(), hash: hash.clone(), reason: String::new() };
        prompt(&d, &mut "a\n".as_bytes());
        assert!(std::fs::read_to_string(dir.join("allow.txt")).unwrap().starts_with(&hash));
    }

    #[test]
    fn delete_removes_file() {
        let f = std::env::temp_dir().join("zengav_del.bin");
        std::fs::write(&f, "x").unwrap();
        prompt(&scan::Detection { path: f.clone(), hash: "b".repeat(64), reason: String::new() }, &mut "d\n".as_bytes());
        assert!(!f.exists());
    }
}
