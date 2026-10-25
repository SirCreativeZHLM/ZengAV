use std::process::Command;

fn eicar() -> String {
    ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"].concat()
}

fn zengav(home: &std::path::Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_zengav"));
    c.env("ZENGAV_HOME", home);
    c
}

#[test]
fn clean_file_passes() {
    let d = std::env::temp_dir().join("zengav_clean");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("a.txt"), "hello").unwrap();
    let o = zengav(&d).args(["check", d.to_str().unwrap(), "--report-only"]).output().unwrap();
    assert!(o.status.success());
}

#[test]
fn eicar_detected_then_deleted() {
    let d = std::env::temp_dir().join("zengav_eicar");
    std::fs::create_dir_all(&d).unwrap();
    let f = d.join("bad.com");
    std::fs::write(&f, eicar()).unwrap();
    let o = zengav(&d).args(["check", f.to_str().unwrap(), "--report-only"]).output().unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(f.exists());
    zengav(&d).args(["check", f.to_str().unwrap(), "--delete"]).output().unwrap();
    assert!(!f.exists());
}

#[test]
fn custom_yara_rule_and_cache() {
    let d = std::env::temp_dir().join("zengav_yara");
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("home/rules")).unwrap();
    std::fs::write(d.join("home/feeds.txt"), "# no remote feeds\n").unwrap();
    std::fs::write(d.join("home/rules/t.yar"), "rule zeng_test { strings: $a = \"ZENGTESTPAYLOAD_9f3a\" condition: $a }").unwrap();
    std::fs::create_dir_all(d.join("scan")).unwrap();
    let f = d.join("scan/x.sh");
    std::fs::write(&f, "echo ZENGTESTPAYLOAD_9f3a").unwrap();
    std::fs::write(d.join("scan/ok.sh"), "echo hi").unwrap();
    let run = |args: &[&str]| zengav(&d.join("home")).arg("check").arg(d.join("scan")).args(args).arg("--report-only").output().unwrap();
    let o = run(&["--update"]);
    let out = String::from_utf8_lossy(&o.stdout).to_string();
    assert_eq!(o.status.code(), Some(1), "{out}");
    assert!(out.contains("zeng_test"), "{out}");
    // Second run: the clean file is served from the cache, the detection is not cached.
    let out2 = String::from_utf8_lossy(&run(&[]).stdout).to_string();
    assert!(out2.contains("1 unchanged skipped") && out2.contains("zeng_test"), "{out2}");
}
