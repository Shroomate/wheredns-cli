use std::io::Write;
use std::process::{Command, Stdio};
#[test]
fn cli_contract() {
    let bin = env!("CARGO_BIN_EXE_wheredns");
    assert!(Command::new(bin)
        .arg("--help")
        .output()
        .unwrap()
        .status
        .success());
    assert!(Command::new(bin)
        .arg("--version")
        .output()
        .unwrap()
        .status
        .success());
    assert_eq!(Command::new(bin).output().unwrap().status.code(), Some(2));
    let mut child = Command::new(bin)
        .args(["headers", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"Subject: folded\r\n continuation\r\nX-Test: a\r\nX-Test: b\r\n\r\nbody")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["fields"][0]["value"], "folded continuation");
    assert_eq!(v["fields"].as_array().unwrap().len(), 3);
    assert!(!out.stdout.contains(&27));
}
