//! End-to-end scenarios: each test runs the real binary against loopback
//! fixtures (a scripted DNS resolver, a saved email header, a scratch config
//! directory). No test sends traffic to the internet.

mod common;
use common::run_with_dns;
use hickory_proto::{
    op::ResponseCode,
    rr::{
        rdata::{MX, TXT},
        Name, RData, Record, RecordType,
    },
};
use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_wheredns");

fn headers(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(BIN)
        .arg("headers")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn json(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).expect("stdout is JSON")
}

fn txt(name: &Name, text: &str) -> Record {
    Record::from_rdata(name.clone(), 300, RData::TXT(TXT::new(vec![text.into()])))
}

/// A fresh, empty config directory for one test.
fn scratch_config(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wheredns-test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ── email headers ───────────────────────────────────────────────────────────

const INVOICE: &[u8] = include_bytes!("fixtures/invoice.eml");

#[test]
fn headers_trace_hops_oldest_first_with_delays() {
    let out = headers(&["--json"], INVOICE);
    assert!(out.status.success());
    let a = &json(&out)["analysis"];
    let hops = a["hops"].as_array().unwrap();
    assert_eq!(hops.len(), 3);
    assert_eq!(hops[0]["by"], "mta.example.com");
    assert_eq!(hops[2]["by"], "mx.example.net");
    assert_eq!(hops[0]["delay_s"], Value::Null);
    assert_eq!(hops[1]["delay_s"], 5);
    assert_eq!(hops[2]["delay_s"], 2);
    assert_eq!(a["total_delay_s"], 7);
    assert_eq!(a["subject"], "Your November invoice");
}

#[test]
fn headers_report_authentication_results_as_untrusted_claims() {
    let out = headers(&["--json"], INVOICE);
    let v = json(&out);
    assert_eq!(v["authentication_results_untrusted"], true);
    let auth = v["analysis"]["auth"].as_array().unwrap();
    let methods: Vec<_> = auth.iter().map(|r| r["method"].as_str().unwrap()).collect();
    assert_eq!(methods, ["dkim", "spf", "dmarc"]);
    assert!(auth.iter().all(|r| r["result"] == "pass"));
}

#[test]
fn headers_terminal_report_is_offline_and_plain_when_piped() {
    let out = headers(&[], INVOICE);
    assert!(out.status.success());
    let report = String::from_utf8(out.stdout).unwrap();
    let first = report.lines().next().unwrap();
    assert_eq!(first, "╭┤headers email header trace├── offline ─");
    // Rows end with their text and stay within the 100-column report width.
    for line in report.lines() {
        assert_eq!(line, line.trim_end(), "trailing spaces: {line:?}");
        assert!(line.chars().count() <= 100, "too wide: {line:?}");
    }
    assert!(report.contains("3 hops, oldest first"));
    assert!(report.contains("total transit 7s"));
    assert!(report.contains("the header never leaves this machine"));
    assert!(!report.contains('\x1b'), "no escape sequences in a pipe");
}

#[test]
fn headers_reject_oversized_and_non_utf8_input() {
    let big = vec![b'a'; 70 * 1024];
    assert_eq!(headers(&[], &big).status.code(), Some(2));
    assert_eq!(
        headers(&[], b"Subject: \xff\xfe\r\n\r\n").status.code(),
        Some(2)
    );
}

// ── DNS outcomes and exit codes ─────────────────────────────────────────────

#[tokio::test]
async fn nxdomain_is_evidence_not_a_failure() {
    let (out, _) = run_with_dns("gone.example.test", &["dns", "A", "--json"], |r| {
        r.metadata.response_code = ResponseCode::NXDomain;
    })
    .await;
    assert_eq!(out.status.code(), Some(0));
    let v = json(&out);
    assert_eq!(v["results"][0]["ok"], true);
    assert_eq!(v["results"][0]["data"]["nxdomain"], true);
}

#[tokio::test]
async fn servfail_fails_the_check() {
    let (out, _) = run_with_dns("broken.example.test", &["dns", "A", "--json"], |r| {
        r.metadata.response_code = ResponseCode::ServFail;
    })
    .await;
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(json(&out)["results"][0]["ok"], false);
}

#[tokio::test]
async fn null_mx_is_labelled_in_the_terminal_report() {
    let (out, _) = run_with_dns("example.test", &["dns", "MX"], |r| {
        let q = r.queries[0].clone();
        if q.query_type() == RecordType::MX {
            r.add_answer(Record::from_rdata(
                q.name().clone(),
                300,
                RData::MX(MX::new(0, Name::root())),
            ));
        }
    })
    .await;
    assert!(out.status.success());
    let report = String::from_utf8(out.stdout).unwrap();
    assert!(
        report.contains("MX         300  0 . (null MX: accepts no mail)"),
        "{report}"
    );
}

#[tokio::test]
async fn email_check_reads_spf_and_dmarc_records() {
    let domain = Name::from_ascii("mail.example.test.").unwrap();
    let dmarc = Name::from_ascii("_dmarc.mail.example.test.").unwrap();
    let mx_host = Name::from_ascii("mx.mail.example.test.").unwrap();
    let (out, _) = run_with_dns("mail.example.test", &["email", "--json"], |r| {
        let q = r.queries[0].clone();
        match (q.name(), q.query_type()) {
            (n, RecordType::MX) if n == &domain => r.add_answer(Record::from_rdata(
                n.clone(),
                300,
                RData::MX(MX::new(10, mx_host.clone())),
            )),
            (n, RecordType::A) if n == &mx_host => r.add_answer(Record::from_rdata(
                n.clone(),
                300,
                RData::A(hickory_proto::rr::rdata::A::new(192, 0, 2, 25)),
            )),
            (n, RecordType::TXT) if n == &domain => r.add_answer(txt(n, "v=spf1 mx -all")),
            (n, RecordType::TXT) if n == &dmarc => {
                r.add_answer(txt(n, "v=DMARC1; p=reject; rua=mailto:d@example.test"))
            }
            _ => r,
        };
    })
    .await;
    let v = json(&out);
    let findings = v["results"][0]["data"]["findings"].as_array().unwrap();
    let find = |name: &str| {
        findings
            .iter()
            .find(|f| f["name"] == name)
            .unwrap_or_else(|| panic!("no {name} finding in {findings:?}"))
    };
    assert_eq!(find("MX")["kind"], "pass");
    assert_eq!(find("MX")["value"], "10 mx.mail.example.test");
    assert_eq!(find("SPF")["value"], "v=spf1 mx -all");
    assert!(find("DMARC")["note"]
        .as_str()
        .unwrap()
        .contains("policy reject"));
}

#[tokio::test]
async fn deadline_cancels_a_hung_run_with_exit_130() {
    // A resolver that accepts packets and never answers.
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver = silent.local_addr().unwrap().to_string();
    let started = Instant::now();
    let out = tokio::process::Command::new(BIN)
        .args(["example.test", "dns", "A", "--json", "--allow-private"])
        .args([
            "--resolver",
            &resolver,
            "--timeout",
            "30",
            "--deadline",
            "1",
        ])
        .kill_on_drop(true)
        .output();
    let out = tokio::time::timeout(Duration::from_secs(10), out)
        .await
        .expect("deadline is enforced")
        .unwrap();
    assert_eq!(out.status.code(), Some(130));
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(silent);
}

// ── input validation and destination policy ─────────────────────────────────

#[test]
fn invalid_targets_are_usage_errors() {
    for target in ["bad domain!!", "http://", "exa mple.com"] {
        let out = Command::new(BIN).args([target, "dns"]).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{target:?}");
        assert!(out.stdout.is_empty(), "{target:?}");
    }
}

#[test]
fn private_destinations_require_allow_private() {
    for (target, check) in [
        ("127.0.0.1", "ports"),
        ("10.0.0.1", "web"),
        ("192.168.1.1", "ports"),
    ] {
        let out = Command::new(BIN)
            .args([target, check, "--json"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{target}");
        let v = json(&out);
        let error = v["results"][0]["error"].to_string();
        assert!(error.contains("--allow-private"), "{target}: {error}");
    }
}

#[test]
fn private_resolver_requires_allow_private() {
    let out = Command::new(BIN)
        .args(["example.test", "dns", "--resolver", "10.0.0.53:53"])
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
}

// ── settings ────────────────────────────────────────────────────────────────

#[test]
fn config_set_show_and_unset_round_trip() {
    let dir = scratch_config("config");
    let run = |args: &[&str]| {
        Command::new(BIN)
            .arg("config")
            .args(args)
            .env("XDG_CONFIG_HOME", &dir)
            .env_remove("WHEREDNS_THEME")
            .env_remove("WHEREDNS_ANIMATE")
            .output()
            .unwrap()
    };
    assert!(run(&["set", "theme", "amber"]).status.success());
    let file = std::fs::read_to_string(dir.join("wheredns/config")).unwrap();
    assert!(file.contains("theme = amber"));
    let shown = String::from_utf8(run(&[]).stdout).unwrap();
    assert!(shown.contains("amber"));

    let bad = run(&["set", "theme", "neon"]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("btop"));

    assert!(run(&["unset", "theme"]).status.success());
    let file = std::fs::read_to_string(dir.join("wheredns/config")).unwrap();
    assert!(!file.contains("theme = amber"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn json_output_is_versioned_and_free_of_escape_sequences() {
    let out = headers(&["--json"], INVOICE);
    let v = json(&out);
    assert_eq!(v["schema_version"], 2);
    assert!(!out.stdout.contains(&0x1b));
}
