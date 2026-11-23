//! Regressions from the 2026-11-22 review: hostile input, evidence ownership,
//! exit codes, redundant queries and concurrency. Loopback fixtures only.

mod common;
use common::{run_with_fixture, Seen};
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{
        rdata::{A, MX, TXT},
        Name, RData, Record, RecordType,
    },
};
use serde_json::Value;
use std::collections::HashMap;
use std::process::{Output, Stdio};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const BIN: &str = env!("CARGO_BIN_EXE_wheredns");
const NOW: Duration = Duration::ZERO;

fn json(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|_| panic!("stdout is JSON: {}", String::from_utf8_lossy(&out.stderr)))
}

fn result<'a>(v: &'a Value, check: &str) -> &'a Value {
    v["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["check"] == check)
        .unwrap_or_else(|| panic!("no {check} result in {v}"))
}

fn finding<'a>(v: &'a Value, name: &str) -> &'a Value {
    result(v, "email")["data"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == name)
        .unwrap()
}

fn question(m: &Message) -> (String, RecordType) {
    let q = &m.queries[0];
    let name = q
        .name()
        .to_ascii()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (name, q.query_type())
}

fn txt_at(m: &mut Message, owner: &str, text: &str) {
    m.add_answer(Record::from_rdata(
        Name::from_ascii(owner).unwrap(),
        300,
        RData::TXT(TXT::new(vec![text.into()])),
    ));
}

/// Answers TXT questions from `records` (owner → values); everything else NODATA.
fn txt_zone(records: &'static [(&'static str, &'static str)]) -> impl Fn(&mut Message) -> bool {
    move |m| {
        let (name, ty) = question(m);
        if ty == RecordType::TXT {
            for (owner, text) in records.iter().filter(|(o, _)| *o == name) {
                txt_at(m, &format!("{owner}."), text);
            }
        }
        true
    }
}

// ── hostile DNS data ────────────────────────────────────────────────────────

#[tokio::test]
async fn non_ascii_txt_never_crashes_the_email_check() {
    let (out, _) = run_with_fixture(
        &["example.test", "email", "--json"],
        &[],
        NOW,
        txt_zone(&[
            ("example.test", "aaaaa€"),
            ("example.test", "v=spf€"),
            ("example.test", "€"),
            ("_dmarc.example.test", "v=DMARC€"),
            ("_mta-sts.example.test", "v=STS€1"),
            ("google._domainkey.example.test", "v=DKIM1; p=€"),
        ]),
    )
    .await;
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = json(&out);
    assert_eq!(finding(&v, "SPF")["value"], "no SPF record");
    assert_eq!(finding(&v, "DKIM")["kind"], "warn");
}

#[tokio::test]
async fn records_at_unrelated_owners_are_not_evidence() {
    let (out, _) = run_with_fixture(&["example.test", "email", "--json"], &[], NOW, |m| {
        let (name, ty) = question(m);
        if ty == RecordType::TXT && name == "example.test" {
            txt_at(m, "unrelated.test.", "v=spf1 -all");
        }
        true
    })
    .await;
    let v = json(&out);
    assert_eq!(finding(&v, "SPF")["value"], "no SPF record");
}

#[tokio::test]
async fn policy_version_impostors_and_keyless_dkim_are_not_positives() {
    let (out, _) = run_with_fixture(
        &[
            "example.test",
            "email",
            "dkim:a",
            "dkim:b",
            "dkim:c",
            "dkim:d",
            "--json",
        ],
        &[],
        NOW,
        txt_zone(&[
            ("_dmarc.example.test", "v=DMARC10; p=reject"),
            ("_mta-sts.example.test", "v=STSv10; id=1"),
            ("a._domainkey.example.test", "v=DKIM1; k=rsa"),
            ("b._domainkey.example.test", "v=DKIM1; p=not*base64"),
            ("c._domainkey.example.test", "v=DKIM1; p=; p=AAAA"),
            ("d._domainkey.example.test", "v=DKIM10; p=AAAA"),
        ]),
    )
    .await;
    let v = json(&out);
    assert_eq!(finding(&v, "DMARC")["value"], "no direct DMARC record");
    assert_eq!(finding(&v, "MTA-STS")["value"], "not published");
    let dkim = finding(&v, "DKIM");
    assert_eq!(dkim["kind"], "warn", "{dkim}");
    for sel in [
        "a (no p=",
        "b (p= is not valid base64)",
        "c (malformed",
        "d (v= must",
    ] {
        assert!(
            dkim["note"].as_str().unwrap().contains(sel),
            "{sel}: {dkim}"
        );
    }
    // A structurally valid key and a revoked one are still recognized.
    let (out, _) = run_with_fixture(
        &["example.test", "email", "dkim:good", "dkim:dead", "--json"],
        &[],
        NOW,
        txt_zone(&[
            (
                "good._domainkey.example.test",
                "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ==",
            ),
            ("dead._domainkey.example.test", "v=DKIM1; p="),
        ]),
    )
    .await;
    let v = json(&out);
    let dkim = finding(&v, "DKIM");
    assert_eq!(dkim["kind"], "pass");
    assert_eq!(dkim["value"], "good");
    assert!(dkim["note"].as_str().unwrap().contains("revoked: dead"));
}

// ── status and exit codes ───────────────────────────────────────────────────

#[tokio::test]
async fn email_nxdomain_is_a_result() {
    let (out, _) = run_with_fixture(&["gone.example.test", "email", "--json"], &[], NOW, |m| {
        m.metadata.response_code = ResponseCode::NXDomain;
        true
    })
    .await;
    assert_eq!(out.status.code(), Some(0));
    let v = json(&out);
    assert_eq!(result(&v, "email")["ok"], true);
    assert_eq!(result(&v, "email")["data"]["nxdomain"], true);
}

#[tokio::test]
async fn one_failed_dkim_selector_fails_the_email_check() {
    let (out, _) = run_with_fixture(&["example.test", "email", "--json"], &[], NOW, |m| {
        if question(m).0 == "google._domainkey.example.test" {
            m.metadata.response_code = ResponseCode::ServFail;
        }
        true
    })
    .await;
    assert_eq!(out.status.code(), Some(1));
    let v = json(&out);
    assert!(result(&v, "email")["error"]
        .as_str()
        .unwrap()
        .contains("google"));
    assert!(result(&v, "email")["data"]["findings"].is_array());
}

#[tokio::test]
async fn servfail_fails_blacklist_and_subdomains_but_keeps_rows() {
    for (target, check) in [("1.1.1.1", "blacklist"), ("example.test", "subdomains")] {
        let (out, _) = run_with_fixture(&[target, check, "--json"], &[], NOW, |m| {
            m.metadata.response_code = ResponseCode::ServFail;
            true
        })
        .await;
        assert_eq!(out.status.code(), Some(1), "{check}");
        let v = json(&out);
        let r = result(&v, check);
        assert_eq!(r["ok"], false, "{check}");
        assert!(!r["data"]["rows"].as_array().unwrap().is_empty(), "{check}");
    }
}

#[tokio::test]
async fn null_mx_skips_the_domain_blacklist() {
    let (out, seen) = run_with_fixture(&["example.test", "blacklist", "--json"], &[], NOW, |m| {
        if question(m).1 == RecordType::MX {
            let owner = m.queries[0].name().clone();
            m.add_answer(Record::from_rdata(
                owner,
                300,
                RData::MX(MX::new(0, Name::root())),
            ));
        }
        true
    })
    .await;
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(seen.queries, [("example.test".to_string(), RecordType::MX)]);
    let v = json(&out);
    assert!(result(&v, "blacklist")["data"]["not_applicable"].is_string());
}

/// Runs `ping` against a fake `ping` that prints one reply and exits `code`.
#[cfg(unix)]
fn run_fake_ping(code: i32) -> std::process::Output {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("wheredns-ping-{}-{code}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ping = dir.join("ping");
    std::fs::write(
        &ping,
        format!(
            "#!/bin/sh\nprintf '64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=1.0 ms\\n'\nexit {code}\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&ping, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = format!(
        "{}:{}",
        dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = std::process::Command::new(BIN)
        .args(["127.0.0.1", "ping", "--allow-private", "--json"])
        .env("PATH", path)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    out
}

#[cfg(unix)]
#[test]
fn ping_error_exit_fails_even_with_a_reply() {
    // Exit 2 is an error on Linux iputils and macOS, not packet loss.
    let out = run_fake_ping(2);
    assert_eq!(out.status.code(), Some(1));
    let v = json(&out);
    let r = result(&v, "ping");
    assert_eq!(r["data"]["received"], 1, "samples are kept");
    assert!(r["error"].as_str().unwrap().contains("1/10 replies"));
}

#[cfg(unix)]
#[test]
fn ping_packet_loss_exit_is_a_result() {
    // Linux iputils exits 1 when some, but not all, replies arrive.
    let out = run_fake_ping(1);
    assert_eq!(out.status.code(), Some(0));
    let v = json(&out);
    let r = result(&v, "ping");
    assert_eq!(r["ok"], true);
    assert_eq!(r["data"]["received"], 1);
}

// ── redundant work and concurrency ──────────────────────────────────────────

#[tokio::test]
async fn overlapping_checks_never_ask_the_same_question_twice() {
    let (out, seen) = run_with_fixture(
        // `all`, offline: the fixture gives rdap.org and the target no address,
        // so registry, web, ping and port checks stop before leaving loopback.
        &["example.test", "all", "--json"],
        &[],
        Duration::from_millis(30),
        |m| {
            let (name, ty) = question(m);
            let owner = m.queries[0].name().clone();
            match (name.as_str(), ty) {
                ("example.test", RecordType::MX) => m.add_answer(Record::from_rdata(
                    owner,
                    300,
                    RData::MX(MX::new(10, Name::from_ascii("mail.example.test.").unwrap())),
                )),
                ("mail.example.test", RecordType::A) => m.add_answer(Record::from_rdata(
                    owner,
                    300,
                    RData::A(A::new(192, 0, 2, 25)),
                )),
                _ => m,
            };
            true
        },
    )
    .await;
    assert!(out.status.code().is_some());
    let mut counts: HashMap<&(String, RecordType), usize> = HashMap::new();
    for q in &seen.queries {
        *counts.entry(q).or_default() += 1;
    }
    let repeated: Vec<_> = counts.iter().filter(|(_, n)| **n > 1).collect();
    assert!(repeated.is_empty(), "asked more than once: {repeated:?}");
    // The shared questions really were shared, not skipped.
    for q in [
        ("example.test", RecordType::A),
        ("example.test", RecordType::NS),
        ("rdap.org", RecordType::A),
        ("example.test", RecordType::MX),
        ("example.test", RecordType::TXT),
        ("mail.example.test", RecordType::A),
    ] {
        assert!(
            counts.contains_key(&(q.0.to_string(), q.1)),
            "{q:?} never asked"
        );
    }
}

#[tokio::test]
async fn concurrency_bounds_in_flight_operations_per_check() {
    for (limit, check) in [("1", "subdomains"), ("3", "dns"), ("2", "email")] {
        let (_, Seen { peak, queries }) = run_with_fixture(
            &["example.test", check, "--json", "--concurrency", limit],
            &[],
            Duration::from_millis(15),
            |_| true,
        )
        .await;
        let limit: usize = limit.parse().unwrap();
        assert!(queries.len() > limit, "{check}");
        assert!(peak <= limit, "{check}: peak {peak} > {limit}");
        assert_eq!(peak, limit, "{check}: limit not used");
    }
}

// ── cancellation and deadlines ──────────────────────────────────────────────

#[tokio::test]
async fn cancelled_blacklist_keeps_answered_lists() {
    let (out, _) = run_with_fixture(
        &[
            "1.1.1.1",
            "blacklist",
            "--json",
            "--deadline",
            "1",
            "--concurrency",
            "16",
        ],
        &[],
        NOW,
        |m| question(m).0.ends_with("bl.spamcop.net"),
    )
    .await;
    assert_eq!(out.status.code(), Some(130));
    let v = json(&out);
    let data = &result(&v, "blacklist")["data"];
    assert_eq!(data["incomplete"], true);
    let rows = data["rows"].as_array().unwrap();
    assert!(rows
        .iter()
        .any(|r| r["name"] == "SpamCop" && r["kind"] == "clean"));
    assert!(rows.iter().any(|r| r["kind"] == "pending"));
}

#[tokio::test]
async fn headers_honor_the_deadline_on_stalled_input() {
    let mut child = tokio::process::Command::new(BIN)
        .args(["headers", "--json", "--deadline", "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let _stdin = child.stdin.take(); // held open, never written
    let out = tokio::time::timeout(Duration::from_secs(6), child.wait_with_output())
        .await
        .expect("deadline applies to headers")
        .unwrap();
    assert_eq!(out.status.code(), Some(130));
    assert_eq!(json(&out)["complete"], false);
}

// ── HTTP response parsing ───────────────────────────────────────────────────

/// Serves one scripted response per request on loopback and runs `web`.
async fn web_against(responses: Vec<Vec<u8>>) -> (Output, usize) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = async move {
        let mut hits = 0;
        for response in responses {
            let Ok(Ok((socket, _))) =
                tokio::time::timeout(Duration::from_secs(3), listener.accept()).await
            else {
                break;
            };
            hits += 1;
            let mut reader = BufReader::new(socket);
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
            }
            let _ = reader.get_mut().write_all(&response).await;
        }
        hits
    };
    let mut command = tokio::process::Command::new(BIN);
    command
        .args([
            &format!("http://{addr}/r0"),
            "web",
            "--allow-private",
            "--json",
            "--timeout",
            "2",
        ])
        .kill_on_drop(true);
    let (out, hits) = tokio::join!(command.output(), server);
    (out.unwrap(), hits)
}

#[tokio::test]
async fn http_interim_incomplete_and_oversized_responses() {
    let (out, _) = web_against(vec![
        b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
    ])
    .await;
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(result(&json(&out), "web")["data"]["final"]["status"], 200);

    let (out, _) = web_against(vec![b"HTTP/1.1 200 OK\r\nServer: half\r\n".to_vec()]).await;
    assert_eq!(
        out.status.code(),
        Some(1),
        "an unfinished header block is not a 200"
    );

    let mut big = b"HTTP/1.1 200 OK\r\nX-Big: ".to_vec();
    big.extend(vec![b'a'; 70 * 1024]);
    big.extend_from_slice(b"\r\n\r\n");
    let (out, _) = web_against(vec![big]).await;
    assert_eq!(out.status.code(), Some(1));
}

#[tokio::test]
async fn five_redirects_are_followed_and_a_sixth_is_refused() {
    let chain = |n: usize| -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                format!(
                    "HTTP/1.1 301 Moved\r\nLocation: /r{}\r\nContent-Length: 0\r\n\r\n",
                    i + 1
                )
                .into_bytes()
            })
            .chain([b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()])
            .collect()
    };
    let (out, hits) = web_against(chain(5)).await;
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(hits, 6);
    let (out, hits) = web_against(chain(6)).await;
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(hits, 6);
    assert!(result(&json(&out), "web")["error"]
        .as_str()
        .unwrap()
        .contains("more than 5 redirects"));
}

// ── settings ────────────────────────────────────────────────────────────────

#[test]
fn config_path_works_without_home() {
    let dir = std::env::temp_dir().join(format!("wheredns-appdata-{}", std::process::id()));
    let out = std::process::Command::new(BIN)
        .args(["config", "path"])
        .env_remove("HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("USERPROFILE")
        .env("APPDATA", &dir)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let path = String::from_utf8(out.stdout).unwrap();
    assert!(
        std::path::Path::new(path.trim()).starts_with(&dir),
        "{path}"
    );
}
