mod common;
use common::run_with_dns;
use hickory_proto::{
    op::ResponseCode,
    rr::{rdata::SOA, Name, RData, Record, RecordType},
};
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
    assert_eq!(v["schema_version"], 2);
    assert_eq!(v["fields"][0]["value"], "folded continuation");
    assert_eq!(v["fields"].as_array().unwrap().len(), 3);
    assert!(!out.stdout.contains(&27));
}

#[test]
fn terminal_headers_show_readable_fields() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wheredns"))
        .arg("headers")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"Subject: Hello\r\nX-Color: \x1b[32m\r\n\r\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(!output.stdout.contains(&27));
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(report.starts_with("╭┤headers email header trace├"));
    assert!(report.contains("│ subject       Hello"));
    // Control characters from the message are shown escaped, never emitted raw.
    assert!(report.contains("x-color"));
    assert!(report.contains("\\u{1b}[32m"));
    assert!(!report.lines().any(|l| l.ends_with(' ')));
}

#[test]
fn invalid_checks_and_record_types_are_usage_errors() {
    let bin = env!("CARGO_BIN_EXE_wheredns");
    for args in [
        vec!["example.test", "propoagation"],
        vec!["example.test", "dns", "invalid"],
        vec!["example.test", "dns", "--type", "A,invalid"],
    ] {
        let out = Command::new(bin).args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
}

#[tokio::test]
async fn http_failure_keeps_redirect_evidence() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = async {
        for (path, response) in [
            ("/start", "HTTP/1.1 302 Found\r\nLocation: /missing\r\n"),
            (
                "/missing",
                "HTTP/1.1 404 Not Found\r\nX-Fixture: missing\r\n",
            ),
        ] {
            let (socket, _) = listener.accept().await.unwrap();
            let mut request = String::new();
            let mut reader = BufReader::new(socket);
            reader.read_line(&mut request).await.unwrap();
            assert_eq!(request, format!("HEAD {path} HTTP/1.1\r\n"));
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap() == 0 || line == "\r\n" {
                    break;
                }
            }
            reader
                .get_mut()
                .write_all(
                    format!("{response}Content-Length: 0\r\nConnection: close\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
        }
    };
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_wheredns"));
    command
        .args([
            &format!("http://{addr}/start"),
            "web",
            "--allow-private",
            "--json",
            "--timeout",
            "2",
        ])
        .kill_on_drop(true);
    let (out, ()) = tokio::time::timeout(Duration::from_secs(6), async {
        tokio::join!(command.output(), server)
    })
    .await
    .unwrap();
    let out = out.unwrap();
    assert_eq!(out.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let result = &report["results"][0];
    assert_eq!(result["ok"], false);
    let hops = &result["data"]["hops"];
    assert_eq!(hops[0]["status"], 302);
    assert_eq!(hops[1]["status"], 404);
    assert!(hops[1]["elapsed_ms"].is_u64());
    assert!(hops[1]["headers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|header| { header["name"] == "x-fixture" && header["value"] == "missing" }));
}

#[tokio::test]
async fn propagation_looks_up_parent_zone_after_nxdomain() {
    let target = Name::from_ascii("missing.example.test.").unwrap();
    let zone = Name::from_ascii("example.test.").unwrap();
    let server = Name::from_ascii("ns.example.test.").unwrap();
    let (out, queries) = run_with_dns(
        "missing.example.test",
        &["propagation", "--json"],
        |response| {
            let name = response.queries[0].name();
            if name == &zone {
                response.add_answer(Record::from_rdata(
                    zone.clone(),
                    60,
                    RData::NS(hickory_proto::rr::rdata::NS(server.clone())),
                ));
            } else {
                response.metadata.response_code = ResponseCode::NXDomain;
            }
        },
    )
    .await;
    assert_eq!(
        out.status.code(),
        Some(1),
        "fixture nameserver has no addresses"
    );
    assert_eq!(queries[0], (target, RecordType::NS));
    assert_eq!(queries.get(1), Some(&(zone, RecordType::NS)));
    assert!(queries.contains(&(server, RecordType::A)));
}

#[tokio::test]
async fn dns_labels_cname_without_requested_record_as_nodata() {
    let (out, _) = run_with_dns("www.example.test", &["dns", "AAAA", "--json"], |response| {
        let zone = Name::from_ascii("example.test.").unwrap();
        response.add_answer(Record::from_rdata(
            response.queries[0].name().clone(),
            60,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(zone.clone())),
        ));
        response.add_authority(Record::from_rdata(
            zone,
            60,
            RData::SOA(SOA::new(
                Name::from_ascii("ns.example.test.").unwrap(),
                Name::from_ascii("hostmaster.example.test.").unwrap(),
                1,
                60,
                60,
                60,
                60,
            )),
        ));
    })
    .await;
    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        report["results"][0]["data"]["queries"][0]["status"],
        "NODATA"
    );
}

#[tokio::test]
async fn terminal_dns_groups_queries_and_records() {
    let (out, _) = run_with_dns("example.test", &["dns", "A", "AAAA"], |response| {
        let question = &response.queries[0];
        if question.query_type() == RecordType::A {
            response.add_answer(Record::from_rdata(
                question.name().clone(),
                60,
                RData::A(hickory_proto::rr::rdata::A::new(192, 0, 2, 1)),
            ));
        }
    })
    .await;
    assert!(out.status.success());
    let report = String::from_utf8(out.stdout).unwrap();
    assert!(report.starts_with("wheredns v"));
    assert!(report.contains("╭┤⁶dns "));
    assert!(report.contains("│ A           60  192.0.2.1\n"));
    assert!(report.contains("│ AAAA         -  -- no record\n"));
    assert!(report.contains("1/1 checks ok"));
    assert!(!report.contains('\x1b'));
}
