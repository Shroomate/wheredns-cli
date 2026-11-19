mod dns;
use clap::Parser;
use futures_util::{stream, StreamExt};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    io::{self, Read},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};
#[derive(Parser, Debug)]
#[command(
    version,
    about = "Local DNS, mail, registration and network diagnostics"
)]
struct Args {
    target: Option<String>,
    #[arg(default_value = "summary")]
    check: String,
    /// DNS record types after the command, e.g. dns A MX
    records: Vec<String>,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    allow_private: bool,
    #[arg(long,default_value_t=5,value_parser=clap::value_parser!(u64).range(1..=30))]
    timeout: u64,
    #[arg(long,default_value_t=60,value_parser=clap::value_parser!(u64).range(1..=300))]
    deadline: u64,
    #[arg(long,default_value_t=4,value_parser=clap::value_parser!(u8).range(1..=16))]
    concurrency: u8,
    #[arg(long, default_value = "1.1.1.1:53")]
    resolver: SocketAddr,
    #[arg(
        long = "type",
        value_delimiter = ',',
        default_value = "A,AAAA,CNAME,NS,SOA,MX,TXT,CAA"
    )]
    types: Vec<String>,
    #[arg(long, value_delimiter = ',', default_value = "443")]
    ports: Vec<u16>,
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "default,google,selector1,selector2"
    )]
    selectors: Vec<String>,
}
#[derive(Serialize)]
struct Row {
    check: String,
    ok: bool,
    data: Value,
    error: Option<String>,
}
#[derive(Serialize)]
struct Report {
    schema_version: u8,
    target: String,
    vantage: &'static str,
    elapsed_ms: u128,
    complete: bool,
    results: Vec<Row>,
}
fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_multicast()
                || o[0] == 0
                || o[0] >= 224
                || (o[0] == 192 && o[1] == 0)
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19 || (o[1] == 51 && o[2] == 100)))
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
                || (o[0] == 100 && o[1] & 192 == 64))
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || s[0] & 0xfe00 == 0xfc00
                || s[0] & 0xffc0 == 0xfe80
                || s[0] & 0xffc0 == 0xfec0
                || (a.to_ipv4_mapped().is_none()
                    && (s[0] & 0xe000 != 0x2000
                        || (s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0xdb8))
                        || s[0] == 0x2002))
                || a.to_ipv4_mapped().is_some_and(|v| !public(IpAddr::V4(v))))
        }
    }
}
fn permit(ip: IpAddr, a: &Args) -> Result<(), String> {
    if a.allow_private || public(ip) {
        Ok(())
    } else {
        Err(format!("destination {ip} requires --allow-private"))
    }
}
fn target(raw: &str) -> Result<(String, reqwest::Url), String> {
    if raw.parse::<IpAddr>().is_ok_and(|v| v.is_ipv6()) {
        return target(&format!("https://[{raw}]/"));
    }
    let u = reqwest::Url::parse(if raw.contains("://") {
        raw
    } else {
        return target(&format!("https://{raw}/"));
    })
    .map_err(|e| e.to_string())?;
    if !["http", "https"].contains(&u.scheme())
        || !u.username().is_empty()
        || u.password().is_some()
    {
        return Err("expected HTTP(S) URL without credentials".into());
    }
    let host = u
        .host_str()
        .ok_or("missing hostname")?
        .trim_matches(['[', ']'])
        .to_string();
    Ok((host, u))
}
async fn lookup(
    a: &Args,
    name: &str,
    kind: &str,
    server: SocketAddr,
    recursive: bool,
) -> Result<dns::Answer, String> {
    permit(server.ip(), a)?;
    tokio::time::timeout(
        Duration::from_secs(a.timeout),
        dns::query(name, kind, server, recursive),
    )
    .await
    .map_err(|_| "DNS timeout".to_string())?
}
async fn addresses(a: &Args, host: &str) -> Result<Vec<IpAddr>, String> {
    let mut ips = vec![];
    if let Ok(ip) = host.parse() {
        ips.push(ip)
    } else {
        for ty in ["A", "AAAA"] {
            let r = lookup(a, host, ty, a.resolver, true).await?;
            ips.extend(r.addresses()?);
        }
    }
    if ips.is_empty() {
        return Err("no IP addresses".into());
    }
    for ip in &ips {
        permit(*ip, a)?
    }
    Ok(ips)
}
async fn http(a: &Args, mut url: reqwest::Url, body: bool) -> Result<Value, String> {
    let mut hops = vec![];
    for _ in 0..6 {
        let host = url
            .host_str()
            .ok_or("missing host")?
            .trim_matches(['[', ']'])
            .to_string();
        let ips = addresses(a, &host).await?;
        let port = url.port_or_known_default().ok_or("unknown port")?;
        let sockets: Vec<_> = ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(a.timeout))
            .resolve_to_addrs(&host, &sockets)
            .build()
            .map_err(|e| e.to_string())?;
        let start = Instant::now();
        let response = if body {
            client.get(url.clone())
        } else {
            client.head(url.clone())
        }
        .send()
        .await
        .map_err(|e| e.to_string())?;
        let status = response.status();
        let headers: Vec<_> = response
            .headers()
            .iter()
            .map(|(k, v)| json!({"name":k.as_str(),"value":v.to_str().unwrap_or("<binary>")}))
            .collect();
        hops.push(json!({"url":url.as_str(),"status":status.as_u16(),"headers":headers,"elapsed_ms":start.elapsed().as_millis()}));
        if status.is_redirection() {
            let loc = response
                .headers()
                .get("location")
                .ok_or("redirect without location")?
                .to_str()
                .map_err(|e| e.to_string())?;
            let next = url.join(loc).map_err(|e| e.to_string())?;
            if !["http", "https"].contains(&next.scheme())
                || !next.username().is_empty()
                || next.password().is_some()
            {
                return Err("unsafe redirect".into());
            }
            url = next;
            continue;
        }
        let data = if body {
            let mut bytes = vec![];
            let mut chunks = response.bytes_stream();
            while let Some(chunk) = chunks.next().await {
                let c = chunk.map_err(|e| e.to_string())?;
                if bytes.len() + c.len() > 1048576 {
                    return Err("HTTP body exceeds 1 MiB".into());
                }
                bytes.extend_from_slice(&c)
            }
            serde_json::from_slice::<Value>(&bytes).map_err(|e| e.to_string())?
        } else {
            Value::Null
        };
        if !status.is_success() {
            return Err(format!("HTTP status {status}"));
        }
        return Ok(json!({"hops":hops,"body":data,"http_success":true}));
    }
    Err("redirect limit exceeded".into())
}
fn ping_program(os: &str, ip: IpAddr) -> &'static str {
    if os == "macos" && ip.is_ipv6() {
        "ping6"
    } else {
        "ping"
    }
}
fn read_headers(reader: impl Read) -> Result<String, String> {
    let mut bytes = Vec::new();
    reader
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("header input: {e}"))?;
    if bytes.len() > 65536 {
        return Err("headers exceed 64 KiB".into());
    }
    String::from_utf8(bytes).map_err(|_| "headers require UTF-8".into())
}
fn parse_headers(raw: &str) -> Value {
    let mut unfolded = String::new();
    for line in raw.lines() {
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) && !unfolded.is_empty() {
            unfolded.push(' ');
            unfolded.push_str(line.trim());
        } else {
            if !unfolded.is_empty() {
                unfolded.push('\n');
            }
            unfolded.push_str(line);
        }
    }
    let mut fields = vec![];
    let mut malformed = 0;
    for line in unfolded.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Some((n, v)) = line.split_once(':') {
            if !n.is_empty() && n.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
                fields.push(json!({"name":n.to_ascii_lowercase(),"value":v.trim()}));
            } else {
                malformed += 1
            }
        } else {
            malformed += 1
        }
    }
    json!({"fields":fields,"malformed_lines":malformed,"authentication_results_untrusted":true})
}
async fn check(a: &Args, host: &str, url: &reqwest::Url, kind: &str) -> Result<Value, String> {
    match kind {
        "dns" => {
            let tasks = a.types.iter().map(|t| async move {
                let t = t.to_uppercase();
                lookup(a, host, &t, a.resolver, true).await
            });
            let rows: Vec<_> = stream::iter(tasks)
                .buffered(a.concurrency as usize)
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?;
            Ok(json!({"queries":rows}))
        }
        "email" => {
            let mut names = vec![
                (host.to_string(), "MX"),
                (host.to_string(), "TXT"),
                (format!("_dmarc.{host}"), "TXT"),
                (format!("_mta-sts.{host}"), "TXT"),
                (format!("_smtp._tls.{host}"), "TXT"),
                (format!("default._bimi.{host}"), "TXT"),
            ];
            for s in &a.selectors {
                if s.len() > 63
                    || !s
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
                {
                    return Err("invalid DKIM selector".into());
                }
                names.push((format!("{s}._domainkey.{host}"), "TXT"))
            }
            let rows: Vec<_> =
                stream::iter(names.iter().map(|(n, t)| lookup(a, n, t, a.resolver, true)))
                    .buffered(a.concurrency as usize)
                    .collect::<Vec<_>>()
                    .await
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?;
            Ok(
                json!({"queries":rows,"scope":"DNS policy evidence; no delivery or signature validation"}),
            )
        }
        "http" => http(a, url.clone(), false).await,
        "web" => http(a, url.clone(), false).await,
        "whois" | "rdap" => {
            let path = if host.parse::<IpAddr>().is_ok() {
                "ip"
            } else {
                "domain"
            };
            http(
                a,
                reqwest::Url::parse(&format!("https://rdap.org/{path}/{host}"))
                    .map_err(|e| e.to_string())?,
                true,
            )
            .await
        }
        "tcp" | "ports" => {
            let ips = addresses(a, host).await?;
            let tasks=a.ports.iter().map(|p|{let ip=ips[0];async move{let start=Instant::now();let r=tokio::time::timeout(Duration::from_secs(a.timeout),tokio::net::TcpStream::connect(SocketAddr::new(ip,*p))).await;json!({"ip":ip,"port":p,"open":matches!(r,Ok(Ok(_))),"elapsed_ms":start.elapsed().as_millis()})}});
            Ok(
                json!({"ports":stream::iter(tasks).buffered(a.concurrency as usize).collect::<Vec<_>>().await}),
            )
        }
        "ip" => {
            let ips = addresses(a, host).await?;
            let mut rows = vec![];
            for ip in ips.iter().take(4) {
                rows.push(json!({"ip":ip,"reverse":lookup(a,&dns::reverse(*ip),"PTR",a.resolver,true).await?}));
            }
            Ok(json!({"addresses":rows}))
        }
        "prop" | "propagation" => {
            let mut zone = host.to_string();
            let ns = loop {
                let r = lookup(a, &zone, "NS", a.resolver, true).await?;
                if r.outcome != dns::Outcome::NoError {
                    return Err("no authoritative zone evidence".into());
                }
                let ns: Vec<_> = r
                    .records
                    .into_iter()
                    .filter(|r| {
                        r.rr_class == 1
                            && r.rr_type == "NS"
                            && r.name
                                .trim_end_matches('.')
                                .eq_ignore_ascii_case(zone.trim_end_matches('.'))
                    })
                    .map(|r| r.value)
                    .collect();
                if !ns.is_empty() {
                    break ns;
                }
                zone = zone
                    .split_once('.')
                    .ok_or("no authoritative zone found")?
                    .1
                    .to_string();
            };
            let mut rows = vec![];
            for name in ns.iter().take(6) {
                match addresses(a, name).await {
                    Ok(ips) => {
                        let server = SocketAddr::new(ips[0], 53);
                        let answer = lookup(a, host, "A", server, false).await?;
                        let soa = lookup(a, &zone, "SOA", server, false).await?;
                        rows.push(json!({"server":name,"answer":answer,"soa":soa}));
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(
                json!({"zone":zone,"servers":rows,"scope":"up to six authoritative servers; A answers and SOA evidence"}),
            )
        }
        "subdomains" => {
            let labels = [
                "www",
                "mail",
                "smtp",
                "imap",
                "pop",
                "webmail",
                "autodiscover",
                "autoconfig",
                "api",
                "dev",
                "staging",
                "test",
                "beta",
                "admin",
                "portal",
                "vpn",
                "remote",
                "ftp",
                "ns1",
                "ns2",
            ];
            let control = format!(
                "wdns-{:x}.{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos(),
                host
            );
            let wildcard = lookup(a, &control, "A", a.resolver, true).await?;
            let rows = stream::iter(labels.iter().map(|n| async move {
                let name = format!("{n}.{host}");
                lookup(a, &name, "A", a.resolver, true).await
            }))
            .buffered(a.concurrency as usize)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
            Ok(
                json!({"wildcard_control":wildcard,"queries":rows,"scope":"20 common names, A only; not exhaustive discovery"}),
            )
        }
        "ping" => {
            let ips = addresses(a, host).await?;
            let mut c = tokio::process::Command::new(ping_program(std::env::consts::OS, ips[0]));
            c.args([
                if cfg!(windows) { "-n" } else { "-c" },
                "3",
                &ips[0].to_string(),
            ])
            .kill_on_drop(true);
            let out = tokio::time::timeout(Duration::from_secs(a.timeout), c.output())
                .await
                .map_err(|_| "ping timeout")?
                .map_err(|e| e.to_string())?;
            if !out.status.success() {
                return Err(format!(
                    "ping failed: {}{}",
                    String::from_utf8_lossy(&out.stdout[..out.stdout.len().min(65536)]),
                    String::from_utf8_lossy(&out.stderr[..out.stderr.len().min(65536)])
                ));
            }
            Ok(
                json!({"success":true,"raw":String::from_utf8_lossy(&out.stdout[..out.stdout.len().min(65536)])}),
            )
        }
        _ => Err(format!("unknown check: {kind}")),
    }
}
#[tokio::main]
async fn main() {
    let mut a = Args::parse();
    if a.target.as_deref() == Some("headers") {
        a.target = None;
        a.check = "headers".into();
    }
    if !a.records.is_empty() {
        a.types = a.records.clone();
    }
    if a.ports.len() > 10 || a.types.len() > 20 || a.selectors.len() > 8 {
        eprintln!("too many ports, types or selectors");
        std::process::exit(2)
    }
    if a.target.is_none() && a.check != "headers" {
        eprintln!("target required; use headers for stdin");
        std::process::exit(2);
    }
    let raw = a.target.clone().unwrap_or_default();
    if a.check == "headers" {
        let s = match read_headers(io::stdin()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        };
        let v = parse_headers(&s);
        println!(
            "{}",
            if a.json {
                serde_json::to_string(&v).unwrap()
            } else {
                serde_json::to_string_pretty(&v).unwrap()
            }
        );
        return;
    }
    let (host, url) = match target(&raw) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2)
        }
    };
    let kinds: Vec<&str> = match a.check.as_str() {
        "summary" | "where" => vec!["dns", "rdap", "ip"],
        "all" => vec![
            "dns",
            "email",
            "web",
            "rdap",
            "ip",
            "tcp",
            "ping",
            "prop",
            "subdomains",
        ],
        s => vec![s],
    };
    let start = Instant::now();
    let work = async {
        let mut rows = vec![];
        for kind in kinds {
            let r = check(&a, &host, &url, kind).await;
            rows.push(match r {
                Ok(data) => Row {
                    check: kind.into(),
                    ok: true,
                    data,
                    error: None,
                },
                Err(e) => Row {
                    check: kind.into(),
                    ok: false,
                    data: Value::Null,
                    error: Some(e),
                },
            })
        }
        rows
    };
    let (rows, complete) = tokio::select! {r=work=>(r,true),_=tokio::signal::ctrl_c()=>(vec![Row{check:"run".into(),ok:false,data:Value::Null,error:Some("cancelled".into())}],false),_=tokio::time::sleep(Duration::from_secs(a.deadline))=>(vec![Row{check:"run".into(),ok:false,data:Value::Null,error:Some("aggregate deadline exceeded".into())}],false)};
    let ok = complete && rows.iter().all(|r| r.ok);
    let report = Report {
        schema_version: 1,
        target: host,
        vantage: "local",
        elapsed_ms: start.elapsed().as_millis(),
        complete,
        results: rows,
    };
    println!(
        "{}",
        if a.json {
            serde_json::to_string(&report).unwrap()
        } else {
            report
                .results
                .iter()
                .map(|r| {
                    format!(
                        "{}: {}\n{}",
                        r.check,
                        if r.ok { "completed" } else { "failed" },
                        r.error
                            .clone()
                            .unwrap_or_else(|| serde_json::to_string_pretty(&r.data).unwrap())
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
    );
    if !ok {
        std::process::exit(if complete { 1 } else { 130 })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_headers_and_platform_policy() {
        assert!(read_headers(&vec![b' '; 65537][..]).is_err());
        assert!(read_headers(&b"Subject: x\n\xff"[..]).is_err());
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("fixture"))
            }
        }
        assert!(read_headers(Broken).is_err());
        assert_eq!(parse_headers("\nSubject: body")["fields"], json!([]));
        assert_eq!(parse_headers(" orphan\nSubject: x")["malformed_lines"], 1);
        for ip in [
            "fec0::1",
            "2001:db8::1",
            "2002::1",
            "192.0.2.1",
            "198.18.0.1",
            "203.0.113.1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "2606:4700:4700::1111"] {
            assert!(public(ip.parse().unwrap()));
        }
        assert_eq!(ping_program("macos", "::1".parse().unwrap()), "ping6");
        assert_eq!(ping_program("linux", "::1".parse().unwrap()), "ping");
        assert_eq!(ping_program("windows", "::1".parse().unwrap()), "ping");
    }
    #[test]
    fn url_normalization() {
        assert_eq!(
            target("https://Example.com/path?q=1").unwrap().0,
            "example.com"
        );
        assert!(target("https://user:pass@example.com").is_err());
        assert!(target("file:///etc/passwd").is_err());
    }
    #[test]
    fn header_fixture() {
        let v=parse_headers("From: sender@example.test\nAuthentication-Results: untrusted\nX-Test: a\nX-Test: b\nbroken");
        assert_eq!(v["fields"].as_array().unwrap().len(), 4);
        assert_eq!(v["malformed_lines"], 1);
        assert_eq!(v["authentication_results_untrusted"], true);
    }
    #[test]
    fn address_policy() {
        for s in [
            "127.0.0.1",
            "10.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "100.64.0.1",
        ] {
            assert!(!public(s.parse().unwrap()))
        }
    }
}
