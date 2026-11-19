use clap::Parser;
use serde::Serialize;
use std::{
    io::{self, Read},
    net::{IpAddr, SocketAddr, TcpStream},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
#[derive(Parser)]
#[command(
    version,
    about = "Local diagnostics; DNS requires dig, HTTPS requires curl, ping requires OS ping"
)]
struct Args {
    target: Option<String>,
    #[arg(default_value = "dns")]
    check: String,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    allow_private: bool,
    #[arg(long, default_value_t=5, value_parser=clap::value_parser!(u64).range(1..=30))]
    timeout: u64,
    #[arg(long, default_value_t = 443)]
    port: u16,
}
#[derive(Serialize)]
struct ResultRow {
    schema_version: u8,
    target: String,
    check: String,
    ok: bool,
    evidence: String,
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
                || (o[0] == 100 && o[1] & 192 == 64))
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || s[0] & 0xfe00 == 0xfc00
                || s[0] & 0xffc0 == 0xfe80
                || a.to_ipv4_mapped().is_some_and(|v| !public(IpAddr::V4(v))))
        }
    }
}
fn run(program: &str, args: &[&str], timeout: u64) -> Result<String, String> {
    let mut c = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{program}: {e}"))?;
    let out = c.stdout.take().unwrap();
    let err = c.stderr.take().unwrap();
    let reader = |mut r: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut b = Vec::new();
            let _ = r.by_ref().take(262144).read_to_end(&mut b);
            b
        })
    };
    let a = reader(Box::new(out));
    let b = reader(Box::new(err));
    let start = Instant::now();
    let status = loop {
        if let Some(s) = c.try_wait().map_err(|e| e.to_string())? {
            break s;
        }
        if start.elapsed() > Duration::from_secs(timeout) {
            let _ = c.kill();
            let _ = c.wait();
            return Err("deadline exceeded".into());
        }
        thread::sleep(Duration::from_millis(20));
    };
    let text = String::from_utf8_lossy(&a.join().unwrap_or_default()).into_owned();
    let err = String::from_utf8_lossy(&b.join().unwrap_or_default()).into_owned();
    if status.success() {
        Ok(text)
    } else {
        Err(format!("{text}{err}"))
    }
}
fn execute(a: &Args, t: &str) -> Result<String, String> {
    if t.is_empty()
        || t.len() > 253
        || t.starts_with('-')
        || !t
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-:".contains(&c))
    {
        return Err("expected a hostname or IP address".into());
    }
    if !a.allow_private {
        if let Ok(ip) = t.parse() {
            if !public(ip) {
                return Err("private target requires --allow-private".into());
            }
        } else if a.check != "headers" {
            return Err(
                "hostname probes require --allow-private: system utilities cannot pin DNS safely"
                    .into(),
            );
        }
    }
    match a.check.as_str() {
        "dns" => run("dig", &[t, "ANY", "+time=2", "+tries=1"], a.timeout),
        "email" => run("dig", &[t, "MX", "+time=2", "+tries=1"], a.timeout),
        "ip" => run("dig", &["-x", t, "+time=2", "+tries=1"], a.timeout),
        "web" => run(
            "curl",
            &[
                "--noproxy",
                "*",
                "--head",
                "--max-time",
                &a.timeout.to_string(),
                &format!("https://{t}/"),
            ],
            a.timeout,
        ),
        "whois" | "rdap" => run(
            "curl",
            &[
                "--noproxy",
                "*",
                "--fail",
                "--max-time",
                &a.timeout.to_string(),
                &format!("https://rdap.org/domain/{t}"),
            ],
            a.timeout,
        ),
        "ports" | "tcp" => {
            let ip: IpAddr = t.parse().map_err(|_| "TCP requires literal IP")?;
            let now = Instant::now();
            TcpStream::connect_timeout(
                &SocketAddr::new(ip, a.port),
                Duration::from_secs(a.timeout),
            )
            .map_err(|e| e.to_string())?;
            Ok(format!(
                "TCP {} connected in {} ms",
                a.port,
                now.elapsed().as_millis()
            ))
        }
        "ping" => {
            let count = if cfg!(windows) { "-n" } else { "-c" };
            run("ping", &[count, "3", t], a.timeout)
        }
        _ => Err("unsupported check (dns, email, ip, web, rdap, tcp, ping)".into()),
    }
}
fn main() {
    let a = Args::parse();
    let t = a.target.clone().unwrap_or_else(|| {
        let mut s = String::new();
        let _ = io::stdin().take(4096).read_to_string(&mut s);
        s.trim().into()
    });
    let r = execute(&a, &t);
    let row = ResultRow {
        schema_version: 1,
        target: t,
        check: a.check.clone(),
        ok: r.is_ok(),
        evidence: r.unwrap_or_else(|e| e),
    };
    if a.json {
        println!("{}", serde_json::to_string(&row).unwrap())
    } else {
        println!("{} {}: {}", row.check, row.target, row.evidence)
    }
    if !row.ok {
        std::process::exit(1)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_addresses() {
        for s in [
            "127.0.0.1",
            "10.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "100.64.0.1",
        ] {
            assert!(!public(s.parse().unwrap()));
        }
        assert!(public("8.8.8.8".parse().unwrap()));
    }
}
