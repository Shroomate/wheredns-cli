//! `wheredns local`: this machine's host name, LAN address and gateway, and
//! the public (WAN) address it reaches the internet from.

use crate::{checks, lookup, Args};
use serde_json::{json, Value};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    time::Duration,
};

/// Authoritative servers that answer with the address the query came from.
/// Queried directly (no recursion), so no resolver sits in between.
const ECHO: [(&str, &str, &str, [u8; 4]); 2] = [
    ("OpenDNS", "myip.opendns.com", "A", [208, 67, 222, 222]),
    (
        "Google",
        "o-o.myaddr.l.google.com",
        "TXT",
        [216, 239, 32, 10],
    ),
];

pub async fn run(a: &Args) -> Value {
    let (host, route, wan) = tokio::join!(hostname(), default_route(a), wan(a));
    let lan_ip = lan_ip();
    json!({
        "schema_version": crate::SCHEMA_VERSION,
        "hostname": host,
        "lan": {
            "ip": lan_ip,
            "interface": route.as_ref().and_then(|r| r.1.clone()),
            "gateway": route.map(|r| r.0),
        },
        "wan": wan,
    })
}

/// The address the OS would send internet traffic from. Connecting a UDP
/// socket only picks a route; no packet is sent.
fn lan_ip() -> Option<IpAddr> {
    let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    s.connect(("1.1.1.1", 53)).ok()?;
    Some(s.local_addr().ok()?.ip()).filter(|ip| !ip.is_unspecified())
}

async fn command(a: &Args, program: &str, args: &[&str]) -> Option<String> {
    let out = tokio::time::timeout(
        Duration::from_secs(a.timeout),
        tokio::process::Command::new(program)
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

async fn hostname() -> Option<String> {
    if cfg!(windows) {
        return std::env::var("COMPUTERNAME").ok().filter(|h| !h.is_empty());
    }
    let out = tokio::process::Command::new("hostname")
        .output()
        .await
        .ok()?;
    let h = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!h.is_empty()).then_some(h)
}

/// Default IPv4 gateway and, where the OS reports it, the interface.
async fn default_route(a: &Args) -> Option<(Ipv4Addr, Option<String>)> {
    match std::env::consts::OS {
        "macos" | "freebsd" | "openbsd" | "netbsd" => {
            parse_bsd_route(&command(a, "route", &["-n", "get", "default"]).await?)
        }
        "linux" => parse_proc_route(&std::fs::read_to_string("/proc/net/route").ok()?),
        "windows" => parse_windows_route(&command(a, "route", &["print", "-4", "0.0.0.0"]).await?),
        _ => None,
    }
}

pub fn parse_bsd_route(s: &str) -> Option<(Ipv4Addr, Option<String>)> {
    let field = |k: &str| {
        s.lines()
            .filter_map(|l| l.trim().strip_prefix(k))
            .map(|v| v.trim().to_string())
            .next()
    };
    let gw = field("gateway:")?.parse().ok()?;
    Some((gw, field("interface:")))
}

/// `/proc/net/route`: the row with destination 0, gateway in little-endian hex.
pub fn parse_proc_route(s: &str) -> Option<(Ipv4Addr, Option<String>)> {
    s.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 3 || f[1] != "00000000" {
            return None;
        }
        let gw = u32::from_str_radix(f[2], 16).ok()?;
        let gw = Ipv4Addr::from(gw.to_le_bytes());
        (!gw.is_unspecified()).then(|| (gw, Some(f[0].to_string())))
    })
}

/// `route print`: `0.0.0.0  0.0.0.0  <gateway>  <interface ip>  <metric>`,
/// lowest metric wins.
pub fn parse_windows_route(s: &str) -> Option<(Ipv4Addr, Option<String>)> {
    s.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 5 || f[0] != "0.0.0.0" || f[1] != "0.0.0.0" {
                return None;
            }
            let gw: Ipv4Addr = f[2].parse().ok()?;
            Some((f[4].parse::<u32>().unwrap_or(u32::MAX), gw))
        })
        .min_by_key(|r| r.0)
        .map(|(_, gw)| (gw, None))
}

async fn echo(a: &Args, (name, qname, kind, server): (&str, &str, &str, [u8; 4])) -> Value {
    let server = SocketAddr::from((server, 53));
    let r = lookup(a, qname, kind, server, false).await;
    let ip = r.as_ref().ok().and_then(|ans| {
        ans.values()
            .into_iter()
            .find_map(|v| v.trim_matches('"').parse::<IpAddr>().ok())
    });
    match (ip, r) {
        (Some(ip), _) => json!({"source": name, "ip": ip}),
        (None, Err(e)) => json!({"source": name, "error": e}),
        (None, Ok(_)) => json!({"source": name, "error": "no address in the answer"}),
    }
}

async fn wan(a: &Args) -> Value {
    let (x, y) = tokio::join!(echo(a, ECHO[0]), echo(a, ECHO[1]));
    let sources = vec![x, y];
    let ips: Vec<IpAddr> = sources
        .iter()
        .filter_map(|s| s["ip"].as_str()?.parse().ok())
        .collect();
    let Some(&ip) = ips.first() else {
        return json!({"ip": null, "sources": sources, "error": "no echo server answered"});
    };
    let agree = ips.iter().all(|i| *i == ip);
    let mut out = json!({"ip": ip, "agree": agree, "sources": sources});
    if checks::special_reason(ip).is_none() {
        let zone = if ip.is_ipv4() {
            "origin.asn.cymru.com"
        } else {
            "origin6.asn.cymru.com"
        };
        let origin = lookup(
            a,
            &format!("{}.{zone}", checks::reversed_labels(ip)),
            "TXT",
            a.resolver,
            true,
        )
        .await;
        let f = origin.ok().and_then(|r| {
            r.values()
                .first()
                .map(|v| checks::cymru(v.trim_matches('"')))
        });
        if let Some(f) = f.filter(|f| f.len() >= 2) {
            if let Some(asn) = f[0].split(' ').next().filter(|n| n.parse::<u32>().is_ok()) {
                let name = lookup(
                    a,
                    &format!("AS{asn}.asn.cymru.com"),
                    "TXT",
                    a.resolver,
                    true,
                )
                .await;
                let as_name = name.ok().and_then(|r| {
                    r.values()
                        .first()
                        .and_then(|v| checks::cymru(v.trim_matches('"')).get(4).cloned())
                });
                out["asn"] = json!(format!("AS{asn}"));
                out["as_name"] = json!(as_name);
                out["prefix"] = json!(f[1]);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_parsers_read_each_platform() {
        let mac = "   route to: default\ndestination: default\n       mask: default\n    gateway: 10.0.60.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n";
        assert_eq!(
            parse_bsd_route(mac),
            Some(("10.0.60.1".parse().unwrap(), Some("en0".into())))
        );
        assert_eq!(
            parse_bsd_route("route: writing to routing socket: not in table"),
            None
        );
        let linux = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n\
            eth0\t0010A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n\
            eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n";
        assert_eq!(
            parse_proc_route(linux),
            Some(("192.168.1.1".parse().unwrap(), Some("eth0".into())))
        );
        let win = "IPv4 Route Table\n===\nActive Routes:\nNetwork Destination        Netmask          Gateway       Interface  Metric\n          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.20     35\n          0.0.0.0          0.0.0.0         10.0.0.1       10.0.0.5     25\n";
        assert_eq!(
            parse_windows_route(win),
            Some(("10.0.0.1".parse().unwrap(), None))
        );
        assert_eq!(parse_windows_route("Persistent Routes:\n  None\n"), None);
    }
}
