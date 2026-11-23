//! The check groups. Each runs locally and returns JSON that one panel renders.

use crate::{
    addresses, dns, limited, lookup, public, publish, rdap, util, web, Args, CheckFailure, Group,
    Target,
};
use futures_util::{future::join_all, stream::FuturesUnordered, StreamExt};
use serde_json::{json, Value};
use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

type CheckResult = Result<Value, CheckFailure>;

fn need_domain<'a>(t: &'a Target, group: &str) -> Result<&'a str, CheckFailure> {
    if t.ip.is_some() {
        return Err(format!("{group} needs a domain, not an IP address").into());
    }
    Ok(&t.host)
}

/// Lookup outcome as reported in JSON: answered, nodata, nxdomain, or error.
fn kind_of(r: &Result<dns::Answer, String>) -> &'static str {
    match r {
        Ok(a) => a.kind(),
        Err(e) if e.contains("timeout") => "timeout",
        Err(_) => "error",
    }
}

fn failed(r: &Result<dns::Answer, String>) -> bool {
    r.is_err()
}

fn values(r: &Result<dns::Answer, String>) -> Vec<String> {
    r.as_ref().map(|a| a.values()).unwrap_or_default()
}

fn host_of(value: &str) -> String {
    value.trim_end_matches('.').to_ascii_lowercase()
}

/// Human description for addresses that public lookups skip.
pub fn special_reason(ip: IpAddr) -> Option<&'static str> {
    if public(ip) {
        return None;
    }
    Some(match ip {
        IpAddr::V4(v) if v.is_loopback() => "loopback",
        IpAddr::V4(v) if v.is_private() => "private (RFC 1918)",
        IpAddr::V4(v) if v.is_link_local() => "link-local",
        IpAddr::V4(v) if v.octets()[0] == 100 && v.octets()[1] & 192 == 64 => "shared CGNAT space",
        IpAddr::V6(v) if v.is_loopback() => "loopback",
        IpAddr::V6(v) if v.segments()[0] & 0xfe00 == 0xfc00 => "unique local",
        IpAddr::V6(v) if v.segments()[0] & 0xffc0 == 0xfe80 => "link-local",
        _ => "reserved or special-use",
    })
}

fn reversed_labels(ip: IpAddr) -> String {
    dns::reverse(ip)
        .trim_end_matches(".in-addr.arpa")
        .trim_end_matches(".ip6.arpa")
        .to_string()
}

/// First address of a hostname (IPv4 preferred) that destination policy permits.
async fn primary_ip(a: &Args, t: &Target) -> Result<(IpAddr, Option<String>), CheckFailure> {
    if let Some(ip) = t.ip {
        crate::permit(ip, a)?;
        return Ok((ip, None));
    }
    let ips = addresses(a, &t.host).await?;
    let ip = ips.iter().find(|ip| ip.is_ipv4()).unwrap_or(&ips[0]);
    Ok((*ip, Some(t.host.clone())))
}

// ── where ──────────────────────────────────────────────────────────────────

/// Provider nameserver domains. A nameserver matches when its name is the
/// domain or ends in `.domain` (a DNS label boundary), never by substring.
const DNS_HOSTING_RULES: &[(&[&str], &str)] = &[
    (&["cloudflare.com"], "Cloudflare"),
    (
        &[
            "azure-dns.com",
            "azure-dns.net",
            "azure-dns.org",
            "azure-dns.info",
        ],
        "Microsoft Azure DNS",
    ),
    (&["googledomains.com"], "Google Cloud DNS"),
    (&["domaincontrol.com"], "GoDaddy DNS"),
    (&["registrar-servers.com"], "Namecheap DNS"),
    (&["dnsimple.com"], "DNSimple"),
    (&["nsone.net"], "NS1"),
    (&["digitalocean.com"], "DigitalOcean DNS"),
    (&["akam.net"], "Akamai Edge DNS"),
    (
        &[
            "ultradns.com",
            "ultradns.net",
            "ultradns.org",
            "ultradns.biz",
            "ultradns.info",
            "ultradns.co.uk",
        ],
        "UltraDNS",
    ),
    (&["squarespacedns.com"], "Squarespace DNS"),
    (&["dns-parking.com"], "Hostinger DNS"),
    (&["worldnic.com"], "Network Solutions DNS"),
    (&["he.net"], "Hurricane Electric DNS"),
    (&["vercel-dns.com"], "Vercel DNS"),
    (&["wixdns.net"], "Wix DNS"),
];

fn under(host: &str, domain: &str) -> bool {
    host == domain
        || host
            .strip_suffix(domain)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// Route 53 nameservers: `ns-N.awsdns-NN.{com,net,org,co.uk}`.
fn is_route53(host: &str) -> bool {
    ["com", "net", "org", "co.uk"].iter().any(|tld| {
        host.strip_suffix(tld)
            .and_then(|r| r.strip_suffix('.'))
            .and_then(|r| r.rsplit('.').next().zip(Some(r)))
            .is_some_and(|(label, r)| {
                r.contains('.')
                    && label
                        .strip_prefix("awsdns-")
                        .is_some_and(|n| n.len() == 2 && n.bytes().all(|c| c.is_ascii_digit()))
            })
    })
}

pub fn dns_hosting_providers(nameservers: &[String]) -> Vec<Value> {
    let mut out: Vec<(String, &str)> = vec![];
    for ns in nameservers {
        let host = host_of(ns);
        let known = if is_route53(&host) {
            Some("Amazon Route 53")
        } else {
            DNS_HOSTING_RULES
                .iter()
                .find(|(domains, _)| domains.iter().any(|d| under(&host, d)))
                .map(|(_, name)| *name)
        };
        let item = match known {
            Some(name) => (name.to_string(), "recognized"),
            None => {
                let labels: Vec<_> = host.split('.').collect();
                let domain = if labels.len() > 2 {
                    labels[1..].join(".")
                } else {
                    host.clone()
                };
                (domain, "nameserver-domain")
            }
        };
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out.into_iter()
        .map(|(name, basis)| json!({"name": name, "basis": basis}))
        .collect()
}

fn ns_at(r: &Result<dns::Answer, String>, owner: &str) -> Vec<String> {
    r.as_ref()
        .map(|a| a.values_at(owner).iter().map(|v| host_of(v)).collect())
        .unwrap_or_default()
}

pub async fn where_(a: &Args, t: &Target) -> CheckResult {
    let name = need_domain(t, "where")?;
    // Ok(...) is evidence (including "no address"); Err(...) means a lookup failed.
    let infrastructure = async {
        let (v4, v6) = tokio::join!(
            lookup(a, name, "A", a.resolver, true),
            lookup(a, name, "AAAA", a.resolver, true)
        );
        let (v4, v6) = (v4?, v6?);
        let ips: Vec<IpAddr> = v4.addresses()?.into_iter().chain(v6.addresses()?).collect();
        let Some(ip) = ips.iter().find(|ip| ip.is_ipv4()).or(ips.first()).copied() else {
            return Ok(
                json!({"status": "not_found", "detail": format!("{name} has no A or AAAA record")}),
            );
        };
        if special_reason(ip).is_some() {
            return Ok(
                json!({"status": "not_found", "ip": ip, "detail": format!("{ip} is not a public address")}),
            );
        }
        crate::permit(ip, a)?;
        let net = rdap::ip(a, ip).await?;
        let Some(provider) = net["holder"].as_str().or(net["name"].as_str()) else {
            return Ok(
                json!({"status": "not_found", "ip": ip, "detail": "network registration did not publish a holder or name"}),
            );
        };
        Ok::<_, String>(
            json!({"status": "found", "provider": provider, "ip": ip, "source": net["source"], "basis": "network-registration"}),
        )
    };
    let (mut ns, registration, infrastructure) = tokio::join!(
        lookup(a, name, "NS", a.resolver, true),
        rdap::domain(a, name),
        infrastructure
    );
    let mut zone = name.to_string();
    let mut nameservers = ns_at(&ns, &zone);
    let no_ns_here = ns
        .as_ref()
        .is_ok_and(|r| r.kind() != "answered" || !r.chain().is_empty() || nameservers.is_empty());
    if nameservers.is_empty() && no_ns_here {
        if let Ok(reg) = &registration {
            if let Some(domain) = reg["domain"].as_str().filter(|d| *d != name) {
                zone = domain.to_string();
                ns = lookup(a, &zone, "NS", a.resolver, true).await;
                nameservers = ns_at(&ns, &zone);
            }
        }
    }
    let dns = if !nameservers.is_empty() {
        json!({"status": "found", "zone": zone, "providers": dns_hosting_providers(&nameservers), "nameservers": nameservers})
    } else {
        let detail = match &ns {
            Err(e) => format!("NS lookup failed: {e}"),
            Ok(_) if registration.as_ref().is_err_and(|e| !rdap::is_not_found(e)) => {
                "could not identify the authoritative parent zone because registration lookup is unavailable".into()
            }
            Ok(_) => "no authoritative nameservers returned".into(),
        };
        let registration_ok = registration
            .as_ref()
            .err()
            .is_none_or(|e| rdap::is_not_found(e));
        json!({"status": if ns.is_ok() && registration_ok { "not_found" } else { "unavailable" }, "zone": zone, "providers": [], "nameservers": [], "detail": detail})
    };
    let mut problems: Vec<String> = vec![];
    if let Err(e) = &ns {
        problems.push(format!("NS lookup failed: {e}"));
    }
    if let Err(e) = &registration {
        if !rdap::is_not_found(e) {
            problems.push(format!("registration lookup failed: {e}"));
        }
    }
    let registration = match &registration {
        Ok(r) => json!({
            "status": if r["registrar"].is_string() { "found" } else { "not_found" },
            "registrar": r["registrar"].as_str().unwrap_or("not published by registry"),
            "registered_domain": r["domain"],
            "registrant_country": r["registrant_country"],
            "source": r["source"],
        }),
        Err(e) if rdap::is_not_found(e) => {
            json!({"status": "not_found", "registrar": "no registration record found", "detail": e})
        }
        Err(e) => {
            json!({"status": "unavailable", "registrar": "registration lookup unavailable", "detail": e})
        }
    };
    let infrastructure = infrastructure.unwrap_or_else(|e| {
        problems.push(format!("infrastructure lookup failed: {e}"));
        json!({"status": "unavailable", "detail": e})
    });
    let data = json!({"domain": name, "dns": dns, "registration": registration, "infrastructure": infrastructure});
    if problems.is_empty() {
        Ok(data)
    } else {
        Err(CheckFailure {
            error: problems.join("; "),
            data,
        })
    }
}

// ── dns ────────────────────────────────────────────────────────────────────

pub const DNS_TYPES: &[&str] = &[
    "A", "AAAA", "CNAME", "NS", "SOA", "MX", "TXT", "CAA", "HTTPS", "SVCB", "DS", "DNSKEY",
    "SSHFP", "NAPTR",
];

pub async fn dns(a: &Args, t: &Target) -> CheckResult {
    let name = need_domain(t, "dns")?;
    let explicit = !a.types.is_empty();
    let mut queries: Vec<(String, String)> = if explicit {
        a.types
            .iter()
            .map(|ty| (name.to_string(), ty.clone()))
            .collect()
    } else {
        DNS_TYPES
            .iter()
            .map(|ty| (name.to_string(), ty.to_string()))
            .collect()
    };
    if !explicit {
        queries.push((format!("_submission._tcp.{name}"), "SRV".into()));
        queries.push((format!("_443._tcp.{name}"), "TLSA".into()));
    }
    // Every query is issued at once; `lookup` holds each to the per-check
    // concurrency limit, so a slow early answer never stalls later ones.
    let results: Vec<_> = join_all(
        queries
            .iter()
            .map(|(owner, ty)| lookup(a, owner, ty, a.resolver, true)),
    )
    .await;
    let mut errors = vec![];
    let rows: Vec<Value> = results
        .iter()
        .zip(&queries)
        .map(|(r, (owner, ty))| match r {
            Ok(answer) => {
                let mut v = serde_json::to_value(answer).unwrap_or_default();
                v["kind"] = json!(answer.kind());
                v["chain"] = json!(answer.chain());
                v
            }
            Err(e) => {
                errors.push(format!("{ty}: {e}"));
                json!({"name": owner, "rr_type": ty, "status": "ERROR", "kind": "error", "error": e, "records": []})
            }
        })
        .collect();
    let nxdomain = results.iter().all(|r| kind_of(r) == "nxdomain");
    let data = json!({
        "resolver": a.resolver.to_string(),
        "name": name,
        "nxdomain": nxdomain,
        "dnssec_validated": results.iter().any(|r| r.as_ref().is_ok_and(|a| a.authenticated)),
        "coverage": if explicit {
            format!("selected {} lookup{} at this owner; not a complete zone inventory.", a.types.join(", "), if a.types.len() == 1 { "" } else { "s" })
        } else {
            "explicit owner/type lookups; not a complete zone inventory. CAA shown at this name only.".into()
        },
        "queries": rows,
    });
    if errors.is_empty() {
        Ok(data)
    } else {
        Err(CheckFailure {
            error: errors.join("; "),
            data,
        })
    }
}

// ── email ──────────────────────────────────────────────────────────────────

pub const COMMON_SELECTORS: &[&str] = &[
    "google",
    "selector1",
    "selector2",
    "default",
    "k1",
    "k2",
    "s1",
    "s2",
    "dkim",
    "mail",
];

fn finding(name: &str, kind: &str, value: impl Into<String>, note: impl Into<String>) -> Value {
    json!({"name": name, "kind": kind, "value": value.into(), "note": note.into()})
}

fn dmarc_tag(rec: &str, key: &str) -> Option<String> {
    rec.split(';').find_map(|part| {
        let (k, v) = part.split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case(key)
            .then(|| v.trim().to_string())
    })
}

/// ASCII case-insensitive prefix test that is safe for any UTF-8 input.
fn starts_ci(s: &str, prefix: &str) -> bool {
    s.as_bytes()
        .get(..prefix.len())
        .is_some_and(|b| b.eq_ignore_ascii_case(prefix.as_bytes()))
}

/// True when a tag-value record (DMARC, MTA-STS, TLS-RPT, BIMI, DKIM) starts
/// with exactly `v=<version>`, so `v=DMARC10` is not a DMARC1 record.
fn has_version(rec: &str, version: &str) -> bool {
    rec.split(';')
        .next()
        .and_then(|t| t.split_once('='))
        .is_some_and(|(k, v)| {
            k.trim().eq_ignore_ascii_case("v") && v.trim().eq_ignore_ascii_case(version)
        })
}

/// Tag-value list (RFC 6376 §3.2). None when a tag is malformed or repeated.
fn tag_list(rec: &str) -> Option<Vec<(String, String)>> {
    let mut out: Vec<(String, String)> = vec![];
    for part in rec.split(';').filter(|p| !p.trim().is_empty()) {
        let (k, v) = part.split_once('=')?;
        let k = k.trim().to_ascii_lowercase();
        let valid = !k.is_empty() && k.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_');
        if !valid || out.iter().any(|(n, _)| *n == k) {
            return None;
        }
        out.push((k, v.trim().to_string()));
    }
    Some(out)
}

fn is_base64(s: &str) -> bool {
    let body = s.trim_end_matches('=');
    !body.is_empty()
        && s.len().is_multiple_of(4)
        && s.len() - body.len() <= 2
        && body
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DkimKey {
    Malformed(&'static str),
    Revoked,
    Published,
}

/// Classifies one TXT value at `<selector>._domainkey`. None means it is not a
/// DKIM key record at all. This checks structure only, never signatures.
pub fn dkim_key(rec: &str) -> Option<DkimKey> {
    let lower = rec.to_ascii_lowercase();
    let Some(tags) = tag_list(rec) else {
        let looks_dkim = has_version(rec, "DKIM1") || lower.contains("p=");
        return looks_dkim.then_some(DkimKey::Malformed("malformed or repeated tags"));
    };
    let get = |k: &str| tags.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    let dkim1 = get("v").is_some_and(|v| v.eq_ignore_ascii_case("DKIM1"));
    match tags.iter().position(|(n, _)| n == "v") {
        Some(0) if dkim1 => {}
        // Some other record type (e.g. SPF) that happens to sit at the selector.
        _ if !dkim1 && get("p").is_none() => return None,
        Some(_) => return Some(DkimKey::Malformed("v= must be first and exactly DKIM1")),
        None => {}
    }
    let Some(p) = get("p") else {
        return Some(DkimKey::Malformed("no p= public key tag"));
    };
    let key: String = p.split_whitespace().collect();
    Some(if key.is_empty() {
        DkimKey::Revoked
    } else if is_base64(&key) {
        DkimKey::Published
    } else {
        DkimKey::Malformed("p= is not valid base64")
    })
}

pub async fn email(a: &Args, t: &Target) -> CheckResult {
    let d = need_domain(t, "email")?;
    let selectors: Vec<String> = if a.selectors.is_empty() {
        COMMON_SELECTORS.iter().map(|s| s.to_string()).collect()
    } else {
        a.selectors.clone()
    };
    let mut q = vec![
        (d.to_string(), "MX"),
        (d.to_string(), "TXT"),
        (format!("_mta-sts.{d}"), "TXT"),
        (format!("_smtp._tls.{d}"), "TXT"),
        (format!("default._bimi.{d}"), "TXT"),
        (format!("_dmarc.{d}"), "TXT"),
    ];
    for s in &selectors {
        q.push((format!("{s}._domainkey.{d}"), "TXT"));
    }
    let r: Vec<_> = join_all(q.iter().map(|(n, ty)| lookup(a, n, ty, a.resolver, true))).await;
    let (mx, spf, mta_sts, tls_rpt, bimi, dmarc) = (&r[0], &r[1], &r[2], &r[3], &r[4], &r[5]);
    let dkims: Vec<(&String, &Result<dns::Answer, String>)> =
        selectors.iter().zip(&r[6..]).collect();
    let mut out = vec![];
    if kind_of(mx) == "nxdomain" && kind_of(spf) == "nxdomain" {
        // NXDOMAIN is a result (README scripting contract), not a lookup failure.
        return Ok(
            json!({"domain": d, "dkim_selectors": selectors, "nxdomain": true, "mx": [],
            "findings": [finding("DNS", "fail", format!("{d} does not exist (NXDOMAIN)"), "no mail records can exist for a name that is not in DNS")],
            "scope": "DNS policy evidence; no delivery or signature validation"}),
        );
    }

    // MX
    let mut mx_rows: Vec<(u16, String)> = values(mx)
        .iter()
        .filter_map(|v| {
            let (pref, host) = v.split_once(' ')?;
            Some((pref.parse().ok()?, host_of(host)))
        })
        .collect();
    mx_rows.sort();
    let mut mx_hosts = vec![];
    let mut errors: Vec<String> = vec![];
    if let Err(e) = mx {
        out.push(finding("MX", "error", "lookup failed", e.clone()));
    } else if mx_rows.len() == 1 && mx_rows[0].1.is_empty() && mx_rows[0].0 == 0 {
        out.push(finding(
            "MX",
            "info",
            "0 .",
            "null MX: this domain says it accepts no mail (RFC 7505)",
        ));
    } else if mx_rows.is_empty() {
        out.push(finding(
            "MX",
            "warn",
            "no MX records",
            "mail falls back to the A record, or bounces",
        ));
    } else {
        let resolved = join_all(mx_rows.iter().take(4).map(|(pref, host)| async move {
            let (a4, a6) = tokio::join!(
                lookup(a, host, "A", a.resolver, true),
                lookup(a, host, "AAAA", a.resolver, true)
            );
            let failed: Vec<String> = [&a4, &a6]
                .into_iter()
                .filter_map(|r| r.as_ref().err().cloned())
                .collect();
            let ips: Vec<String> = values(&a4).into_iter().chain(values(&a6)).collect();
            json!({"pref": pref, "host": host, "ips": ips, "error": failed.first()})
        }))
        .await;
        mx_hosts = resolved;
        let unresolved: Vec<&str> = mx_hosts
            .iter()
            .filter(|m| m["error"].is_string())
            .filter_map(|m| m["host"].as_str())
            .collect();
        let dangling: Vec<&str> = mx_hosts
            .iter()
            .filter(|m| m["error"].is_null())
            .filter(|m| m["ips"].as_array().is_some_and(|i| i.is_empty()))
            .filter_map(|m| m["host"].as_str())
            .collect();
        if !unresolved.is_empty() {
            errors.push(format!(
                "MX host address lookup failed for {}",
                unresolved.join(", ")
            ));
        }
        let n = mx_rows.len();
        out.push(finding(
            "MX",
            if !unresolved.is_empty() {
                "error"
            } else if dangling.is_empty() {
                "pass"
            } else {
                "warn"
            },
            mx_rows
                .iter()
                .map(|(p, h)| format!("{p} {h}"))
                .collect::<Vec<_>>()
                .join("  "),
            if !unresolved.is_empty() {
                format!("address lookup failed for {}", unresolved.join(", "))
            } else if dangling.is_empty() {
                format!(
                    "{n} host{} · all resolve{}",
                    if n > 1 { "s" } else { "" },
                    if n > 4 { " (first 4 checked)" } else { "" }
                )
            } else {
                format!("{} has no address", dangling.join(", "))
            },
        ));
    }

    // SPF
    let spf_recs: Vec<String> = values(spf)
        .into_iter()
        .filter(|v| {
            starts_ci(v, "v=spf1")
                && v.get(6..)
                    .is_some_and(|r| r.chars().next().is_none_or(char::is_whitespace))
        })
        .collect();
    if failed(spf) {
        out.push(finding(
            "SPF",
            "error",
            "lookup failed",
            "TXT lookup failed",
        ));
    } else if spf_recs.is_empty() {
        out.push(finding(
            "SPF",
            "warn",
            "no SPF record",
            "receivers cannot tell which servers may send for this domain",
        ));
    } else if spf_recs.len() > 1 {
        out.push(finding(
            "SPF",
            "fail",
            spf_recs.join(" | "),
            format!(
                "{} SPF records; there must be exactly one (permerror)",
                spf_recs.len()
            ),
        ));
    } else {
        let rec = &spf_recs[0];
        let lower = rec.to_ascii_lowercase();
        let all = lower.split_whitespace().find_map(|term| {
            let q = term.chars().next()?;
            if term == "all" {
                Some('+')
            } else if "+-~?".contains(q) && &term[1..] == "all" {
                Some(q)
            } else {
                None
            }
        });
        let mut kind = "info";
        let mut notes = vec!["direct record lint only; recursive lookup budget and sender authorization not evaluated"];
        match all {
            Some('+') => {
                kind = "fail";
                notes.push("+all lets anyone send as you");
            }
            Some('?') => {
                kind = "warn";
                notes.push("?all is neutral");
            }
            Some('~') => notes.push("~all soft-fail"),
            Some('-') => notes.push("-all hard-fail"),
            _ if !lower.contains("redirect=") => {
                kind = "warn";
                notes.push("no all mechanism");
            }
            _ => {}
        }
        if lower.split_whitespace().any(|t| {
            t.trim_start_matches(['+', '-', '~', '?']) == "ptr"
                || t.trim_start_matches(['+', '-', '~', '?'])
                    .starts_with("ptr:")
        }) {
            kind = "warn";
            notes.push("ptr is discouraged");
        }
        out.push(finding("SPF", kind, rec.clone(), notes.join(" · ")));
    }

    // DMARC: exact record lint, not RFC 9989 tree-walk policy.
    let dmarc_recs: Vec<String> = values(dmarc)
        .into_iter()
        .filter(|v| has_version(v, "DMARC1"))
        .collect();
    if failed(dmarc) {
        out.push(finding("DMARC", "error", "lookup failed", ""));
    } else if dmarc_recs.len() > 1 {
        out.push(finding(
            "DMARC",
            "fail",
            "multiple direct DMARC records",
            "ambiguous record set",
        ));
    } else if dmarc_recs.is_empty() {
        out.push(finding(
            "DMARC",
            "warn",
            "no direct DMARC record",
            format!("nothing at _dmarc.{d}; inherited RFC 9989 policy not evaluated"),
        ));
    } else {
        let rec = &dmarc_recs[0];
        let p = dmarc_tag(rec, "p").unwrap_or_default().to_ascii_lowercase();
        let mut notes = vec![
            format!(
                "direct record: policy {}",
                if p.is_empty() { "missing" } else { &p }
            ),
            "effective policy/alignment not evaluated (RFC 9989)".into(),
        ];
        notes.push(if dmarc_tag(rec, "rua").is_some() {
            "aggregate reports on".into()
        } else {
            "no rua: you get no reports".into()
        });
        let kind = match p.as_str() {
            "none" => "warn",
            "quarantine" | "reject" => "info",
            _ => "fail",
        };
        out.push(finding("DMARC", kind, rec.clone(), notes.join(" · ")));
    }

    // DKIM: key record structure only; signatures are never validated here.
    let classified: Vec<(&str, Option<DkimKey>)> = dkims
        .iter()
        .map(|(sel, r)| {
            (
                sel.as_str(),
                values(r).iter().filter_map(|v| dkim_key(v)).max(),
            )
        })
        .collect();
    let with = |want: fn(&DkimKey) -> bool| -> Vec<&str> {
        classified
            .iter()
            .filter(|(_, k)| k.as_ref().is_some_and(want))
            .map(|(s, _)| *s)
            .collect()
    };
    let published = with(|k| *k == DkimKey::Published);
    let revoked = with(|k| *k == DkimKey::Revoked);
    let malformed: Vec<String> = classified
        .iter()
        .filter_map(|(s, k)| match k {
            Some(DkimKey::Malformed(why)) => Some(format!("{s} ({why})")),
            _ => None,
        })
        .collect();
    let dkim_errors: Vec<&str> = dkims
        .iter()
        .filter(|(_, r)| failed(r))
        .map(|(s, _)| s.as_str())
        .collect();
    let mut extra = vec![];
    if !revoked.is_empty() {
        extra.push(format!("revoked: {}", revoked.join(", ")));
    }
    if !malformed.is_empty() {
        extra.push(format!("malformed: {}", malformed.join(", ")));
    }
    if !dkim_errors.is_empty() {
        extra.push(format!("lookup failed: {}", dkim_errors.join(", ")));
        errors.push(format!("DKIM lookup failed for {}", dkim_errors.join(", ")));
    }
    let extra = extra.iter().map(|e| format!(" · {e}")).collect::<String>();
    if !published.is_empty() {
        out.push(finding(
            "DKIM",
            "pass",
            published.join(", "),
            format!(
                "key record published for {} selector{}{extra}",
                published.len(),
                if published.len() > 1 { "s" } else { "" },
            ),
        ));
    } else if !revoked.is_empty() || !malformed.is_empty() {
        let names: Vec<&str> = classified
            .iter()
            .filter(|(_, k)| k.is_some())
            .map(|(s, _)| *s)
            .collect();
        out.push(finding(
            "DKIM",
            "warn",
            names.join(", "),
            format!("no usable key{extra}"),
        ));
    } else if !dkim_errors.is_empty() {
        out.push(finding(
            "DKIM",
            "error",
            "lookup failed",
            format!("selector lookups failed: {}", dkim_errors.join(", ")),
        ));
    } else {
        out.push(finding(
            "DKIM",
            "info",
            format!("tried {}", selectors.join(", ")),
            "no key at these selectors; that is not proof DKIM is off. Use dkim:<selector>",
        ));
    }

    let sts = values(mta_sts)
        .into_iter()
        .find(|v| has_version(v, "STSv1"));
    out.push(match (failed(mta_sts), sts) {
        (true, _) => finding(
            "MTA-STS",
            "error",
            "lookup failed",
            "publication status unknown",
        ),
        (_, None) => finding(
            "MTA-STS",
            "none",
            "not published",
            "optional: enforces TLS for inbound mail",
        ),
        (_, Some(v)) => finding(
            "MTA-STS",
            "info",
            v,
            "DNS policy announcement found · HTTPS policy file not checked",
        ),
    });
    let rpt = values(tls_rpt)
        .into_iter()
        .find(|v| has_version(v, "TLSRPTv1"));
    out.push(match (failed(tls_rpt), rpt) {
        (true, _) => finding(
            "TLS-RPT",
            "error",
            "lookup failed",
            "publication status unknown",
        ),
        (_, None) => finding(
            "TLS-RPT",
            "none",
            "not published",
            "optional: reports TLS delivery failures",
        ),
        (_, Some(v)) => finding("TLS-RPT", "pass", v, "TLS failure reports on"),
    });
    let b = values(bimi).into_iter().find(|v| has_version(v, "BIMI1"));
    out.push(match (failed(bimi), b) {
        (true, _) => finding(
            "BIMI",
            "error",
            "lookup failed",
            "publication status unknown",
        ),
        (_, None) => finding(
            "BIMI",
            "none",
            "not published",
            "optional: brand logo in inboxes",
        ),
        (_, Some(v)) => finding("BIMI", "pass", v, "brand logo published"),
    });

    for f in out.iter().filter(|f| f["kind"] == "error") {
        let name = f["name"].as_str().unwrap_or_default();
        if !errors.iter().any(|e| e.starts_with(name)) {
            errors.push(format!("{name} lookup failed"));
        }
    }
    let data = json!({"domain": d, "dkim_selectors": selectors, "findings": out, "mx": mx_hosts,
        "scope": "DNS policy evidence; no delivery or signature validation"});
    if errors.is_empty() {
        Ok(data)
    } else {
        Err(CheckFailure {
            error: errors.join("; "),
            data,
        })
    }
}

// ── blacklist ──────────────────────────────────────────────────────────────

pub const DNSBLS: &[(&str, &str)] = &[
    ("SpamCop", "bl.spamcop.net"),
    ("Barracuda", "b.barracudacentral.org"),
    ("PSBL", "psbl.surriel.com"),
    ("Mailspike", "bl.mailspike.net"),
    ("UCEPROTECT L1", "dnsbl-1.uceprotect.net"),
    ("UCEPROTECT L2", "dnsbl-2.uceprotect.net"),
    ("UCEPROTECT L3", "dnsbl-3.uceprotect.net"),
    ("DroneBL", "dnsbl.dronebl.org"),
    ("0spam", "bl.0spam.org"),
    ("s5h", "all.s5h.net"),
    ("JustSpam", "dnsbl.justspam.org"),
    ("SpamRATS", "all.spamrats.com"),
    ("Backscatterer", "ips.backscatterer.org"),
    ("GBUdb Truncate", "truncate.gbudb.net"),
];

pub async fn blacklist(a: &Args, t: &Target) -> CheckResult {
    let mut ips: Vec<(IpAddr, String)> = vec![];
    if let Some(ip) = t.ip {
        if let Some(why) = special_reason(ip) {
            return Err(format!("{ip} is {why}: public blocklists skipped").into());
        }
        ips.push((ip, ip.to_string()));
    } else {
        let mx = lookup(a, &t.host, "MX", a.resolver, true).await;
        let mx = mx.map_err(|e| format!("MX lookup failed: {e}"))?;
        let rows: Vec<(u16, String)> = mx
            .values()
            .iter()
            .filter_map(|v| {
                let (pref, host) = v.split_once(' ')?;
                Some((pref.parse().ok()?, host_of(host)))
            })
            .collect();
        if rows.len() == 1 && rows[0] == (0, String::new()) {
            // RFC 7505 null MX: there is no mail server to look up.
            return Ok(json!({
                "targets": [], "listed": 0, "answered": 0, "total": 0, "rows": [],
                "not_applicable": format!("{} publishes a null MX (accepts no mail); check an IP address directly instead", t.host),
            }));
        }
        let mut sorted = rows;
        sorted.sort();
        let mut hosts: Vec<String> = sorted
            .into_iter()
            .map(|(_, h)| h)
            .filter(|h| !h.is_empty())
            .collect();
        hosts.dedup();
        hosts.truncate(2);
        // No MX at all: mail is delivered to the domain's own address (RFC 5321 §5.1).
        if hosts.is_empty() {
            hosts.push(t.host.clone());
        }
        for h in hosts {
            let r = lookup(a, &h, "A", a.resolver, true)
                .await
                .map_err(|e| format!("address lookup for {h} failed: {e}"))?;
            if let Some(ip) = r
                .addresses()
                .ok()
                .and_then(|v| v.into_iter().find(|ip| special_reason(*ip).is_none()))
            {
                ips.push((ip, format!("{h} → {ip}")));
            }
        }
        if ips.is_empty() {
            return Err(format!("no public IPv4 found for {} or its mail servers", t.host).into());
        }
    }
    let v4: Vec<_> = ips.into_iter().filter(|(ip, _)| ip.is_ipv4()).collect();
    if v4.is_empty() {
        return Err("blocklists here are IPv4-only; this address is IPv6".into());
    }
    let queries: Vec<(IpAddr, &str, &str)> = v4
        .iter()
        .flat_map(|(ip, _)| DNSBLS.iter().map(move |(n, z)| (*ip, *n, *z)))
        .collect();
    let targets: Vec<&String> = v4.iter().map(|(_, l)| l).collect();
    let total = queries.len();
    let order: Vec<(IpAddr, &str)> = queries.iter().map(|(ip, n, _)| (*ip, *n)).collect();
    let mut s: FuturesUnordered<_> = queries
        .into_iter()
        .map(|(ip, name, zone)| async move {
            let owner = format!("{}.{zone}", reversed_labels(ip));
            let r = lookup(a, &owner, "A", a.resolver, true).await;
            let (kind, detail) = match &r {
                Ok(ans) if ans.kind() != "answered" => ("clean", String::new()),
                Ok(ans) => {
                    let codes = ans.values();
                    if codes
                        .iter()
                        .any(|c| c.starts_with("127.255.255.") || c == "127.0.0.1")
                    {
                        ("error", format!("list refused the query ({})", codes[0]))
                    } else if !codes.is_empty() && codes.iter().all(|c| c.starts_with("127.")) {
                        let reason = lookup(a, &owner, "TXT", a.resolver, true).await;
                        let text = values(&reason)
                            .into_iter()
                            .next()
                            .map(|s| s.chars().take(200).collect());
                        ("listed", text.unwrap_or_else(|| codes.join(", ")))
                    } else {
                        (
                            "error",
                            "unexpected list response; listing status unavailable".into(),
                        )
                    }
                }
                Err(e) if e.contains("timeout") => ("timeout", e.clone()),
                Err(e) => ("error", e.clone()),
            };
            json!({"ip": ip, "name": name, "zone": zone, "kind": kind, "detail": detail})
        })
        .collect();
    let mut done: Vec<Value> = vec![];
    let ordered = |done: &[Value], fill: bool| -> Vec<Value> {
        order
            .iter()
            .filter_map(|(ip, n)| {
                done.iter()
                    .find(|r| r["ip"] == ip.to_string() && r["name"] == *n)
                    .cloned()
                    .or_else(|| fill.then(|| json!({"ip": ip, "name": n, "kind": "pending"})))
            })
            .collect()
    };
    while let Some(row) = s.next().await {
        done.push(row);
        let listed = done.iter().filter(|r| r["kind"] == "listed").count();
        let answered = done
            .iter()
            .filter(|r| r["kind"] == "listed" || r["kind"] == "clean")
            .count();
        publish(
            Group::Blacklist,
            json!({"targets": targets, "listed": listed, "answered": answered, "total": total, "rows": ordered(&done, true)}),
        );
    }
    let rows = ordered(&done, false);
    let count = |k: &[&str]| {
        rows.iter()
            .filter(|r| k.iter().any(|k| r["kind"] == *k))
            .count()
    };
    let unanswered = count(&["error", "timeout"]);
    let data = json!({
        "targets": targets,
        "listed": count(&["listed"]),
        "answered": count(&["listed", "clean"]),
        "total": rows.len(),
        "rows": rows,
        "skipped": ["Spamhaus (requires a key; public resolvers are refused)"],
    });
    if unanswered > 0 {
        return Err(CheckFailure {
            error: format!(
                "{unanswered} of {} blocklist lookups failed; listing status for those lists is unknown",
                data["total"]
            ),
            data,
        });
    }
    Ok(data)
}

// ── whois ──────────────────────────────────────────────────────────────────

pub async fn whois(a: &Args, t: &Target) -> CheckResult {
    if let Some(ip) = t.ip {
        if let Some(why) = special_reason(ip) {
            return Err(format!("{ip} is {why}; public registration lookup skipped").into());
        }
        return Ok(rdap::ip(a, ip).await?);
    }
    Ok(rdap::domain(a, &t.host).await?)
}

// ── ip ─────────────────────────────────────────────────────────────────────

fn cymru(v: &str) -> Vec<String> {
    v.split('|').map(|s| s.trim().to_string()).collect()
}

pub async fn ip(a: &Args, t: &Target) -> CheckResult {
    let (ip, from) = primary_ip(a, t).await?;
    let rev = dns::reverse(ip);
    let special = special_reason(ip);
    let ptr = lookup(a, &rev, "PTR", a.resolver, true).await;
    let ptr = match ptr {
        Ok(p) => p,
        Err(e) => {
            return Err(CheckFailure {
                error: format!("PTR lookup failed: {e}"),
                data: json!({"ip": ip, "from": from, "public": special.is_none(), "rows": [{"k": "ptr", "v": format!("lookup failed: {e}"), "kind": "error"}]}),
            })
        }
    };
    let ptrs: Vec<String> = ptr.values().iter().map(|v| host_of(v)).take(5).collect();
    let mut rows = vec![
        json!({"k": "class", "v": match special { Some(why) => why.to_string(), None => format!("public IPv{}", if ip.is_ipv4() { 4 } else { 6 }) }, "kind": "info"}),
    ];
    if ptrs.is_empty() {
        rows.push(json!({"k": "ptr", "v": "no reverse DNS", "kind": "warn"}));
    }
    let mut confirmed_any = false;
    let mut errors: Vec<String> = vec![];
    let family = if ip.is_ipv4() { "A" } else { "AAAA" };
    let forwards = join_all(
        ptrs.iter()
            .take(3)
            .map(|h| lookup(a, h, family, a.resolver, true)),
    )
    .await;
    for (h, fwd) in ptrs.iter().zip(forwards) {
        let confirmed = fwd
            .as_ref()
            .ok()
            .and_then(|r| r.addresses().ok())
            .is_some_and(|v| v.contains(&ip));
        confirmed_any |= confirmed;
        let note = match &fwd {
            _ if confirmed => "forward-confirmed".to_string(),
            Err(e) => {
                errors.push(format!("forward lookup for {h} failed: {e}"));
                format!("forward lookup failed: {e}")
            }
            Ok(_) => "does not resolve back to this IP".to_string(),
        };
        rows.push(json!({"k": "ptr", "v": h, "kind": if confirmed { "pass" } else if fwd.is_err() { "error" } else { "warn" },
            "note": note}));
    }
    if special.is_none() {
        let zone = if ip.is_ipv4() {
            "origin.asn.cymru.com"
        } else {
            "origin6.asn.cymru.com"
        };
        let origin_name = format!("{}.{zone}", reversed_labels(ip));
        let (origin, rir) = tokio::join!(
            lookup(a, &origin_name, "TXT", a.resolver, true),
            rdap::ip(a, ip)
        );
        if let Err(e) = &origin {
            errors.push(format!("ASN lookup failed: {e}"));
        }
        match values(&origin).first().map(|v| cymru(v)) {
            Some(f) if f.len() >= 4 && f[0].split(' ').next().is_some_and(|n| n.parse::<u32>().is_ok()) => {
                let asn = f[0].split(' ').next().unwrap_or_default().to_string();
                let name = lookup(a, &format!("AS{asn}.asn.cymru.com"), "TXT", a.resolver, true).await;
                if let Err(e) = &name {
                    errors.push(format!("AS name lookup failed: {e}"));
                }
                let as_name = values(&name).first().and_then(|v| cymru(v).get(4).cloned()).unwrap_or_default();
                rows.push(json!({"k": "asn", "v": if as_name.is_empty() { format!("AS{asn}") } else { format!("AS{asn} · {as_name}") }, "kind": "info"}));
                rows.push(json!({"k": "bgp prefix", "v": format!("{} · {} · {}", f[1], f[2], f[3]), "kind": "info"}));
            }
            _ => rows.push(json!({"k": "asn", "v": "ASN information unavailable from Team Cymru", "kind": if origin.is_err() { "error" } else { "info" }})),
        }
        match rir {
            Ok(r) => {
                let net = [
                    r["name"].as_str(),
                    r["cidrs"][0].as_str().or(r["range"].as_str()),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" · ");
                rows.push(json!({"k": "network", "v": net, "kind": "info"}));
                if let Some(h) = r["holder"].as_str() {
                    let cc = r["country"]
                        .as_str()
                        .map(|c| format!(" · {c}"))
                        .unwrap_or_default();
                    rows.push(json!({"k": "holder", "v": format!("{h}{cc}"), "kind": "info"}));
                }
                if let Some(abuse) = r["abuse"].as_str() {
                    rows.push(json!({"k": "abuse", "v": abuse, "kind": "info"}));
                }
            }
            Err(e) => {
                errors.push(format!("network registration unavailable: {e}"));
                rows.push(json!({"k": "network", "v": e, "kind": "error"}))
            }
        }
    }
    let data = json!({"ip": ip, "from": from, "public": special.is_none(), "rows": rows, "ptr_confirmed": confirmed_any});
    if errors.is_empty() {
        Ok(data)
    } else {
        Err(CheckFailure {
            error: errors.join("; "),
            data,
        })
    }
}

// ── web ────────────────────────────────────────────────────────────────────

const MAX_REDIRECTS: usize = 5;

/// Statuses that carry a Location to follow (RFC 9110 §15.4). 300 and 304 do not.
fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn permitted_redirect(u: &reqwest::Url) -> bool {
    ["http", "https"].contains(&u.scheme()) && u.username().is_empty() && u.password().is_none()
}

pub async fn web(a: &Args, t: &Target) -> CheckResult {
    let start = t.url.clone();
    let mut url = start.clone();
    let mut hops: Vec<Value> = vec![];
    let mut error = None;
    let mut seen = vec![];
    // The first request plus up to MAX_REDIRECTS followed redirects.
    for i in 0..=MAX_REDIRECTS + 1 {
        if i > MAX_REDIRECTS {
            error = Some(format!("more than {MAX_REDIRECTS} redirects"));
            break;
        }
        seen.push(url.to_string());
        match web::hop(a, &url).await {
            Err(e) => {
                error = Some(e);
                break;
            }
            Ok(h) => {
                hops.push(h.value);
                if is_redirect(h.status) {
                    let Some(loc) = h.location else {
                        error = Some("redirect without location".into());
                        break;
                    };
                    match url.join(&loc) {
                        Ok(next) if permitted_redirect(&next) => {
                            if seen.contains(&next.to_string()) {
                                error = Some("redirect loop".into());
                                break;
                            }
                            url = next;
                        }
                        _ => {
                            error = Some("redirect target is not permitted".into());
                            break;
                        }
                    }
                    continue;
                }
                if !(200..400).contains(&h.status) {
                    error = Some(format!("HTTP status {}", h.status));
                }
                break;
            }
        }
    }
    // Does plain HTTP upgrade to HTTPS? Only when the user did not ask for http://.
    let mut http_upgrade = Value::Null;
    if start.scheme() == "https" && !t.explicit_http {
        let mut plain = start.clone();
        if plain.set_scheme("http").is_ok() && plain.set_port(None).is_ok() {
            plain.set_path("/");
            plain.set_query(None);
            if let Ok(h) = web::hop(a, &plain).await {
                http_upgrade = json!(
                    is_redirect(h.status)
                        && h.location
                            .and_then(|l| plain.join(&l).ok())
                            .is_some_and(|u| u.scheme() == "https")
                );
            }
        }
    }
    let sum = |key: &str| -> Value {
        let parts: Vec<f64> = hops
            .iter()
            .filter_map(|h| h["timings"][key].as_f64())
            .collect();
        if parts.len() == hops.len() && !parts.is_empty() {
            json!((parts.iter().sum::<f64>() * 10.0).round() / 10.0)
        } else {
            Value::Null
        }
    };
    let last = hops.last();
    let data = json!({
        "start": start.as_str(),
        "final": last.map(|h| json!({"status": h["status"], "url": h["url"]})),
        "total_ms": sum("total_ms"),
        "timings": {
            "requests": hops.len(),
            "dns_ms": sum("dns_ms"), "tcp_ms": sum("tcp_ms"), "tls_ms": sum("tls_ms"),
            "response_ms": sum("response_ms"), "total_ms": sum("total_ms"),
        },
        "http_upgrade": http_upgrade,
        "hsts": last.is_some_and(|h| h["hsts"] == true),
        "error": error,
        "hops": hops,
    });
    match error {
        None => Ok(data),
        Some(e) if data["hops"].as_array().is_some_and(|h| h.is_empty()) => Err(e.into()),
        Some(e) => Err(CheckFailure { error: e, data }),
    }
}

// ── ports ──────────────────────────────────────────────────────────────────

pub const PORTS: &[(u16, &str)] = &[
    (21, "ftp"),
    (22, "ssh"),
    (25, "smtp"),
    (80, "http"),
    (443, "https"),
    (465, "smtps"),
    (587, "submission"),
    (993, "imaps"),
    (995, "pop3s"),
    (3389, "rdp"),
];

fn service(port: u16) -> &'static str {
    PORTS
        .iter()
        .chain(&[
            (53, "dns"),
            (110, "pop3"),
            (143, "imap"),
            (8080, "http-alt"),
            (8443, "https-alt"),
        ])
        .find(|(p, _)| *p == port)
        .map_or("custom", |(_, s)| s)
}

pub async fn ports(a: &Args, t: &Target) -> CheckResult {
    let (ip, from) = primary_ip(a, t).await?;
    let selected: Vec<u16> = if a.ports.is_empty() {
        PORTS.iter().map(|(p, _)| *p).collect()
    } else {
        a.ports.clone()
    };
    let wait = Duration::from_secs(a.timeout.min(3));
    let placeholder =
        |port: u16| json!({"port": port, "svc": service(port), "kind": "pending", "ms": null});
    let all = selected.clone();
    let mut s: FuturesUnordered<_> = selected.into_iter().map(|port| async move {
        let (r, elapsed) = limited(async {
            let start = Instant::now();
            let r = tokio::time::timeout(wait, tokio::net::TcpStream::connect(SocketAddr::new(ip, port))).await;
            (r, util::ms(start.elapsed()))
        })
        .await;
        let (kind, ms, detail) = match r {
            Ok(Ok(_)) => ("open", Some(elapsed), ""),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => ("closed", None, "connection refused"),
            Ok(Err(_)) => ("error", None, "connection unavailable from this machine"),
            Err(_) => ("timeout", None, "no answer before timeout"),
        };
        json!({"port": port, "svc": service(port), "kind": kind, "ms": ms, "detail": detail, "open": kind == "open"})
    }).collect();
    let mut done: Vec<Value> = vec![];
    while let Some(row) = s.next().await {
        done.push(row);
        let partial: Vec<Value> = all
            .iter()
            .map(|p| {
                done.iter()
                    .find(|r| r["port"] == *p)
                    .cloned()
                    .unwrap_or_else(|| placeholder(*p))
            })
            .collect();
        publish(
            Group::Ports,
            json!({"ip": ip, "from": from, "rows": partial}),
        );
    }
    let rows: Vec<Value> = all
        .iter()
        .filter_map(|p| done.iter().find(|r| r["port"] == *p).cloned())
        .collect();
    Ok(json!({"ip": ip, "from": from, "rows": rows}))
}

// ── ping ───────────────────────────────────────────────────────────────────

pub fn ping_program(os: &str, ip: IpAddr) -> &'static str {
    if os == "macos" && ip.is_ipv6() {
        "ping6"
    } else {
        "ping"
    }
}

pub const PING_COUNT: u32 = 10;

/// Extracts per-sequence round-trip times from macOS, Linux or Windows ping output.
/// macOS numbers sequences from 0, Linux from 1, Windows not at all (reply order).
pub fn parse_ping(raw: &str, count: u32) -> Vec<Option<f64>> {
    let number_after = |s: &str, key: &str| -> Option<String> {
        let i = s.find(key)? + key.len();
        let v: String = s[i..]
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        (!v.is_empty()).then_some(v)
    };
    let mut replies: Vec<(Option<usize>, f64)> = vec![];
    for line in raw.lines().map(str::to_ascii_lowercase) {
        let Some(ms) = number_after(&line, "time=")
            .or_else(|| number_after(&line, "time<"))
            .and_then(|v| v.parse::<f64>().ok())
        else {
            continue;
        };
        let seq = number_after(&line, "icmp_seq=").and_then(|v| v.parse::<usize>().ok());
        replies.push((seq, ms));
    }
    let base = if raw.contains("icmp_seq=0 ")
        || raw.contains("icmp_seq 0\n")
        || raw.contains("icmp_seq 0 ")
    {
        0
    } else {
        1
    };
    let mut samples = vec![None; count as usize];
    for (order, (seq, ms)) in replies.into_iter().enumerate() {
        let slot = seq.map_or(order, |s| s.saturating_sub(base));
        if let Some(cell) = samples.get_mut(slot) {
            *cell = Some(ms);
        }
    }
    samples
}

pub async fn ping(a: &Args, t: &Target) -> CheckResult {
    let (ip, from) = primary_ip(a, t).await?;
    let os = std::env::consts::OS;
    let mut c = tokio::process::Command::new(ping_program(os, ip));
    let count = PING_COUNT.to_string();
    match os {
        "windows" => c.args(["-n", &count]),
        "macos" => c.args(["-c", &count, "-i", "0.2", "-t", "8"]),
        _ => c.args(["-c", &count, "-i", "0.2", "-w", "8"]),
    };
    c.arg(ip.to_string())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = c.spawn().map_err(|e| format!("could not run ping: {e}"))?;
    let mut stdout = child.stdout.take().ok_or("ping produced no output")?;
    let mut stderr = child.stderr.take().ok_or("ping produced no output")?;
    let live = |raw: &str| {
        // Replies stream into the panel as they arrive.
        let replies = parse_ping(raw, PING_COUNT);
        let seen = raw
            .lines()
            .filter(|l| {
                let l = l.to_ascii_lowercase();
                l.contains("time=")
                    || l.contains("time<")
                    || l.contains("timeout")
                    || l.contains("timed out")
                    || l.contains("unreachable")
            })
            .count()
            .min(PING_COUNT as usize);
        let seen = seen.max(
            replies
                .iter()
                .rposition(Option::is_some)
                .map_or(0, |i| i + 1),
        );
        publish(
            Group::Ping,
            json!({"ip": ip, "from": from, "sent": PING_COUNT, "live": true,
                   "samples": replies[..seen].iter().enumerate().map(|(i, ms)| json!({"seq": i + 1, "ms": ms})).collect::<Vec<_>>()}),
        );
    };
    live("");
    let read_all = async {
        use tokio::io::AsyncReadExt;
        let mut raw = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if raw.len() < 65536 {
                        raw.extend_from_slice(&buf[..n]);
                    }
                    live(&String::from_utf8_lossy(&raw));
                }
            }
        }
        let mut err = Vec::new();
        let _ = (&mut stderr).take(4096).read_to_end(&mut err).await;
        let status = child.wait().await;
        (raw, err, status)
    };
    let (out_raw, err_raw, status) =
        tokio::time::timeout(Duration::from_secs(a.timeout.max(12)), read_all)
            .await
            .map_err(|_| "ping timeout")?;
    let raw = String::from_utf8_lossy(&out_raw).into_owned();
    let samples = parse_ping(&raw, PING_COUNT);
    let received = samples.iter().filter(|s| s.is_some()).count();
    let data = json!({
        "ip": ip, "from": from, "method": "icmp", "sent": PING_COUNT, "received": received,
        "samples": samples.iter().enumerate().map(|(i, ms)| json!({"seq": i + 1, "ms": ms})).collect::<Vec<_>>(),
        "raw": raw,
        "exit_code": status.as_ref().ok().and_then(|s| s.code()),
    });
    let stderr = String::from_utf8_lossy(&err_raw);
    if received == 0 {
        return Err(CheckFailure {
            error: format!(
                "ping failed: no ICMP replies (many hosts drop ping; that is not \"down\"). {}{}",
                raw.trim(),
                stderr.trim()
            ),
            data,
        });
    }
    // Replies arrived, but ping itself reported failure (e.g. packet loss on
    // Linux, or an error after the first reply). The samples are kept.
    match status {
        Ok(s) if s.success() => Ok(data),
        Ok(s) => Err(CheckFailure {
            error: format!(
                "ping exited with {s} after {received}/{PING_COUNT} replies{}",
                if stderr.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", stderr.trim())
                }
            ),
            data,
        }),
        Err(e) => Err(CheckFailure {
            error: format!("could not read ping's exit status: {e}"),
            data,
        }),
    }
}

// ── propagation ────────────────────────────────────────────────────────────

/// What one server says about `host` A, in a form that compares like for like:
/// the rcode, a CNAME at the name itself (if any) and the A values at the name.
/// Authoritative servers do not chase out-of-zone aliases, so only the
/// name's own records are compared, never the resolver's chased chain.
fn a_evidence(ans: &dns::Answer, host: &str) -> Value {
    let mut cname = ans
        .records
        .iter()
        .filter(|r| r.rr_class == 1 && r.rr_type == "CNAME")
        .filter(|r| r.name.trim_end_matches('.').eq_ignore_ascii_case(host))
        .map(|r| host_of(&r.value));
    let mut answers = ans.values_at(host);
    answers.sort();
    json!({
        "outcome": if ans.outcome == dns::Outcome::NxDomain { "nxdomain" } else { "noerror" },
        "cname": cname.next(),
        "answers": answers,
    })
}

pub async fn propagation(a: &Args, t: &Target) -> CheckResult {
    let host = need_domain(t, "propagation")?
        .trim_end_matches('.')
        .to_string();
    let mut zone = host.as_str();
    let ns = loop {
        let r = lookup(a, zone, "NS", a.resolver, true).await?;
        let ns = ns_at(&Ok(r.clone()), zone);
        if r.outcome == dns::Outcome::NoError && !ns.is_empty() {
            break ns;
        }
        zone = zone.split_once('.').ok_or("no authoritative zone found")?.1;
    };
    let zone = zone.to_string();
    let rows: Vec<Value> = join_all(ns.iter().take(6).map(|server| {
        let (zone, host) = (zone.clone(), host.clone());
        async move {
            let ips = match addresses(a, server).await {
                Ok(ips) => ips,
                Err(e) => return json!({"server": server, "kind": "error", "answers": [], "detail": format!("nameserver address unavailable: {e}")}),
            };
            let ip = *ips.iter().find(|ip| ip.is_ipv4()).unwrap_or(&ips[0]);
            let sock = SocketAddr::new(ip, 53);
            let (soa, ans) = tokio::join!(
                lookup(a, &zone, "SOA", sock, false),
                lookup(a, &host, "A", sock, false)
            );
            match (soa, ans) {
                (Ok(soa), Ok(ans)) => {
                    let soa_rec = soa.values_at(&zone).into_iter().next();
                    let serial = soa_rec.as_ref().and_then(|v| v.split_whitespace().nth(2)?.parse::<u64>().ok());
                    let provider = soa_rec.as_ref().and_then(|v| v.split_whitespace().next()).map(host_of).unwrap_or_default();
                    let evidence = a_evidence(&ans, &host);
                    let authoritative = soa.authoritative && ans.authoritative;
                    let (kind, detail) = match serial {
                        None => ("error", "nameserver returned no SOA serial"),
                        Some(_) if !authoritative => ("warn", "answer is not authoritative (lame delegation?); not counted"),
                        Some(_) => ("pass", ""),
                    };
                    json!({"server": server, "ip": ip, "serial": serial, "provider": provider,
                        "answers": evidence["answers"], "cname": evidence["cname"], "outcome": evidence["outcome"],
                        "evidence": evidence, "aa": authoritative, "kind": kind, "detail": detail})
                }
                (Err(e), _) | (_, Err(e)) => json!({"server": server, "ip": ip, "kind": "error", "answers": [], "detail": if e.contains("timeout") { "nameserver query timed out".to_string() } else { e }}),
            }
        }
    }))
    .await;
    let recursive = lookup(a, &host, "A", a.resolver, true).await;
    propagation_report(&zone, &host, rows, &recursive, &a.resolver.to_string())
}

/// Compares the per-server rows with each other and with the recursive answer.
fn propagation_report(
    zone: &str,
    host: &str,
    mut rows: Vec<Value>,
    recursive: &Result<dns::Answer, String>,
    resolver: &str,
) -> CheckResult {
    // Only authoritative answers with a serial substantiate agreement.
    let ok: Vec<usize> = (0..rows.len())
        .filter(|i| rows[*i]["serial"].is_u64() && rows[*i]["aa"] == true)
        .collect();
    let mut by_provider: std::collections::BTreeMap<String, std::collections::BTreeSet<u64>> =
        Default::default();
    for &i in &ok {
        by_provider
            .entry(rows[i]["provider"].as_str().unwrap_or_default().to_string())
            .or_default()
            .insert(rows[i]["serial"].as_u64().unwrap_or_default());
    }
    let split: Vec<&String> = by_provider
        .iter()
        .filter(|(_, s)| s.len() > 1)
        .map(|(p, _)| p)
        .collect();
    let sets: std::collections::BTreeSet<String> = ok
        .iter()
        .map(|&i| rows[i]["evidence"].to_string())
        .collect();
    let serials_differ = !split.is_empty();
    let answers_differ = sets.len() > 1;
    for &i in &ok {
        let p = rows[i]["provider"].as_str().unwrap_or_default().to_string();
        if split.contains(&&p) || answers_differ {
            rows[i]["kind"] = json!("warn");
        }
    }
    for row in &mut rows {
        if let Some(o) = row.as_object_mut() {
            o.remove("evidence");
        }
    }
    let (rec_answers, matches) = match recursive {
        Ok(r) => {
            let evidence = a_evidence(r, host);
            let chased = {
                let mut v = r.values();
                v.sort();
                v
            };
            let matches = !ok.is_empty() && sets.len() == 1 && sets.contains(&evidence.to_string());
            (chased, json!(matches))
        }
        // Unknown, not "differs" and never "matches".
        Err(_) => (vec![], Value::Null),
    };
    let failed_servers: Vec<&str> = rows
        .iter()
        .filter(|r| r["kind"] == "error")
        .filter_map(|r| r["server"].as_str())
        .collect();
    let data = json!({
        "zone": zone, "name": host, "providers": by_provider.len(),
        "recursive": {"resolver": resolver, "answers": rec_answers, "matches": matches,
            "error": recursive.as_ref().err()},
        "agree": !ok.is_empty() && !serials_differ && !answers_differ,
        "serials_differ": serials_differ, "answers_differ": answers_differ, "checked": ok.len(),
        "servers": rows,
        "scope": "up to six authoritative servers; A answers and SOA evidence; non-authoritative answers are not counted",
    });
    let mut problems = vec![];
    if ok.is_empty() {
        problems.push("no nameserver gave an authoritative answer".to_string());
    }
    if !failed_servers.is_empty() {
        problems.push(format!(
            "no usable answer from {}",
            failed_servers.join(", ")
        ));
    }
    if let Err(e) = recursive {
        problems.push(format!("recursive lookup failed: {e}"));
    }
    if problems.is_empty() {
        Ok(data)
    } else {
        Err(CheckFailure {
            error: problems.join("; "),
            data,
        })
    }
}

fn unique(v: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    v.retain(|x| seen.insert(x.clone()));
}

// ── subdomains ─────────────────────────────────────────────────────────────

pub const COMMON_NAMES: &[&str] = &[
    "www",
    "mail",
    "smtp",
    "imap",
    "pop",
    "pop3",
    "webmail",
    "autodiscover",
    "autoconfig",
    "api",
    "app",
    "cdn",
    "static",
    "assets",
    "blog",
    "shop",
    "status",
    "dev",
    "staging",
    "test",
];

pub async fn subdomains(a: &Args, t: &Target) -> CheckResult {
    let base = need_domain(t, "subdomains")?;
    let controls: Vec<String> = (0..3)
        .map(|_| format!("wd-{:024x}", rand::random::<u128>() >> 32))
        .collect();
    let labels: Vec<String> = controls
        .iter()
        .cloned()
        .chain(COMMON_NAMES.iter().map(|s| s.to_string()))
        .collect();
    let queries: Vec<(String, &str)> = labels
        .iter()
        .flat_map(|l| ["A", "AAAA"].map(|ty| (l.clone(), ty)))
        .collect();
    let results: Vec<(String, Result<dns::Answer, String>)> =
        join_all(queries.into_iter().map(|(label, ty)| async move {
            let r = lookup(a, &format!("{label}.{base}"), ty, a.resolver, true).await;
            (label, r)
        }))
        .await;
    let signature = |label: &str| {
        let mut parts: Vec<String> = results
            .iter()
            .filter(|(l, _)| l == label)
            .filter_map(|(_, r)| r.as_ref().ok())
            .flat_map(|r| {
                r.values()
                    .into_iter()
                    .map(|v| format!("{}:{v}", r.rr_type))
                    .chain(r.chain().into_iter().map(|c| format!("CNAME:{c}")))
            })
            .collect();
        parts.sort();
        parts.join("|")
    };
    let wildcard: std::collections::HashSet<String> = controls
        .iter()
        .map(|c| signature(c))
        .filter(|s| !s.is_empty())
        .collect();
    let rows: Vec<Value> = COMMON_NAMES
        .iter()
        .map(|label| {
            let rs: Vec<_> = results
                .iter()
                .filter(|(l, _)| l == label)
                .map(|(_, r)| r)
                .collect();
            let mut ips: Vec<String> = rs.iter().flat_map(|r| values(r)).collect();
            unique(&mut ips);
            let mut cnames: Vec<String> = rs
                .iter()
                .filter_map(|r| r.as_ref().ok())
                .flat_map(|r| r.chain())
                .collect();
            unique(&mut cnames);
            let sig = signature(label);
            let status = if rs
                .iter()
                .any(|r| kind_of(r) == "answered" && !values(r).is_empty())
            {
                "answered"
            } else if rs
                .iter()
                .all(|r| matches!(kind_of(r), "nxdomain" | "nodata" | "answered"))
            {
                "no_match"
            } else {
                "unavailable"
            };
            json!({"name": format!("{label}.{base}"), "ips": ips, "cnames": cnames,
                "possible_wildcard": !sig.is_empty() && wildcard.contains(&sig), "status": status})
        })
        .collect();
    let unavailable: Vec<&str> = rows
        .iter()
        .filter(|r| r["status"] == "unavailable")
        .filter_map(|r| r["name"].as_str())
        .collect();
    let control_failed = results
        .iter()
        .any(|(l, r)| controls.contains(l) && failed(r));
    let mut problems = vec![];
    if !unavailable.is_empty() {
        problems.push(format!("lookups failed for {}", unavailable.join(", ")));
    }
    if control_failed {
        problems.push("wildcard control lookups failed".to_string());
    }
    let data = json!({
        "base": base, "tested": COMMON_NAMES.len(), "queries": results.len(), "controls": controls.len(),
        "wildcard_observed": !wildcard.is_empty(),
        "coverage": "20 common names beneath the entered hostname, with randomized wildcard controls; not complete discovery. Wildcard matches remain visible.",
        "rows": rows,
    });
    if problems.is_empty() {
        Ok(data)
    } else {
        Err(CheckFailure {
            error: problems.join("; "),
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(
        name: &str,
        ty: &str,
        outcome: dns::Outcome,
        records: &[(&str, &str, &str)],
    ) -> dns::Answer {
        dns::Answer {
            name: name.into(),
            rr_type: ty.into(),
            server: "fixture".into(),
            status: "fixture".into(),
            outcome,
            authoritative: false,
            authenticated: false,
            records: records
                .iter()
                .map(|(n, t, v)| dns::Record {
                    name: (*n).into(),
                    rr_type: (*t).into(),
                    rr_class: 1,
                    ttl: 1,
                    value: (*v).into(),
                })
                .collect(),
        }
    }

    #[test]
    fn prefix_matching_is_utf8_safe() {
        let prefixes = [
            "v=spf1",
            "v=DMARC1",
            "v=STSv1",
            "v=TLSRPTv1",
            "v=BIMI1",
            "v=DKIM1",
        ];
        for p in prefixes {
            for cut in 0..=p.len() + 1 {
                for tail in ["€", "é", "😀", "\u{0301}"] {
                    let s = format!("{}{tail}", &p[..cut.min(p.len())]);
                    let _ = starts_ci(&s, p);
                    let _ = has_version(&s, &p[2..]);
                    let _ = dkim_key(&s);
                }
            }
        }
        assert!(starts_ci("V=SPF1 -all", "v=spf1"));
        assert!(!starts_ci("aaaaa€", "v=spf1"));
        assert!(has_version("v=DMARC1; p=reject", "DMARC1"));
        assert!(has_version(" v = STSv1 ;id=1", "STSv1"));
        assert!(!has_version("v=DMARC10; p=reject", "DMARC1"));
        assert!(!has_version("p=reject; v=DMARC1", "DMARC1"));
    }

    #[test]
    fn dkim_key_structure() {
        use DkimKey::*;
        assert_eq!(dkim_key("v=DKIM1; k=rsa; p=MIIBIjAN"), Some(Published));
        assert_eq!(dkim_key("k=rsa; p=MIIB IjAN"), Some(Published));
        assert_eq!(dkim_key("v=DKIM1; p="), Some(Revoked));
        assert!(matches!(dkim_key("v=DKIM1; k=rsa"), Some(Malformed(_))));
        assert!(matches!(dkim_key("v=DKIM1; p=***"), Some(Malformed(_))));
        assert!(matches!(dkim_key("v=DKIM1; p=AAA"), Some(Malformed(_))));
        assert!(matches!(dkim_key("v=DKIM1; p=a; p=b"), Some(Malformed(_))));
        assert!(matches!(
            dkim_key("k=rsa; v=DKIM1; p=AAAA"),
            Some(Malformed(_))
        ));
        assert!(matches!(dkim_key("v=DKIM10; p=AAAA"), Some(Malformed(_))));
        assert_eq!(dkim_key("google-site-verification=abc"), None);
        assert_eq!(dkim_key("v=spf1 -all"), None);
    }

    #[test]
    fn providers_match_at_label_boundaries() {
        let p = dns_hosting_providers(&[
            "ns.cloudflare.com.unrelated.test".into(),
            "evilcloudflare.com".into(),
            "ns-1.awsdns-01.co.uk.".into(),
            "ns.awsdns-01.com.unrelated.test".into(),
            "ns1-01.azure-dns.info".into(),
            "Kate.NS.Cloudflare.com.".into(),
        ]);
        let names: Vec<(&str, &str)> = p
            .iter()
            .map(|v| (v["name"].as_str().unwrap(), v["basis"].as_str().unwrap()))
            .collect();
        assert_eq!(
            names,
            [
                ("cloudflare.com.unrelated.test", "nameserver-domain"),
                ("evilcloudflare.com", "nameserver-domain"),
                ("Amazon Route 53", "recognized"),
                ("awsdns-01.com.unrelated.test", "nameserver-domain"),
                ("Microsoft Azure DNS", "recognized"),
                ("Cloudflare", "recognized"),
            ]
        );
    }

    fn server(name: &str, aa: bool, evidence: Value) -> Value {
        json!({"server": name, "serial": 7, "provider": "ns.example.test", "aa": aa,
            "answers": evidence["answers"], "evidence": evidence, "kind": if aa { "pass" } else { "warn" }})
    }

    #[test]
    fn propagation_needs_authoritative_evidence() {
        let host = "www.example.test";
        let empty = json!({"outcome": "noerror", "cname": null, "answers": []});
        let ok_rec = Ok(answer(host, "A", dns::Outcome::NoError, &[]));
        // Lame servers do not count, even when they agree.
        let lame = vec![
            server("a", false, empty.clone()),
            server("b", false, empty.clone()),
        ];
        let r = propagation_report("example.test", host, lame, &ok_rec, "fixture");
        let Err(f) = r else {
            panic!("lame-only must fail")
        };
        assert_eq!(f.data["checked"], 0);
        assert_eq!(f.data["agree"], false);
        assert_eq!(f.data["recursive"]["matches"], false);
        // A failed recursive lookup is unknown, never a match.
        let auth = vec![
            server("a", true, empty.clone()),
            server("b", true, empty.clone()),
        ];
        let r = propagation_report(
            "example.test",
            host,
            auth.clone(),
            &Err("DNS timeout".into()),
            "fixture",
        );
        let Err(f) = r else {
            panic!("recursive failure must fail")
        };
        assert_eq!(f.data["recursive"]["matches"], Value::Null);
        assert_eq!(f.data["agree"], true);
        // Agreement and a matching recursive answer.
        let r = propagation_report("example.test", host, auth, &ok_rec, "fixture");
        assert_eq!(r.ok().unwrap()["recursive"]["matches"], true);
        // NXDOMAIN versus NODATA, and different aliases, are different answers.
        let nx = json!({"outcome": "nxdomain", "cname": null, "answers": []});
        let alias = |t: &str| json!({"outcome": "noerror", "cname": t, "answers": []});
        for other in [nx, alias("b.cdn.test")] {
            let rows = vec![
                server("a", true, alias("a.cdn.test")),
                server("b", true, other),
            ];
            let d = propagation_report("example.test", host, rows, &ok_rec, "fixture")
                .ok()
                .unwrap();
            assert_eq!(d["answers_differ"], true);
            assert_eq!(d["agree"], false);
        }
    }

    #[test]
    fn a_evidence_compares_the_name_itself() {
        let host = "www.example.test";
        let authoritative = answer(
            host,
            "A",
            dns::Outcome::NoError,
            &[(host, "CNAME", "edge.cdn.test.")],
        );
        let recursive = answer(
            host,
            "A",
            dns::Outcome::NoError,
            &[
                (host, "CNAME", "edge.cdn.test."),
                ("edge.cdn.test.", "A", "192.0.2.1"),
            ],
        );
        assert_eq!(
            a_evidence(&authoritative, host),
            a_evidence(&recursive, host)
        );
        assert_eq!(a_evidence(&recursive, host)["cname"], "edge.cdn.test");
    }
}
