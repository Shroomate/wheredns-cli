//! RDAP registration evidence through rdap.org redirect routing, parsed into the
//! fields shown in the whois panel. Every hop is resolved and pinned by policy.

use crate::{addresses, shared_slot, Args, Shared};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Mutex, OnceLock},
    time::Duration,
};

const MAX_BODY: usize = 1024 * 1024;

/// Deepest suffix tried as a registration (e.g. `foo.pvt.k12.ma.us`).
const MAX_REGISTRABLE_LABELS: usize = 5;

const NOT_FOUND: &str = "no registration record found (registry returned 404)";

/// True for the "registry has no such domain" result, as opposed to a failure.
pub fn is_not_found(e: &str) -> bool {
    e == NOT_FOUND
}

#[derive(Clone)]
pub struct Fetched {
    pub status: u16,
    pub body: Value,
    pub source: String,
}

type Fetches = Mutex<HashMap<String, Shared<Result<Fetched, String>>>>;

/// GET an RDAP document once per run: `where`, `whois` and `ip` share answers
/// for the same URL, including requests that are still in flight.
pub async fn get_json(a: &Args, url: &str) -> Result<Fetched, String> {
    static FETCHES: OnceLock<Fetches> = OnceLock::new();
    let slot = shared_slot(FETCHES.get_or_init(Default::default), url.to_string());
    slot.get_or_init(|| fetch(a, url)).await.clone()
}

/// GET an RDAP document, following at most four HTTPS redirects.
async fn fetch(a: &Args, url: &str) -> Result<Fetched, String> {
    use futures_util::StreamExt;
    let mut url = reqwest::Url::parse(url).map_err(|e| e.to_string())?;
    for _ in 0..5 {
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
            return Err("unsafe registry referral".into());
        }
        let host = url.host_str().ok_or("missing host")?.to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        let sockets: Vec<_> = addresses(a, &host)
            .await?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(a.timeout.max(4) * 2))
            .resolve_to_addrs(&host, &sockets)
            .user_agent(concat!("wheredns/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| e.to_string())?;
        let response = client
            .get(url.clone())
            .header("accept", "application/rdap+json, application/json")
            .send()
            .await
            .map_err(|e| format!("registry unavailable: {}", short_error(&e)))?;
        let status = response.status();
        if status.is_redirection() {
            let loc = response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .ok_or("registry redirect without location")?;
            url = url.join(loc).map_err(|e| e.to_string())?;
            continue;
        }
        if status.as_u16() != 200 {
            return Ok(Fetched {
                status: status.as_u16(),
                body: Value::Null,
                source: host,
            });
        }
        let mut bytes = vec![];
        let mut chunks = response.bytes_stream();
        while let Some(chunk) = chunks.next().await {
            let c = chunk.map_err(|e| e.to_string())?;
            if bytes.len() + c.len() > MAX_BODY {
                return Err("registry response exceeds 1 MiB".into());
            }
            bytes.extend_from_slice(&c);
        }
        let body = serde_json::from_slice(&bytes).map_err(|_| "invalid registry response")?;
        return Ok(Fetched {
            status: 200,
            body,
            source: host,
        });
    }
    Err("registry redirect limit reached".into())
}

fn short_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timed out".into()
    } else if e.is_connect() {
        "connection failed".into()
    } else {
        e.to_string()
    }
}

fn str_of(v: &Value) -> Option<String> {
    v.as_str()
        .map(|s| s.chars().take(500).collect::<String>())
        .filter(|s| !s.is_empty())
}

fn vcard(entity: &Value, field: &str) -> Option<String> {
    let props = entity.get("vcardArray")?.get(1)?.as_array()?;
    let prop = props
        .iter()
        .find(|p| p.get(0).and_then(Value::as_str) == Some(field))?;
    match prop.get(3)? {
        Value::String(s) => str_of(&Value::String(s.clone())),
        Value::Array(parts) => {
            let joined = parts
                .iter()
                .filter_map(Value::as_str)
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(", ");
            (!joined.is_empty()).then_some(joined)
        }
        _ => None,
    }
}

fn find_entities<'a>(entities: &'a Value, role: &str, depth: usize, out: &mut Vec<&'a Value>) {
    let Some(list) = entities.as_array() else {
        return;
    };
    if depth > 4 {
        return;
    }
    for e in list.iter().take(50) {
        if e["roles"]
            .as_array()
            .is_some_and(|r| r.iter().any(|x| x == role))
        {
            out.push(e);
        }
        find_entities(&e["entities"], role, depth + 1, out);
    }
}

fn find_entity<'a>(entities: &'a Value, role: &str) -> Option<&'a Value> {
    let mut out = vec![];
    find_entities(entities, role, 0, &mut out);
    out.into_iter().next()
}

fn events(obj: &Value) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    for ev in obj["events"].as_array().into_iter().flatten().take(50) {
        if let (Some(action), Some(date)) = (ev["eventAction"].as_str(), ev["eventDate"].as_str()) {
            if crate::util::parse_iso_date(date).is_some() {
                out.insert(action.to_string(), date[..10].to_string());
            }
        }
    }
    out
}

fn redacted(obj: &Value, needle: &str) -> bool {
    obj["redacted"].as_array().is_some_and(|items| {
        items.iter().take(50).any(|r| {
            [&r["name"]["description"], &r["name"]["type"]]
                .iter()
                .any(|v| {
                    v.as_str()
                        .is_some_and(|s| s.to_lowercase().contains(needle))
                })
        })
    })
}

fn country(entities: &[&Value]) -> Option<String> {
    let mut found = std::collections::BTreeSet::new();
    for e in entities {
        for p in e["vcardArray"][1].as_array().into_iter().flatten() {
            if p[0] == "adr" {
                if let Some(cc) = p[1]["cc"].as_str() {
                    if cc.len() == 2 && cc.chars().all(|c| c.is_ascii_alphabetic()) {
                        found.insert(cc.to_ascii_uppercase());
                    }
                }
            }
        }
    }
    (found.len() == 1).then(|| found.into_iter().next().unwrap())
}

/// Suffixes of `labels` to try as the registration, longest first: at most
/// MAX_REGISTRABLE_LABELS deep and never a single label.
fn candidates(labels: &[&str]) -> Vec<String> {
    (2..=labels.len().min(MAX_REGISTRABLE_LABELS))
        .rev()
        .map(|keep| labels[labels.len() - keep..].join(".").to_ascii_lowercase())
        .collect()
}

/// Registration for the registrable domain that contains `host`.
pub async fn domain(a: &Args, host: &str) -> Result<Value, String> {
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    if labels.len() < 2 {
        return Err("no registrable domain in a single-label name".into());
    }
    // Longest candidate first; registries answer 404 for names below the
    // registration. Names deeper than any plausible registration start at
    // MAX_REGISTRABLE_LABELS, so a.b.c.example.test still reaches example.test
    // and the request count stays bounded.
    let mut last = String::from(NOT_FOUND);
    for candidate in candidates(&labels) {
        let r = get_json(a, &format!("https://rdap.org/domain/{candidate}")).await?;
        match r.status {
            200 => return parse_domain(a, &candidate, r).await,
            404 => continue,
            429 => return Err("registry rate-limited the lookup".into()),
            s => last = format!("registry lookup unavailable (HTTP {s})"),
        }
    }
    Err(last)
}

/// The document describes exactly `domain` (same normalization for the first
/// response and for referrals).
fn is_domain(d: &Value, domain: &str) -> bool {
    d["objectClassName"] == "domain"
        && d["ldhName"]
            .as_str()
            .is_some_and(|n| n.trim_end_matches('.').eq_ignore_ascii_case(domain))
}

async fn parse_domain(a: &Args, candidate: &str, r: Fetched) -> Result<Value, String> {
    let d = &r.body;
    if !is_domain(d, candidate) {
        return Err("registry returned a different or malformed domain".into());
    }
    let registrar = find_entity(&d["entities"], "registrar");
    let iana = registrar.and_then(|r| {
        r["publicIds"].as_array()?.iter().find_map(|p| {
            p["type"]
                .as_str()
                .filter(|t| t.to_ascii_lowercase().contains("iana"))
                .and(p["identifier"].as_str().map(String::from))
        })
    });
    let ev = events(d);
    let mut registrants = vec![];
    find_entities(&d["entities"], "registrant", 0, &mut registrants);
    let mut registrant = registrants
        .first()
        .and_then(|e| vcard(e, "org").or_else(|| vcard(e, "fn")));
    let mut registrant_country = if redacted(d, "registrant country") {
        None
    } else {
        country(&registrants)
    };
    let mut abuse = registrar
        .and_then(|r| find_entity(&r["entities"], "abuse"))
        .and_then(|e| vcard(e, "email"));
    // Thin registries (e.g. .com) link to the registrar's own RDAP record.
    let related = d["links"].as_array().and_then(|links| {
        links.iter().find_map(|l| {
            (l["rel"] == "related" && l["type"] == "application/rdap+json")
                .then(|| l["href"].as_str())
                .flatten()
                .filter(|h| h.starts_with("https://"))
        })
    });
    let mut registrant_redacted = registrant.is_none() && redacted(d, "registrant");
    let mut referral = Value::Null;
    if let Some(href) = related.filter(|_| registrant.is_none() || registrant_country.is_none()) {
        if let Ok(rr) = get_json(a, href).await {
            let body = &rr.body;
            // A referral for another domain must never fill in this one's owner.
            let matches = rr.status == 200 && is_domain(body, candidate);
            referral = json!({"source": rr.source, "used": matches});
            if matches {
                let mut ref_registrants = vec![];
                find_entities(&body["entities"], "registrant", 0, &mut ref_registrants);
                if registrant.is_none() {
                    registrant = ref_registrants
                        .first()
                        .and_then(|e| vcard(e, "org").or_else(|| vcard(e, "fn")));
                }
                if registrant_country.is_none() && !redacted(body, "registrant country") {
                    registrant_country = country(&ref_registrants);
                }
                if registrant.is_none()
                    && (redacted(body, "registrant") || !ref_registrants.is_empty())
                {
                    registrant = Some("redacted by registrar".into());
                    registrant_redacted = false;
                }
                if abuse.is_none() {
                    abuse = find_entity(&body["entities"], "abuse").and_then(|e| vcard(e, "email"));
                }
            }
        }
    }
    if registrant.is_none() && registrant_redacted {
        registrant = Some("redacted by registry".into());
    }
    let nameservers: Vec<String> = d["nameservers"]
        .as_array()
        .into_iter()
        .flatten()
        .take(50)
        .filter_map(|n| n["ldhName"].as_str())
        .map(|n| n.trim_end_matches('.').to_ascii_lowercase())
        .collect();
    let status: Vec<&str> = d["status"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .take(50)
        .collect();
    Ok(json!({
        "kind": "domain",
        "domain": candidate,
        "source": r.source,
        "registrar": registrar.and_then(|r| vcard(r, "fn")),
        "iana_id": iana,
        "created": ev.get("registration"),
        "expires": ev.get("expiration"),
        "updated": ev.get("last changed").or(ev.get("last update of RDAP database")),
        "status": status,
        "nameservers": nameservers,
        "dnssec": d["secureDNS"]["delegationSigned"].as_bool(),
        "registrant": registrant,
        "registrant_country": registrant_country,
        "abuse": abuse,
        "referral": referral,
    }))
}

/// Network registration for one IP address.
pub async fn ip(a: &Args, ip: std::net::IpAddr) -> Result<Value, String> {
    let r = get_json(a, &format!("https://rdap.org/ip/{ip}")).await?;
    match r.status {
        200 => {}
        429 => return Err("RIR rate-limited the lookup".into()),
        s => return Err(format!("RIR returned HTTP {s}")),
    }
    let d = &r.body;
    if d["objectClassName"] != "ip network" {
        return Err("RIR returned a malformed network".into());
    }
    let holder = find_entity(&d["entities"], "registrant")
        .or_else(|| find_entity(&d["entities"], "administrative"))
        .and_then(|e| vcard(e, "fn"));
    let cidrs: Vec<String> = d["cidr0_cidrs"]
        .as_array()
        .into_iter()
        .flatten()
        .take(20)
        .filter_map(|c| {
            let prefix = c["v4prefix"].as_str().or(c["v6prefix"].as_str())?;
            Some(format!("{prefix}/{}", c["length"].as_u64()?))
        })
        .collect();
    let ev = events(d);
    let range = match (d["startAddress"].as_str(), d["endAddress"].as_str()) {
        (Some(s), Some(e)) => Some(format!("{s} – {e}")),
        _ => None,
    };
    Ok(json!({
        "kind": "ip",
        "ip": ip,
        "source": r.source,
        "handle": str_of(&d["handle"]),
        "name": str_of(&d["name"]),
        "range": range,
        "cidrs": cidrs,
        "type": str_of(&d["type"]),
        "country": d["country"].as_str().filter(|c| c.len() == 2),
        "holder": holder,
        "abuse": find_entity(&d["entities"], "abuse").and_then(|e| vcard(e, "email")),
        "registered": ev.get("registration"),
        "updated": ev.get("last changed"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registration_candidates_reach_the_parent() {
        let c = |h: &str| candidates(&h.split('.').collect::<Vec<_>>());
        assert_eq!(
            c("a.b.c.Example.test"),
            [
                "a.b.c.example.test",
                "b.c.example.test",
                "c.example.test",
                "example.test"
            ]
        );
        let deep = c("1.2.3.4.5.6.7.8.example.co.uk");
        assert_eq!(deep.len(), MAX_REGISTRABLE_LABELS - 1);
        assert_eq!(deep.last().unwrap(), "co.uk");
        assert!(deep.contains(&"example.co.uk".to_string()));
        assert_eq!(c("example.test"), ["example.test"]);
    }
    #[test]
    fn referral_identity_must_match() {
        let doc = |name: &str| json!({"objectClassName": "domain", "ldhName": name});
        assert!(is_domain(&doc("EXAMPLE.test."), "example.test"));
        assert!(!is_domain(&doc("unrelated.test"), "example.test"));
        assert!(!is_domain(
            &json!({"objectClassName": "entity", "ldhName": "example.test"}),
            "example.test"
        ));
        assert!(!is_domain(
            &json!({"objectClassName": "domain"}),
            "example.test"
        ));
    }
}
