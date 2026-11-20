//! Email header parsing and hop analysis. Input comes from stdin and never leaves the machine.

use crate::util;
use serde_json::{json, Value};
use std::io::Read;

pub fn read(reader: impl Read) -> Result<String, String> {
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

pub fn parse(raw: &str) -> Value {
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
        match line.split_once(':') {
            Some((n, v))
                if !n.is_empty() && n.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') =>
            {
                fields.push((n.to_ascii_lowercase(), v.trim().to_string()));
            }
            _ => malformed += 1,
        }
    }
    let analysis = analyze(&fields);
    json!({
        "schema_version": crate::SCHEMA_VERSION,
        "fields": fields.iter().map(|(n, v)| json!({"name": n, "value": v})).collect::<Vec<_>>(),
        "malformed_lines": malformed,
        "authentication_results_untrusted": true,
        "analysis": analysis,
    })
}

fn word_after<'a>(body: &'a str, lower: &str, key: &str) -> Option<&'a str> {
    let at = lower
        .match_indices(key)
        .find(|(i, _)| *i == 0 || lower.as_bytes()[i - 1].is_ascii_whitespace())?
        .0;
    body[at + key.len()..].split_whitespace().next()
}

fn analyze(fields: &[(String, String)]) -> Value {
    let first = |n: &str| fields.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    // Each server prepends Received:, so reverse for chronological order.
    let received: Vec<&String> = fields
        .iter()
        .filter(|(k, _)| k == "received")
        .map(|(_, v)| v)
        .rev()
        .collect();
    let mut prev: Option<i64> = None;
    let (mut first_t, mut last_t) = (None, None);
    let hops: Vec<Value> = received
        .iter()
        .map(|v| {
            let (body, date) = v.rsplit_once(';').unwrap_or((v, ""));
            let lower = body.to_ascii_lowercase();
            let from = lower.find("from ").filter(|i| *i == 0 || lower.as_bytes()[i - 1] == b' ').map(|i| {
                let rest = &body[i + 5..];
                let rest_l = &lower[i + 5..];
                let end = [" by ", " with ", " id ", " for "]
                    .iter()
                    .filter_map(|k| rest_l.find(k))
                    .min()
                    .unwrap_or(rest.len());
                rest[..end].trim().chars().take(140).collect::<String>()
            });
            let t = util::parse_rfc2822(date.trim());
            let delay = match (t, prev) {
                (Some(t), Some(p)) => Some(t - p),
                _ => None,
            };
            if let Some(t) = t {
                prev = Some(t);
                first_t.get_or_insert(t);
                last_t = Some(t);
            }
            json!({
                "from": from,
                "by": word_after(body, &lower, "by "),
                "with": word_after(body, &lower, "with "),
                "date": t.map(util::ymd_hms).unwrap_or_else(|| date.trim().chars().take(40).collect()),
                "delay_s": delay,
            })
        })
        .collect();
    let mut auth: Vec<Value> = vec![];
    for (_, ar) in fields
        .iter()
        .filter(|(k, _)| k == "authentication-results" || k == "arc-authentication-results")
        .take(2)
    {
        for part in ar.split(';') {
            let part = part.trim();
            let Some((method, rest)) = part.split_once('=') else {
                continue;
            };
            let method = method.trim().to_ascii_lowercase();
            if !["spf", "dkim", "dmarc", "arc", "compauth"].contains(&method.as_str())
                || auth.iter().any(|a| a["method"] == method)
            {
                continue;
            }
            let result: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphabetic())
                .collect::<String>()
                .to_ascii_lowercase();
            let detail: String = rest[result.len()..].trim().chars().take(160).collect();
            auth.push(json!({"method": method, "result": result, "detail": detail}));
        }
    }
    if !auth.iter().any(|a| a["method"] == "spf") {
        if let Some(rs) = first("received-spf") {
            let result = rs
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            auth.push(json!({"method": "spf", "result": result, "detail": "from Received-SPF"}));
        }
    }
    json!({
        "from": first("from"),
        "to": first("to"),
        "subject": first("subject"),
        "date": first("date"),
        "message_id": first("message-id"),
        "return_path": first("return-path"),
        "auth": auth,
        "hops": hops,
        "total_delay_s": match (first_t, last_t) { (Some(a), Some(b)) => Some(b - a), _ => None },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hop_trace_and_auth() {
        let v = parse(concat!(
            "Received: from mx.example.net (mx.example.net [192.0.2.5]) by inbound.example.org with ESMTPS id abc; Tue, 19 Nov 2024 10:00:05 +0000\r\n",
            "Received: from laptop (unknown) by mx.example.net with ESMTPSA id x1; Tue, 19 Nov 2024 10:00:00 +0000\r\n",
            "Authentication-Results: inbound.example.org; spf=pass smtp.mailfrom=example.net; dkim=fail header.d=example.net; dmarc=pass\r\n",
            "Subject: Hi\r\n\r\nbody"
        ));
        let a = &v["analysis"];
        assert_eq!(a["hops"][0]["by"], "mx.example.net");
        assert_eq!(
            a["hops"][1]["from"],
            "mx.example.net (mx.example.net [192.0.2.5])"
        );
        assert_eq!(a["hops"][1]["delay_s"], 5);
        assert_eq!(a["total_delay_s"], 5);
        assert_eq!(a["auth"][1]["method"], "dkim");
        assert_eq!(a["auth"][1]["result"], "fail");
        assert_eq!(a["subject"], "Hi");
    }
}
