//! Small calendar and formatting helpers (UTC only, no time zone database).

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn ymd(ts: i64) -> String {
    let (y, m, d) = civil_from_days(ts.div_euclid(86400));
    format!("{y:04}-{m:02}-{d:02}")
}

pub fn ymd_hms(ts: i64) -> String {
    let secs = ts.rem_euclid(86400);
    format!(
        "{} {:02}:{:02}:{:02}Z",
        ymd(ts),
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// Parses the `YYYY-MM-DD` prefix of an ISO 8601 timestamp to a Unix time at midnight UTC.
pub fn parse_iso_date(s: &str) -> Option<i64> {
    let b = s.get(..10)?;
    let mut parts = b.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    ((1..=12).contains(&m) && (1..=31).contains(&d)).then(|| days_from_civil(y, m, d) * 86400)
}

/// Parses an RFC 5322 date such as `Tue, 19 Nov 2026 22:18:01 -0800 (PST)`.
pub fn parse_rfc2822(s: &str) -> Option<i64> {
    let s = s.split('(').next()?.trim();
    let s = s.split_once(',').map_or(s, |(_, rest)| rest).trim();
    let mut it = s.split_whitespace();
    let day: u32 = it.next()?.parse().ok()?;
    let month = match it.next()?.get(..3)?.to_ascii_lowercase().as_str() {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => return None,
    };
    let mut year: i64 = it.next()?.parse().ok()?;
    if year < 100 {
        year += if year < 50 { 2000 } else { 1900 };
    }
    let mut hms = it.next()?.split(':');
    let h: i64 = hms.next()?.parse().ok()?;
    let mi: i64 = hms.next()?.parse().ok()?;
    let sec: i64 = hms.next().map_or(Some(0), |v| v.parse().ok())?;
    let offset = match it.next() {
        Some(z) if z.len() == 5 && (z.starts_with('+') || z.starts_with('-')) => {
            let sign = if z.starts_with('-') { -1 } else { 1 };
            let hh: i64 = z[1..3].parse().ok()?;
            let mm: i64 = z[3..5].parse().ok()?;
            sign * (hh * 3600 + mm * 60)
        }
        Some("EDT") => -4 * 3600,
        Some("EST") | Some("CDT") => -5 * 3600,
        Some("CST") | Some("MDT") => -6 * 3600,
        Some("MST") | Some("PDT") => -7 * 3600,
        Some("PST") => -8 * 3600,
        _ => 0,
    };
    if !(1..=31).contains(&day) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86400 + h * 3600 + mi * 60 + sec - offset)
}

pub fn colon_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Rounds milliseconds to one decimal place.
pub fn ms(d: std::time::Duration) -> f64 {
    (d.as_secs_f64() * 10000.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn calendar_round_trip() {
        for z in [-1000, 0, 19000, 20774, 30000] {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m, d), z);
        }
        assert_eq!(ymd(0), "1970-01-01");
        assert_eq!(
            parse_iso_date("2028-10-09T04:00:00Z").map(ymd).unwrap(),
            "2028-10-09"
        );
        let t = parse_rfc2822("Tue, 19 Nov 2024 22:18:01 -0800 (PST)").unwrap();
        assert_eq!(ymd_hms(t), "2024-11-20 06:18:01Z");
        assert!(parse_rfc2822("garbage").is_none());
    }
}
