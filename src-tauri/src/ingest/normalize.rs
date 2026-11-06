//! Shared normalization primitives: timestamps, IPs, ports, transport, severity.
//!
//! Every value written to the database passes through one of these helpers so a
//! single contract exists for the detection engine and the query layer.

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use serde_json::Value;

/// Canonical severities understood by the query layer (CASE severity ...).
pub fn normalize_severity(raw: &str) -> Option<String> {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() {
        return None;
    }
    let mapped = match s.as_str() {
        "critical" | "crit" | "fatal" | "5" => "critical",
        "high" | "error" | "severe" | "4" => "high",
        "medium" | "warning" | "warn" | "3" => "medium",
        "low" | "notice" | "minor" | "2" => "low",
        "info" | "informational" | "debug" | "1" | "0" => "info",
        _ => return None,
    };
    Some(mapped.to_string())
}

/// Suricata alert severity levels: 1 = high, 2 = medium, 3 = low, anything else info.
pub fn suricata_severity(level: i64) -> &'static str {
    match level {
        1 => "high",
        2 => "medium",
        3 => "low",
        _ => "info",
    }
}

/// Normalize a transport / IP protocol value. Only ip-based transports are kept.
pub fn normalize_transport(raw: &str) -> Option<String> {
    let s = raw.trim().to_ascii_lowercase();
    let out = match s.as_str() {
        "tcp" | "tcp6" | "6" => "tcp",
        "udp" | "udp6" | "17" => "udp",
        "icmp" | "1" => "icmp",
        "icmpv6" | "icmp6" | "58" => "icmpv6",
        "sctp" | "132" => "sctp",
        _ => return None,
    };
    Some(out.to_string())
}

/// Canonical action vocabulary used by detection (blocked / failed for network).
pub fn normalize_action(raw: &str) -> Option<String> {
    let s = raw.trim().to_ascii_lowercase().replace([' ', '_'], "-");
    let out = match s.as_str() {
        "allowed" | "allow" | "accept" | "accepted" | "pass" | "permit" | "permitted" => "allowed",
        "blocked" | "block" | "deny" | "denied" | "drop" | "dropped" | "reject" | "rejected" => {
            "blocked"
        }
        "failed" | "failure" | "error" | "timeout" | "timed-out" => "failed",
        "success" | "succeeded" | "ok" | "successful" => "success",
        _ => return None,
    };
    Some(out.to_string())
}

/// Trim, drop empty values and the usual not-set markers used by network logs.
pub fn clean(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty()
        || s == "-"
        || s == "."
        || s == "(empty)"
        || s.eq_ignore_ascii_case("null")
        || s.eq_ignore_ascii_case("none")
    {
        None
    } else {
        Some(s.to_string())
    }
}

/// Parse and canonicalize an IPv4/IPv6 address.
pub fn normalize_ip(raw: &str) -> Option<String> {
    let s = raw.trim().trim_matches('"');
    if s.is_empty() {
        return None;
    }
    let s = if s.starts_with('[') && s.ends_with(']') && s.len() > 2 {
        &s[1..s.len() - 1]
    } else {
        s
    };
    s.parse::<std::net::IpAddr>().ok().map(|ip| ip.to_string())
}

/// Validate a port number (0-65535).
pub fn valid_port(port: i64) -> Option<i64> {
    if (0..=65535).contains(&port) {
        Some(port)
    } else {
        None
    }
}

pub fn normalize_port(raw: &str) -> Option<i64> {
    let s = raw.trim();
    if s.is_empty() || s == "-" || s == "." {
        return None;
    }
    let port = s
        .parse::<i64>()
        .ok()
        .or_else(|| s.parse::<f64>().ok().map(|f| f.round() as i64))?;
    valid_port(port)
}

/// Interpret a numeric epoch value as milliseconds, seconds, microseconds or nanosec.
pub fn scale_epoch(value: f64) -> Option<i64> {
    if !value.is_finite() || value <= 0.0 {
        return None;
    }
    let ms = if value >= 1e17 {
        value / 1e6
    } else if value >= 1e14 {
        value / 1e3
    } else if value >= 1e11 {
        value
    } else {
        value * 1000.0
    };
    let out = ms.round() as i64;
    if out > 0 {
        Some(out)
    } else {
        None
    }
}

fn naive_utc_ms(dt: NaiveDateTime) -> i64 {
    Utc.from_utc_datetime(&dt).timestamp_millis()
}

fn parse_with_format(raw: &str, format: &str) -> Option<i64> {
    if let Ok(dt) = DateTime::parse_from_str(raw, format) {
        return Some(dt.timestamp_millis());
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(raw, format) {
        return Some(naive_utc_ms(dt));
    }
    if let Ok(date) = NaiveDate::parse_from_str(raw, format) {
        return date.and_hms_opt(0, 0, 0).map(naive_utc_ms);
    }
    None
}

/// Parse a timestamp string. Accepts ISO-8601 / RFC-3339, common naive formats and
/// epoch integers or floats (Zeek writes epoch seconds as a float).
/// A custom chrono format from a CSV mapping is tried first when present.
pub fn parse_timestamp(raw: &str, custom_format: Option<&str>) -> Option<i64> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(format) = custom_format {
        let format = format.trim();
        if !format.is_empty() {
            if let Some(ts) = parse_with_format(s, format) {
                return Some(ts);
            }
        }
    }
    let numeric = s
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '.' | '-' | '+'));
    if numeric {
        if let Ok(value) = s.parse::<f64>() {
            if let Some(ts) = scale_epoch(value) {
                return Some(ts);
            }
        }
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.timestamp_millis());
    }
    const FORMATS: [&str; 8] = [
        "%Y-%m-%dT%H:%M:%S%.f%z",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%dT%H:%M:%S",
        "%Y-%m-%d",
    ];
    for format in FORMATS {
        if let Some(ts) = parse_with_format(s, format) {
            return Some(ts);
        }
    }
    None
}

/// Walk a dotted path inside a JSON value, e.g. "alert.severity" or "id.orig_h".
pub fn value_at<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for part in path.split('.') {
        current = match current {
            Value::Object(map) => map.get(part)?,
            Value::Array(items) => items.get(part.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(current)
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => clean(s),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// First matching dotted path that yields a string.
pub fn lookup_str(value: &Value, paths: &[&str]) -> Option<String> {
    paths
        .iter()
        .find_map(|path| value_at(value, path).and_then(value_to_string))
}

/// First matching dotted path that yields an integer.
pub fn lookup_i64(value: &Value, paths: &[&str]) -> Option<i64> {
    paths.iter().find_map(|path| {
        value_at(value, path).and_then(|v| match v {
            Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f.round() as i64)),
            Value::String(s) => s
                .trim()
                .parse::<i64>()
                .ok()
                .or_else(|| s.trim().parse::<f64>().ok().map(|f| f.round() as i64)),
            _ => None,
        })
    })
}

/// First matching dotted path that parses as an epoch timestamp in milliseconds.
pub fn lookup_timestamp(value: &Value, paths: &[&str]) -> Option<i64> {
    paths.iter().find_map(|path| {
        let v = value_at(value, path)?;
        match v {
            Value::Number(n) => scale_epoch(n.as_f64()?),
            Value::String(s) => parse_timestamp(s, None),
            _ => None,
        }
    })
}

/// Clone a JSON object and remove the keys already mapped to columns.
pub fn object_without(record: &Value, remove: &[&str]) -> Value {
    match record.as_object() {
        Some(map) => {
            let mut out = map.clone();
            for key in remove {
                out.remove(*key);
            }
            Value::Object(out)
        }
        None => Value::Object(Default::default()),
    }
}
