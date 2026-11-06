//! Apache / Nginx access log parser (common and combined formats).

use super::normalize;
use super::RecordOutcome;
use crate::error::{AppError, AppResult};
use crate::types::NormalizedEvent;
use serde_json::{Map, Value};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

const HTTP_METHODS: [&str; 9] = [
    "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

pub(crate) struct AccessLine {
    pub ts: i64,
    pub client_ip: String,
    pub username: Option<String>,
    pub method: String,
    pub uri: String,
    pub protocol: Option<String>,
    pub status: i64,
    pub bytes: Option<i64>,
    pub referrer: Option<String>,
    pub user_agent: Option<String>,
}

fn quoted_strings(input: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut rest = input;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        match after.find('"') {
            Some(end) => {
                values.push(after[..end].to_string());
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
    values
}

pub(crate) fn parse_access(line: &str) -> Option<AccessLine> {
    let cleaned = normalize::strip_bom(line).trim();
    let tokens: Vec<&str> = cleaned.split_whitespace().collect();
    if tokens.len() < 7 {
        return None;
    }
    let client_ip = normalize::normalize_ip(tokens[0])?;
    let open = cleaned.find('[')?;
    let close = cleaned[open..].find(']')? + open;
    let stamp = cleaned[open + 1..close].trim();
    let ts = chrono::DateTime::parse_from_str(stamp, "%d/%b/%Y:%H:%M:%S %z")
        .ok()?
        .timestamp_millis();
    let rest = &cleaned[close + 1..];
    let request_start = rest.find('"')?;
    let request_end = rest[request_start + 1..].find('"')? + request_start + 1;
    let request = &rest[request_start + 1..request_end];
    let mut request_parts = request.split_whitespace();
    let method = request_parts.next()?.to_string();
    let method_upper = method.to_ascii_uppercase();
    if !HTTP_METHODS.contains(&method_upper.as_str()) {
        return None;
    }
    let uri = request_parts.next().unwrap_or("/").to_string();
    let protocol = request_parts.next().map(|value| value.to_string());
    let after = rest[request_end + 1..].trim_start();
    let mut parts = after.split_whitespace();
    let status: i64 = parts.next()?.parse().ok()?;
    if !(100..=599).contains(&status) {
        return None;
    }
    let bytes = parts.next().and_then(|value| {
        if value == "-" {
            None
        } else {
            value.parse::<i64>().ok()
        }
    });
    let extras = quoted_strings(after);
    let referrer = extras
        .first()
        .filter(|value| value.as_str() != "-")
        .cloned();
    let user_agent = extras
        .get(1)
        .filter(|value| value.as_str() != "-")
        .cloned();
    let username = tokens
        .get(2)
        .filter(|value| **value != "-")
        .map(|value| value.to_string());
    Some(AccessLine {
        ts,
        client_ip,
        username,
        method,
        uri,
        protocol,
        status,
        bytes,
        referrer,
        user_agent,
    })
}

/// Normalize one web access line. Detection reuses this function.
pub fn parse_line(line: &str, line_number: i64) -> Result<NormalizedEvent, String> {
    let access = parse_access(line).ok_or_else(|| "not a web access log record".to_string())?;
    let mut event = NormalizedEvent::new(access.ts, "web_access");
    event.category = Some("web".to_string());
    event.event_type = Some("http".to_string());
    event.src_ip = Some(access.client_ip.clone());
    event.username = access.username.clone();
    event.message = Some(format!(
        "{} {} {}",
        access.method, access.uri, access.status
    ));
    let mut attrs = Map::new();
    attrs.insert(
        "lineNumber".to_string(),
        Value::Number(line_number.into()),
    );
    attrs.insert(
        "method".to_string(),
        Value::String(access.method.clone()),
    );
    attrs.insert("uri".to_string(), Value::String(access.uri.clone()));
    attrs.insert("status".to_string(), Value::Number(access.status.into()));
    if let Some(protocol) = &access.protocol {
        attrs.insert("protocol".to_string(), Value::String(protocol.clone()));
    }
    if let Some(bytes) = access.bytes {
        attrs.insert("bytes".to_string(), Value::Number(bytes.into()));
    }
    if let Some(referrer) = &access.referrer {
        attrs.insert("referrer".to_string(), Value::String(referrer.clone()));
    }
    if let Some(user_agent) = &access.user_agent {
        attrs.insert("userAgent".to_string(), Value::String(user_agent.clone()));
    }
    event.attrs = Value::Object(attrs);
    event.raw = normalize::raw_line(line);
    Ok(event)
}

/// Stream an Apache/Nginx access log: one event per non-empty line.
pub fn stream(
    path: &Path,
    sink: &mut dyn FnMut(i64, RecordOutcome) -> AppResult<()>,
) -> AppResult<()> {
    let file = File::open(path)
        .map_err(|e| AppError::msg(format!("cannot open {}: {e}", path.display())))?;
    let reader = BufReader::new(file);
    let mut index = 0i64;
    for line in reader.lines() {
        let line = line?;
        let cleaned = normalize::strip_bom(&line);
        if cleaned.trim().is_empty() {
            continue;
        }
        index += 1;
        sink(index, parse_line(cleaned.trim_end(), index))?;
    }
    Ok(())
}
