//! Firewall key=value log parser.
//!
//! Example line (real user file):
//!   2024-01-15 06:01:29 ALLOW TCP src=192.168.1.105 dst=142.250.180.14 port=443 user=rjones failed=0
//! Maps failed>0 to action "failed", otherwise the firewall verb decides
//! allowed / blocked.

use super::normalize;
use super::RecordOutcome;
use crate::error::{AppError, AppResult};
use crate::types::NormalizedEvent;
use serde_json::{Map, Value};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

fn is_action_token(token: &str) -> bool {
    let upper: String = token
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .collect::<String>()
        .to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "ALLOW"
            | "ALLOWED"
            | "ACCEPT"
            | "ACCEPTED"
            | "PERMIT"
            | "PASS"
            | "DENY"
            | "DENIED"
            | "DROP"
            | "DROPPED"
            | "BLOCK"
            | "BLOCKED"
            | "REJECT"
            | "REJECTED"
    )
}

fn parse_fields(line: &str) -> Map<String, Value> {
    let mut fields = Map::new();
    for token in line.split_whitespace() {
        if let Some(index) = token.find('=') {
            let key = token[..index].trim().to_ascii_lowercase();
            let value = token[index + 1..]
                .trim_matches('"')
                .trim_matches(',')
                .trim_matches(';');
            if key.is_empty() {
                continue;
            }
            fields.insert(key, Value::String(value.to_string()));
        }
    }
    fields
}

fn field_str(fields: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = fields.get(*key).and_then(|value| value.as_str()) {
            if let Some(cleaned) = normalize::clean(value) {
                return Some(cleaned);
            }
        }
    }
    None
}

fn field_ip(fields: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    field_str(fields, keys).and_then(|value| normalize::normalize_ip(&value))
}

fn field_port(fields: &Map<String, Value>, keys: &[&str]) -> Option<i64> {
    field_str(fields, keys).and_then(|value| normalize::normalize_port(&value))
}

fn timestamp_from(tokens: &[&str], fields: &Map<String, Value>) -> Option<i64> {
    if let Some(first) = tokens.first() {
        if first.contains('T') {
            if let Some(ts) = normalize::parse_timestamp(first, None) {
                return Some(ts);
            }
        }
        if first.len() == 10 && tokens.len() >= 2 {
            let combined = format!("{} {}", first, tokens[1]);
            if let Some(ts) = normalize::parse_timestamp(&combined, None) {
                return Some(ts);
            }
        }
        if let Some(ts) = normalize::parse_timestamp(first, None) {
            return Some(ts);
        }
    }
    for key in ["timestamp", "time", "ts", "date", "eventtime"] {
        if let Some(value) = fields.get(key).and_then(|value| value.as_str()) {
            if let Some(ts) = normalize::parse_timestamp(value, None) {
                return Some(ts);
            }
        }
    }
    None
}

/// Normalize one firewall record. Detection reuses this function, so a line only
/// counts as firewall data when it actually parses.
pub fn parse_line(line: &str, line_number: i64) -> Result<NormalizedEvent, String> {
    let cleaned = normalize::strip_bom(line).trim();
    if cleaned.is_empty() {
        return Err("empty line".to_string());
    }
    let tokens: Vec<&str> = cleaned.split_whitespace().collect();
    let pair_count = tokens.iter().filter(|token| token.contains('=')).count();
    if pair_count < 2 {
        return Err("not a firewall key=value record".to_string());
    }
    let action_token = tokens.iter().find(|token| is_action_token(token));
    let action_token = match action_token {
        Some(token) => *token,
        None => return Err("no firewall action keyword".to_string()),
    };
    let fields = parse_fields(cleaned);
    let ts = timestamp_from(&tokens, &fields).ok_or_else(|| "missing timestamp".to_string())?;

    let mut event = NormalizedEvent::new(ts, "firewall");
    event.category = Some("network".to_string());
    event.event_type = Some("firewall".to_string());
    event.transport = field_str(&fields, &["proto", "protocol", "transport"])
        .and_then(|value| normalize::normalize_transport(&value))
        .or_else(|| {
            tokens
                .iter()
                .find_map(|token| normalize::normalize_transport(token))
        });
    event.src_ip = field_ip(
        &fields,
        &["src", "src_ip", "srcip", "source", "source_ip", "saddr"],
    );
    event.dst_ip = field_ip(
        &fields,
        &["dst", "dst_ip", "dstip", "dest", "destination", "dest_ip", "daddr"],
    );
    event.src_port = field_port(&fields, &["sport", "src_port", "srcport", "spt"]);
    event.dst_port = field_port(&fields, &["port", "dport", "dst_port", "dstport", "dpt"]);
    event.username = field_str(&fields, &["user", "username", "src_user"]);
    event.app_proto = field_str(&fields, &["app", "app_proto", "application", "service"]);
    let failed = fields
        .get("failed")
        .and_then(|value| value.as_str())
        .and_then(|value| value.parse::<i64>().ok());
    event.action = if failed.unwrap_or(0) > 0 {
        Some("failed".to_string())
    } else {
        normalize::normalize_action(action_token)
    };
    event.message = Some(cleaned.to_string());

    let mut attrs = fields.clone();
    attrs.insert(
        "lineNumber".to_string(),
        Value::Number(line_number.into()),
    );
    attrs.insert(
        "actionRaw".to_string(),
        Value::String(action_token.to_ascii_uppercase()),
    );
    if let Some(failed) = failed {
        attrs.insert("failedAttempts".to_string(), Value::Number(failed.into()));
    }
    if let Some(rule) = field_str(&fields, &["rule", "policy", "acl", "rulename"]) {
        attrs.insert("rule".to_string(), Value::String(rule));
    }
    event.attrs = Value::Object(attrs);
    event.raw = normalize::raw_line_with_fields(cleaned, parse_fields(cleaned));
    Ok(event)
}

/// Stream a firewall key=value log: one event per non-empty line.
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
