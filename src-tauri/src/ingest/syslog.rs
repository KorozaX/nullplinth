//! Syslog parser: RFC3164 (classic BSD), RFC5424 and ISO-prefixed lines.

use super::normalize;
use super::RecordOutcome;
use crate::error::{AppError, AppResult};
use crate::types::NormalizedEvent;
use chrono::Datelike;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

pub(crate) struct SyslogPrefix {
    pub ts: i64,
    pub hostname: Option<String>,
    pub app: Option<String>,
    pub pid: Option<i64>,
    pub message: String,
    pub priority: Option<i64>,
    pub structured: Option<String>,
}

fn month_number(name: &str) -> Option<u32> {
    MONTHS
        .iter()
        .position(|month| month.eq_ignore_ascii_case(name))
        .map(|index| index as u32 + 1)
}

fn build_ts(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> Option<i64> {
    let date = chrono::NaiveDate::from_ymd_opt(year, month, day)?;
    let time = date.and_hms_opt(hour, minute, second)?;
    Some(chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(time, chrono::Utc).timestamp_millis())
}

fn parse_hms(token: &str) -> Option<(u32, u32, u32)> {
    let mut parts = token.split(':');
    let hour = parts.next()?.parse().ok()?;
    let minute = parts.next()?.parse().ok()?;
    let second = parts.next()?.trim_end_matches('.').parse().ok()?;
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some((hour, minute, second))
}

fn split_app_tag(tag: &str) -> (Option<String>, Option<i64>) {
    let tag = tag.trim();
    if tag.is_empty() || tag == "-" {
        return (None, None);
    }
    if let Some(open) = tag.find('[') {
        let app = tag[..open].trim();
        let pid_text = tag[open + 1..].trim_end_matches(']');
        let pid = pid_text.parse::<i64>().ok();
        return (non_empty(app), pid);
    }
    (non_empty(tag), None)
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "-" {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Split "app[pid]: message" into app, pid and message.
fn split_tag(input: &str) -> (Option<String>, Option<i64>, String) {
    match input.find(": ") {
        Some(index) => {
            let tag = &input[..index];
            let message = input[index + 2..].trim_start().to_string();
            let (app, pid) = split_app_tag(tag);
            (app, pid, message)
        }
        None => (None, None, input.trim().to_string()),
    }
}

/// Split "host tag: message" into hostname and the rest.
fn split_host(input: &str) -> (Option<String>, String) {
    let mut parts = input.splitn(2, ' ');
    let host = parts.next().unwrap_or("");
    let rest = parts.next().unwrap_or("").trim_start();
    (non_empty(host), rest.to_string())
}

fn after_tokens(input: &str, count: usize) -> &str {
    let mut rest = input;
    for _ in 0..count {
        rest = rest.trim_start();
        match rest.find(char::is_whitespace) {
            Some(index) => rest = &rest[index..],
            None => return "",
        }
    }
    rest.trim_start()
}

fn parse_rfc5424(rest: &str, priority: Option<i64>) -> Option<SyslogPrefix> {
    let mut version_parts = rest.splitn(2, ' ');
    version_parts.next()?;
    let remainder = version_parts.next()?.trim_start();
    let ts_token = remainder.split_whitespace().next()?;
    let ts = normalize::parse_timestamp(ts_token, None)?;
    let after_ts = after_tokens(remainder, 1);
    let mut fields = after_ts.splitn(6, ' ');
    let hostname = non_empty(fields.next().unwrap_or(""));
    let app = non_empty(fields.next().unwrap_or(""));
    let pid = fields.next().and_then(|value| value.parse::<i64>().ok());
    let _msgid = fields.next();
    let structured = non_empty(fields.next().unwrap_or(""));
    let message = fields.next().unwrap_or("").to_string();
    Some(SyslogPrefix {
        ts,
        hostname,
        app,
        pid,
        message,
        priority,
        structured,
    })
}

fn parse_rfc3164(rest: &str, priority: Option<i64>) -> Option<SyslogPrefix> {
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    if tokens.len() < 4 {
        return None;
    }
    let month = month_number(tokens[0])?;
    let day: u32 = tokens[1].parse().ok()?;
    let (hour, minute, second) = parse_hms(tokens[2])?;
    let remainder = after_tokens(rest, 3);
    if !remainder.contains(": ") {
        return None;
    }
    let year = chrono::Utc::now().year();
    let ts = build_ts(year, month, day, hour, minute, second)?;
    let (hostname, tag_and_msg) = split_host(remainder);
    let (app, pid, message) = split_tag(&tag_and_msg);
    Some(SyslogPrefix {
        ts,
        hostname,
        app,
        pid,
        message,
        priority,
        structured: None,
    })
}

fn parse_iso_prefixed(rest: &str, priority: Option<i64>) -> Option<SyslogPrefix> {
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    if tokens.len() < 3 {
        return None;
    }
    let first = tokens[0];
    let (ts, remainder) = if first.len() >= 10 && first.as_bytes()[4] == b'-' && first.as_bytes()[7] == b'-' {
        if first.contains('T') {
            (normalize::parse_timestamp(first, None)?, after_tokens(rest, 1))
        } else {
            let combined = format!("{} {}", first, tokens[1]);
            (normalize::parse_timestamp(&combined, None)?, after_tokens(rest, 2))
        }
    } else {
        return None;
    };
    if !remainder.contains(": ") {
        return None;
    }
    let (hostname, tag_and_msg) = split_host(remainder);
    let (app, pid, message) = split_tag(&tag_and_msg);
    Some(SyslogPrefix {
        ts,
        hostname,
        app,
        pid,
        message,
        priority,
        structured: None,
    })
}

/// Parse a syslog line prefix (timestamp, host, app, pid, message).
pub(crate) fn parse_prefix(line: &str) -> Option<SyslogPrefix> {
    let cleaned = normalize::strip_bom(line).trim_end();
    let mut rest = cleaned.trim_start();
    if rest.is_empty() {
        return None;
    }
    let mut priority: Option<i64> = None;
    if rest.starts_with('<') {
        if let Some(close) = rest.find('>') {
            if let Ok(value) = rest[1..close].trim().parse::<i64>() {
                if (0..=191).contains(&value) {
                    priority = Some(value);
                    rest = rest[close + 1..].trim_start();
                }
            }
        }
    }
    let first_token = rest.split_whitespace().next()?;
    if priority.is_some() && first_token == "1" {
        return parse_rfc5424(rest, priority);
    }
    if month_number(first_token).is_some() {
        return parse_rfc3164(rest, priority);
    }
    parse_iso_prefixed(rest, priority)
}

fn syslog_severity(priority: i64) -> &'static str {
    match priority & 7 {
        0 | 1 | 2 => "high",
        3 => "medium",
        4 => "low",
        _ => "info",
    }
}

/// Normalize one syslog line. Category is left empty on purpose: syslog does not
/// carry an event taxonomy, so inventing one would poison the detection engine.
pub fn parse_line(line: &str, _line_number: i64) -> Result<NormalizedEvent, String> {
    let prefix = parse_prefix(line).ok_or_else(|| "not a syslog record".to_string())?;
    let mut event = NormalizedEvent::new(prefix.ts, "syslog");
    event.event_type = Some("syslog".to_string());
    event.hostname = prefix.hostname.clone();
    event.process_name = prefix.app.clone();
    event.message = Some(prefix.message.clone());
    let mut attrs = serde_json::Map::new();
    if let Some(priority) = prefix.priority {
        event.severity = syslog_severity(priority).to_string();
        attrs.insert("priority".to_string(), serde_json::Value::Number(priority.into()));
        attrs.insert("facility".to_string(), serde_json::Value::Number((priority / 8).into()));
    }
    if let Some(pid) = prefix.pid {
        attrs.insert("pid".to_string(), serde_json::Value::Number(pid.into()));
    }
    if let Some(app) = &prefix.app {
        attrs.insert("app".to_string(), serde_json::Value::String(app.clone()));
    }
    if let Some(structured) = &prefix.structured {
        attrs.insert(
            "structuredData".to_string(),
            serde_json::Value::String(structured.clone()),
        );
    }
    event.attrs = serde_json::Value::Object(attrs);
    event.raw = normalize::raw_line(line);
    Ok(event)
}

/// Stream a syslog file: one event per non-empty line.
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
