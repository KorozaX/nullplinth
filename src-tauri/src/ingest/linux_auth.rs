//! Linux authentication log parser: sshd, sudo, su, PAM and login.
//!
//! Contract shared with the detection engine: category = "authentication",
//! action = "failed" | "success".

use super::normalize;
use super::RecordOutcome;
use crate::error::AppResult;
use crate::types::NormalizedEvent;
use serde_json::{Map, Value};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

const AUTH_APPS: [&str; 5] = ["sshd", "sudo", "su", "login", "systemd-logind"];

fn is_auth_app(app: &str) -> bool {
    let lower = app.trim().to_ascii_lowercase();
    AUTH_APPS
        .iter()
        .any(|known| lower == *known || lower.starts_with(known))
        || lower.starts_with("pam")
        || lower.contains("sshd")
        || lower.starts_with("polkit")
}

fn is_auth_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    const MARKERS: [&str; 13] = [
        "failed password",
        "accepted password",
        "accepted publickey",
        "invalid user",
        "authentication failure",
        "failed publickey",
        "session opened",
        "session closed",
        "authentication succeeded",
        "pam_unix",
        "failed su",
        "incorrect password",
        "authentication failed",
    ];
    MARKERS.iter().any(|marker| lower.contains(marker))
}

fn key_value(message: &str, key: &str) -> Option<String> {
    let needle = format!("{}=", key.to_ascii_lowercase());
    for token in message.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix(needle.as_str()) {
            let value = rest.trim_matches('"').trim_matches(',').trim_matches(';');
            if !value.is_empty() && value != "-" {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn word_after<'a>(text: &'a str, needle: &str) -> Option<&'a str> {
    let lower = text.to_ascii_lowercase();
    let start = lower.find(needle)? + needle.len();
    text[start..].trim_start().split_whitespace().next()
}

fn username_from(message: &str) -> Option<String> {
    let lower = message.to_ascii_lowercase();
    const NEEDLES: [&str; 6] = [
        "failed password for invalid user ",
        "invalid user ",
        "failed password for ",
        "accepted password for ",
        "accepted publickey for ",
        "for user ",
    ];
    for needle in NEEDLES {
        if lower.contains(needle) {
            if let Some(candidate) = word_after(message, needle) {
                let cleaned = candidate.trim_matches(|c: char| c == ',' || c == ';' || c == '(');
                if !cleaned.is_empty() && cleaned != "invalid" {
                    return Some(cleaned.to_string());
                }
            }
        }
    }
    if let Some(value) = key_value(message, "user") {
        return Some(value);
    }
    if let Some(index) = message.find(" : ") {
        let candidate = message[..index].trim();
        if !candidate.is_empty() && !candidate.contains(' ') {
            return Some(candidate.to_string());
        }
    }
    None
}

fn source_ip_from(message: &str) -> Option<String> {
    if let Some(value) = key_value(message, "rhost") {
        if let Some(ip) = normalize::normalize_ip(&value) {
            return Some(ip);
        }
    }
    if let Some(value) = key_value(message, "from") {
        if let Some(ip) = normalize::normalize_ip(&value) {
            return Some(ip);
        }
    }
    if let Some(index) = message.to_ascii_lowercase().find(" from ") {
        let rest = &message[index + 6..];
        for token in rest.split_whitespace() {
            let cleaned = token.trim_matches(|c: char| c == ',' || c == ';' || c == '(');
            if let Some(ip) = normalize::normalize_ip(cleaned) {
                return Some(ip);
            }
        }
    }
    None
}

fn event_kind(app: &str, message: &str) -> &'static str {
    let lower_app = app.to_ascii_lowercase();
    let lower_message = message.to_ascii_lowercase();
    if lower_app.contains("sshd") || lower_message.contains("sshd") {
        "ssh"
    } else if lower_app.contains("sudo") {
        "sudo"
    } else if lower_app == "su" || lower_message.contains("su: pam") {
        "su"
    } else if lower_app.contains("login") {
        "login"
    } else {
        "auth"
    }
}

fn classify_action(lower: &str) -> Option<&'static str> {
    if lower.contains("failed password")
        || lower.contains("failed publickey")
        || lower.contains("authentication failure")
        || lower.contains("authentication failed")
        || lower.contains("failed su")
        || lower.contains("incorrect password")
        || lower.contains("invalid user")
    {
        return Some("failed");
    }
    if lower.contains("accepted password")
        || lower.contains("accepted publickey")
        || lower.contains("accepted keyboard")
        || lower.contains("authentication succeeded")
        || lower.contains("session opened")
        || lower.contains("session closed")
    {
        return Some("success");
    }
    None
}

fn auth_method(lower: &str) -> Option<&'static str> {
    if lower.contains("publickey") {
        Some("publickey")
    } else if lower.contains("keyboard-interactive") {
        Some("keyboard-interactive")
    } else if lower.contains("password") {
        Some("password")
    } else {
        None
    }
}

fn command_from(message: &str) -> Option<String> {
    let index = message.find("COMMAND=")?;
    let command = message[index + 8..].trim();
    if command.is_empty() {
        None
    } else {
        Some(command.to_string())
    }
}

/// Normalize one Linux authentication line. Returns Err when the line is not an
/// authentication record, which is what format detection counts.
pub fn parse_line(line: &str, line_number: i64) -> Result<NormalizedEvent, String> {
    let prefix = super::syslog::parse_prefix(line)
        .ok_or_else(|| "not a Linux authentication record".to_string())?;
    let app = prefix.app.clone().unwrap_or_default();
    let message = prefix.message.clone();
    let lower = message.to_ascii_lowercase();
    if !is_auth_app(&app) && !is_auth_message(&message) {
        return Err("not a Linux authentication record".to_string());
    }

    let mut event = super::syslog::parse_line(line, line_number)?;
    event.source_type = "linux_auth".to_string();
    event.category = Some("authentication".to_string());
    event.event_type = Some(event_kind(&app, &message).to_string());
    event.username = username_from(&message);
    event.src_ip = source_ip_from(&message);
    event.action = classify_action(&lower).map(|value| value.to_string());
    if event.attrs.is_null() {
        event.attrs = Value::Object(Map::new());
    }
    if let Some(attrs) = event.attrs.as_object_mut() {
        attrs.insert(
            "lineNumber".to_string(),
            Value::Number(line_number.into()),
        );
        if let Some(method) = auth_method(&lower) {
            attrs.insert("authMethod".to_string(), Value::String(method.to_string()));
        }
        if let Some(command) = command_from(&message) {
            attrs.insert("command".to_string(), Value::String(command));
        }
        if let Some(target) = key_value(&message, "user") {
            attrs.insert("targetUser".to_string(), Value::String(target));
        }
    }
    let _ = normalize::strip_bom(line);
    Ok(event)
}

/// Stream a Linux authentication log: one event per non-empty line.
pub fn stream(
    path: &Path,
    sink: &mut dyn FnMut(i64, RecordOutcome) -> AppResult<()>,
) -> AppResult<()> {
    let file = File::open(path)
        .map_err(|e| crate::error::AppError::msg(format!("cannot open {}: {e}", path.display())))?;
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
