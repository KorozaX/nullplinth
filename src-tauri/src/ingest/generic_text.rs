//! Fallback parser for unknown text logs: one event per non-empty line.
//!
//! Honesty rules: never invent IPs, category or severity; the timestamp is kept
//! only when the line actually carries one (ts=0 means unknown).

use super::normalize;
use super::RecordOutcome;
use crate::error::{AppError, AppResult};
use crate::types::NormalizedEvent;
use serde_json::{Map, Value};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Best-effort timestamp extraction from the start of a text line.
pub fn extract_timestamp(line: &str) -> Option<i64> {
    let cleaned = normalize::strip_bom(line).trim_start();
    if cleaned.is_empty() {
        return None;
    }
    if let Some(prefix) = super::syslog::parse_prefix(cleaned) {
        return Some(prefix.ts);
    }
    let tokens: Vec<&str> = cleaned.split_whitespace().collect();
    let first = tokens.first()?;
    if first.contains('T') {
        if let Some(ts) = normalize::parse_timestamp(first, None) {
            return Some(ts);
        }
    }
    if first.len() == 10 && first.as_bytes()[4] == b'-' && tokens.len() >= 2 {
        let combined = format!("{} {}", first, tokens[1]);
        if let Some(ts) = normalize::parse_timestamp(&combined, None) {
            return Some(ts);
        }
    }
    if first.len() == 10 {
        if let Some(ts) = normalize::parse_timestamp(first, None) {
            return Some(ts);
        }
    }
    if first.len() >= 9 && first.chars().all(|c| c.is_ascii_digit()) {
        if let Some(ts) = normalize::parse_timestamp(first, None) {
            return Some(ts);
        }
    }
    None
}

/// Normalize one unknown text line. This always succeeds: the import manager
/// counts it as an imported event with an honest, minimal representation.
pub fn parse_line(line: &str, line_number: i64) -> Result<NormalizedEvent, String> {
    let cleaned = normalize::strip_bom(line).trim();
    if cleaned.is_empty() {
        return Err("empty line".to_string());
    }
    let ts = extract_timestamp(cleaned).unwrap_or(0);
    let mut event = NormalizedEvent::new(ts, "generic_text");
    event.message = Some(cleaned.to_string());
    let mut attrs = Map::new();
    attrs.insert("lineNumber".to_string(), Value::Number(line_number.into()));
    attrs.insert("timestampParsed".to_string(), Value::Bool(ts > 0));
    event.attrs = Value::Object(attrs);
    event.raw = normalize::raw_line(cleaned);
    Ok(event)
}

/// Stream an unknown text log: one event per non-empty line.
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
