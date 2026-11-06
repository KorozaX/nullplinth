//! Format detection: file extension first, then content sniffing.

use crate::error::{AppError, AppResult};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// A single JSON document holding an array of records.
    JsonArray,
    /// One JSON object per line.
    Ndjson,
    /// Suricata EVE JSON (one object per line with an event_type field).
    Suricata,
    /// Zeek TSV logs with the #separator / #fields / #types header block.
    Zeek,
    /// Delimited text requiring an explicit column mapping.
    Csv,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::JsonArray => "json",
            Format::Ndjson => "ndjson",
            Format::Suricata => "suricata",
            Format::Zeek => "zeek",
            Format::Csv => "csv",
        }
    }

    /// Parse a caller-supplied source type. Accepts common aliases.
    pub fn from_source_type(raw: &str) -> Option<Format> {
        let key: String = raw
            .trim()
            .to_ascii_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        match key.as_str() {
            "json" | "jsonarray" | "array" => Some(Format::JsonArray),
            "jsonl" | "ndjson" | "ndjsonl" | "jsons" => Some(Format::Ndjson),
            "suricata" | "eve" | "suricataeve" | "suricatajson" => Some(Format::Suricata),
            "zeek" | "zeektsv" | "bro" | "brologs" => Some(Format::Zeek),
            "csv" | "tsv" | "delimited" => Some(Format::Csv),
            _ => None,
        }
    }
}

/// What the first lines of a file look like.
pub(crate) struct Sniff {
    pub first_line: Option<String>,
    pub starts_array: bool,
    pub has_event_type: bool,
    pub is_zeek: bool,
}

pub(crate) fn sniff(path: &Path) -> AppResult<Sniff> {
    let file = File::open(path)
        .map_err(|e| AppError::msg(format!("cannot open {}: {e}", path.display())))?;
    let reader = BufReader::new(file);
    let mut sniff = Sniff {
        first_line: None,
        starts_array: false,
        has_event_type: false,
        is_zeek: false,
    };
    for line in reader.lines().take(64) {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("#separator")
            || trimmed.starts_with("#fields")
            || trimmed.starts_with("#types")
            || trimmed.starts_with("#path")
        {
            sniff.is_zeek = true;
            if sniff.first_line.is_none() {
                sniff.first_line = Some(line.clone());
            }
            continue;
        }
        if sniff.first_line.is_none() {
            sniff.first_line = Some(line.clone());
            sniff.starts_array = trimmed.starts_with('[');
            sniff.has_event_type = trimmed.starts_with('{') && line.contains("\"event_type\"");
            break;
        }
    }
    Ok(sniff)
}

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Detect the log format of a file. Extension wins, content sniffing breaks ties.
pub fn detect(path: &Path) -> AppResult<Format> {
    if !path.is_file() {
        return Err(AppError::msg(format!(
            "file does not exist or is not a file: {}",
            path.display()
        )));
    }
    let sniff = sniff(path)?;
    if sniff.first_line.is_none() && !sniff.is_zeek {
        return Err(AppError::msg(format!(
            "cannot detect log format of empty file: {}",
            path.display()
        )));
    }
    let ext = extension(path);
    let detected = match ext.as_str() {
        "json" => {
            if sniff.starts_array {
                Format::JsonArray
            } else if sniff.has_event_type {
                Format::Suricata
            } else {
                Format::Ndjson
            }
        }
        "jsonl" | "ndjson" => {
            if sniff.has_event_type {
                Format::Suricata
            } else {
                Format::Ndjson
            }
        }
        "log" | "tsv" | "zeek" | "bro" => {
            if sniff.is_zeek {
                Format::Zeek
            } else {
                Format::Csv
            }
        }
        "csv" | "txt" | "dat" => Format::Csv,
        _ => {
            if sniff.is_zeek {
                Format::Zeek
            } else if sniff.starts_array {
                Format::JsonArray
            } else if sniff.has_event_type {
                Format::Suricata
            } else if sniff
                .first_line
                .as_deref()
                .map(|l| l.trim_start().starts_with('{'))
                .unwrap_or(false)
            {
                Format::Ndjson
            } else {
                Format::Csv
            }
        }
    };
    Ok(detected)
}
