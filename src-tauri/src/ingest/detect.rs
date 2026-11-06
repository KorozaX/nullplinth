//! Content-based format registry. File extensions are hints only; the bytes decide.
//!
//! Every line-oriented parser exposes a line-level recognizer that detection reuses,
//! so detection and parsing can never disagree about what a line is.

use crate::error::{AppError, AppResult};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub const MAX_SAMPLE_LINES: usize = 300;

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
    /// Linux authentication log (sshd, sudo, su, PAM).
    LinuxAuth,
    /// RFC3164 / RFC5424 syslog.
    Syslog,
    /// Apache / Nginx access log (common or combined).
    WebAccess,
    /// Firewall key=value log, e.g. "2024-01-15 06:01:29 ALLOW TCP src=... dst=... port=443".
    Firewall,
    /// Unknown text: one event per line, no invented fields.
    GenericText,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::JsonArray => "json",
            Format::Ndjson => "ndjson",
            Format::Suricata => "suricata",
            Format::Zeek => "zeek",
            Format::Csv => "csv",
            Format::LinuxAuth => "linux_auth",
            Format::Syslog => "syslog",
            Format::WebAccess => "web_access",
            Format::Firewall => "firewall",
            Format::GenericText => "generic_text",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Format::JsonArray => "JSON array",
            Format::Ndjson => "NDJSON (one JSON object per line)",
            Format::Suricata => "Suricata EVE JSON",
            Format::Zeek => "Zeek TSV",
            Format::Csv => "CSV table",
            Format::LinuxAuth => "Linux authentication log",
            Format::Syslog => "Syslog",
            Format::WebAccess => "Web access log (Apache/Nginx)",
            Format::Firewall => "Firewall key=value log",
            Format::GenericText => "Generic text log",
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
            "linuxauth" | "auth" | "authlog" | "sshd" | "linuxauthlog" => Some(Format::LinuxAuth),
            "syslog" | "rfc3164" | "rfc5424" | "messages" => Some(Format::Syslog),
            "webaccess" | "apache" | "nginx" | "accesslog" | "httpd" | "httpdaccess" => {
                Some(Format::WebAccess)
            }
            "firewall" | "kv" | "keyvalue" | "iptables" | "paloalto" | "firewallkv" => {
                Some(Format::Firewall)
            }
            "generictext" | "text" | "plain" | "log" | "other" => Some(Format::GenericText),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Detection {
    pub format: Format,
    pub confidence: String,
    pub sample_lines: Vec<String>,
    pub estimated_records: Option<i64>,
    pub warnings: Vec<String>,
}

fn read_sample_lines(path: &Path) -> AppResult<Vec<String>> {
    let file = File::open(path)
        .map_err(|e| AppError::msg(format!("cannot open {}: {e}", path.display())))?;
    let reader = BufReader::new(file);
    let mut samples: Vec<String> = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let cleaned = super::normalize::strip_bom(&line).trim_end();
        if cleaned.trim().is_empty() {
            continue;
        }
        samples.push(cleaned.to_string());
        if samples.len() >= MAX_SAMPLE_LINES {
            break;
        }
    }
    Ok(samples)
}

fn non_empty_line_count(path: &Path) -> AppResult<(i64, i64)> {
    let file = File::open(path)
        .map_err(|e| AppError::msg(format!("cannot open {}: {e}", path.display())))?;
    let reader = BufReader::new(file);
    let mut lines = 0i64;
    let mut hash_lines = 0i64;
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        lines += 1;
        if trimmed.starts_with('#') {
            hash_lines += 1;
        }
    }
    Ok((lines, hash_lines))
}

struct Candidate {
    format: Format,
    ratio: f64,
    strong: bool,
}

fn priority(format: Format) -> u8 {
    match format {
        Format::Suricata => 0,
        Format::Zeek => 1,
        Format::JsonArray => 2,
        Format::Ndjson => 3,
        Format::Firewall => 4,
        Format::LinuxAuth => 5,
        Format::WebAccess => 6,
        Format::Syslog => 7,
        Format::Csv => 8,
        Format::GenericText => 9,
    }
}

fn analyse_json(samples: &[String]) -> Option<Candidate> {
    let first = samples.first()?.trim_start();
    if first.starts_with('[') {
        return Some(Candidate {
            format: Format::JsonArray,
            ratio: 1.0,
            strong: true,
        });
    }
    if !first.starts_with('{') {
        return None;
    }
    let mut parsed = 0usize;
    let mut with_event_type = 0usize;
    for line in samples {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line.trim()) {
            parsed += 1;
            if value.get("event_type").is_some() {
                with_event_type += 1;
            }
        }
    }
    if parsed == 0 {
        return None;
    }
    let ratio = parsed as f64 / samples.len() as f64;
    if ratio < 0.6 {
        return None;
    }
    let format = if with_event_type * 2 >= parsed {
        Format::Suricata
    } else {
        Format::Ndjson
    };
    Some(Candidate {
        format,
        ratio,
        strong: ratio >= 0.98,
    })
}

fn analyse_zeek(samples: &[String]) -> Option<Candidate> {
    for line in samples.iter().take(10) {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#separator")
            || trimmed.starts_with("#fields")
            || trimmed.starts_with("#types")
        {
            return Some(Candidate {
                format: Format::Zeek,
                ratio: 1.0,
                strong: true,
            });
        }
    }
    None
}

fn ratio_of(samples: &[String], recognize: impl Fn(&str) -> bool) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let hits = samples.iter().filter(|line| recognize(line)).count();
    hits as f64 / samples.len() as f64
}

fn candidate_from_ratio(format: Format, ratio: f64, threshold: f64, strong_at: f64) -> Option<Candidate> {
    if ratio < threshold {
        return None;
    }
    Some(Candidate {
        format,
        ratio,
        strong: ratio >= strong_at,
    })
}

fn analyse_firewall(samples: &[String]) -> Option<Candidate> {
    let ratio = ratio_of(samples, |line| super::firewall::parse_line(line, 0).is_ok());
    candidate_from_ratio(Format::Firewall, ratio, 0.6, 0.98)
}

fn analyse_linux_auth(samples: &[String]) -> Option<Candidate> {
    let ratio = ratio_of(samples, |line| super::linux_auth::parse_line(line, 0).is_ok());
    candidate_from_ratio(Format::LinuxAuth, ratio, 0.5, 0.9)
}

fn analyse_web_access(samples: &[String]) -> Option<Candidate> {
    let ratio = ratio_of(samples, |line| super::web_access::parse_line(line, 0).is_ok());
    candidate_from_ratio(Format::WebAccess, ratio, 0.6, 0.98)
}

fn analyse_syslog(samples: &[String]) -> Option<Candidate> {
    let ratio = ratio_of(samples, |line| super::syslog::parse_line(line, 0).is_ok());
    candidate_from_ratio(Format::Syslog, ratio, 0.6, 0.98)
}

fn analyse_csv(samples: &[String]) -> Option<Candidate> {
    if samples.len() < 2 {
        return None;
    }
    const DELIMITERS: [char; 4] = [',', ';', '\t', '|'];
    for delimiter in DELIMITERS {
        let counts: Vec<usize> = samples
            .iter()
            .map(|line| super::csv_import::count_delimiter(line, delimiter))
            .collect();
        let first_count = match counts.first() {
            Some(count) => *count,
            None => continue,
        };
        if first_count == 0 {
            continue;
        }
        if counts.iter().any(|count| *count != first_count) {
            continue;
        }
        let text = samples.join("\n");
        let mut reader = csv::ReaderBuilder::new()
            .delimiter(delimiter as u8)
            .has_headers(false)
            .flexible(false)
            .from_reader(text.as_bytes());
        let mut rows = 0usize;
        let mut width = 0usize;
        let mut consistent = true;
        for record in reader.records() {
            match record {
                Ok(record) => {
                    rows += 1;
                    if width == 0 {
                        width = record.len();
                    }
                    if record.len() != width {
                        consistent = false;
                        break;
                    }
                }
                Err(_) => {
                    consistent = false;
                    break;
                }
            }
        }
        if !consistent || rows != samples.len() || width != first_count + 1 {
            continue;
        }
        let columns: Vec<String> = samples
            .first()
            .map(|line| line.split(delimiter).map(|cell| cell.trim().to_string()).collect())
            .unwrap_or_default();
        let has_header = super::csv_import::looks_like_header(&columns);
        return Some(Candidate {
            format: Format::Csv,
            ratio: 1.0,
            strong: has_header,
        });
    }
    None
}

/// Inspect a file and report what it is, with sample lines and warnings.
pub fn detect_full(path: &Path) -> AppResult<Detection> {
    if !path.is_file() {
        return Err(AppError::msg(format!(
            "file does not exist or is not a file: {}",
            path.display()
        )));
    }
    let samples = read_sample_lines(path)?;
    if samples.is_empty() {
        return Err(AppError::msg(format!(
            "cannot detect log format of empty file: {}",
            path.display()
        )));
    }
    let analysers: [fn(&[String]) -> Option<Candidate>; 7] = [
        analyse_json,
        analyse_zeek,
        analyse_firewall,
        analyse_linux_auth,
        analyse_web_access,
        analyse_syslog,
        analyse_csv,
    ];
    let mut candidates: Vec<Candidate> = Vec::new();
    for analyser in analysers {
        if let Some(candidate) = analyser(&samples) {
            candidates.push(candidate);
        }
    }
    candidates.sort_by(|a, b| {
        b.strong
            .cmp(&a.strong)
            .then_with(|| b.ratio.partial_cmp(&a.ratio).unwrap_or(std::cmp::Ordering::Equal))
            .then_with(|| priority(a.format).cmp(&priority(b.format)))
    });

    let mut warnings: Vec<String> = Vec::new();
    let (format, confidence) = match candidates.first() {
        Some(best) => {
            if let Some(second) = candidates.get(1) {
                if second.ratio >= 0.9
                    && (second.ratio - best.ratio).abs() <= 0.01
                    && second.strong == best.strong
                {
                    warnings.push(format!(
                        "ambiguous content: also resembles {}; chosen {}",
                        second.format.label(),
                        best.format.label()
                    ));
                }
            }
            let confidence = if best.strong || best.ratio >= 0.98 {
                "high"
            } else if best.ratio >= 0.6 {
                "medium"
            } else {
                "low"
            };
            (best.format, confidence.to_string())
        }
        None => (Format::GenericText, "low".to_string()),
    };

    if let Some(ext) = path.extension().and_then(|value| value.to_str()) {
        let ext_lower = ext.to_ascii_lowercase();
        let hint = match ext_lower.as_str() {
            "json" => Some(Format::JsonArray),
            "jsonl" | "ndjson" => Some(Format::Ndjson),
            "csv" | "tsv" => Some(Format::Csv),
            _ => None,
        };
        if let Some(hint) = hint {
            let compatible = hint == format
                || (format == Format::Suricata
                    && (hint == Format::JsonArray || hint == Format::Ndjson));
            if !compatible {
                warnings.push(format!(
                    "file extension .{ext_lower} is misleading; content looks like {}",
                    format.label()
                ));
            }
        }
    }

    if format == Format::GenericText {
        warnings.push(
            "no known format matched: importing as generic text, one record per line".to_string(),
        );
        if samples
            .iter()
            .all(|line| super::generic_text::extract_timestamp(line).is_none())
        {
            warnings.push("no timestamps found in the sample; records import with ts=0".to_string());
        }
    }

    let (non_empty, hash_lines) = non_empty_line_count(path)?;
    let estimated_records = match format {
        Format::JsonArray => None,
        Format::Zeek => Some((non_empty - hash_lines).max(0)),
        Format::Csv => Some((non_empty - 1).max(0)),
        _ => Some(non_empty),
    };
    let sample_lines = samples
        .iter()
        .take(12)
        .map(|line| truncate_line(line, 500))
        .collect();
    Ok(Detection {
        format,
        confidence,
        sample_lines,
        estimated_records,
        warnings,
    })
}

/// Detect the log format of a file from its content.
pub fn detect(path: &Path) -> AppResult<Format> {
    Ok(detect_full(path)?.format)
}

fn truncate_line(line: &str, max: usize) -> String {
    if line.chars().count() <= max {
        line.to_string()
    } else {
        let mut out: String = line.chars().take(max).collect();
        out.push_str("...");
        out
    }
}
