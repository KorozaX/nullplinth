//! CSV import wizard backend: delimiter detection, preview and mapping-driven parsing.
//!
//! The frontend asks for preview_csv(), lets the user map columns, then calls
//! import() with an explicit CsvMapping. Nothing here guesses a mapping.

use super::normalize;
use super::RecordOutcome;
use crate::error::{AppError, AppResult};
use crate::types::{CsvMapping, CsvPreview, NormalizedEvent};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

pub const MAX_PREVIEW_ROWS: usize = 50;
const CANDIDATE_DELIMITERS: [char; 4] = [',', ';', '\t', '|'];
const HEADER_HINTS: &[&str] = &[
    "ts", "timestamp", "time", "datetime", "date", "src", "srcip", "source", "sourceip", "dst",
    "dest", "destination", "sport", "dport", "srcport", "dstport", "action", "user", "username",
    "host", "hostname", "severity", "message", "msg", "proto", "protocol", "event", "category",
    "process", "pid", "bytes", "port", "service", "duration", "status",
];

/// Turn a configured delimiter string into a byte accepted by the csv crate.
pub fn delimiter_byte(spec: &str) -> AppResult<u8> {
    let trimmed = spec.trim();
    let resolved = match trimmed {
        "" => ",",
        "\\t" | "tab" | "TAB" | "\\x09" => "\t",
        other => other,
    };
    let first = resolved
        .chars()
        .next()
        .ok_or_else(|| AppError::msg("empty CSV delimiter"))?;
    if !first.is_ascii() {
        return Err(AppError::msg(format!(
            "CSV delimiter must be an ASCII character, got {first:?}"
        )));
    }
    Ok(first as u8)
}

/// Count one delimiter outside quoted strings. Format detection reuses this.
pub(crate) fn count_delimiter(line: &str, delimiter: char) -> usize {
    let mut in_quotes = false;
    let mut count = 0usize;
    for ch in line.chars() {
        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }
        if in_quotes {
            continue;
        }
        if ch == delimiter {
            count += 1;
        }
    }
    count
}

fn count_delimiters(line: &str, counts: &mut [usize; 4]) {
    for (position, delimiter) in CANDIDATE_DELIMITERS.iter().enumerate() {
        counts[position] += count_delimiter(line, *delimiter);
    }
}

/// Detect the delimiter by counting , ; tab | outside quoted strings.
pub fn detect_delimiter(path: &Path) -> AppResult<char> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| AppError::msg(format!("cannot read {}: {e}", path.display())))?;
    let mut totals = [0usize; 4];
    let mut seen = 0usize;
    let mut checked = HashSet::new();
    let mut index = 0usize;
    for line in text.lines().take(200) {
        if line.trim().is_empty() {
            continue;
        }
        seen += 1;
        let mut line_counts = [0usize; 4];
        count_delimiters(line, &mut line_counts);
        for (position, count) in line_counts.iter().enumerate() {
            totals[position] += count;
            if *count > 0 {
                checked.insert(position);
            }
        }
        index += 1;
        if seen >= 20 {
            break;
        }
    }
    let _ = index;
    if checked.is_empty() {
        return Ok(',');
    }
    let mut best_position = 0usize;
    let mut best = totals[0];
    for position in 1..4 {
        if checked.contains(&position) && totals[position] > best {
            best = totals[position];
            best_position = position;
        }
    }
    if !checked.contains(&best_position) {
        best_position = *checked.iter().next().unwrap_or(&0);
    }
    Ok(CANDIDATE_DELIMITERS[best_position])
}

fn canonical_key(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Heuristic: a header row holds names, not values.
pub(crate) fn looks_like_header(row: &[String]) -> bool {
    if row.iter().any(|cell| {
        let key = canonical_key(cell);
        HEADER_HINTS
            .iter()
            .any(|hint| canonical_key(hint) == key)
    }) {
        return true;
    }
    let has_value = row.iter().any(|cell| {
        let trimmed = cell.trim();
        if trimmed.is_empty() {
            return false;
        }
        trimmed.parse::<f64>().is_ok()
            || normalize::normalize_ip(trimmed).is_some()
            || normalize::parse_timestamp(trimmed, None).is_some()
    });
    !has_value
}

/// Column aliases used to pre-fill the import wizard mapping (users can override).
const SUGGESTED_FIELDS: [(&str, &[&str]); 15] = [
    (
        "timestamp",
        &[
            "ts", "time", "timestamp", "datetime", "eventtime", "timegenerated", "logtime",
            "date", "occurred", "when", "insertionstring",
        ],
    ),
    (
        "srcIp",
        &[
            "srcip", "sourceip", "src", "source", "srcaddr", "sourceaddress", "clientip",
            "ipaddress", "client", "ip",
        ],
    ),
    (
        "dstIp",
        &[
            "dstip", "destip", "destinationip", "dst", "dest", "destination", "dstaddr",
            "destinationaddress", "serverip", "server",
        ],
    ),
    ("srcPort", &["srcport", "sourceport", "sport"]),
    (
        "dstPort",
        &["dstport", "destport", "destinationport", "dport", "port", "portnumber"],
    ),
    ("transport", &["transport", "proto", "protocol"]),
    ("appProto", &["appproto", "service", "application"]),
    (
        "action",
        &["action", "eventaction", "outcome", "decision", "verdict"],
    ),
    (
        "username",
        &["username", "user", "userid", "account", "subjectusername"],
    ),
    (
        "hostname",
        &[
            "hostname", "host", "workstation", "computername", "computer", "device",
        ],
    ),
    (
        "processName",
        &["processname", "process", "image", "applicationname", "program"],
    ),
    (
        "message",
        &["message", "msg", "description", "detail", "summary", "eventdescription"],
    ),
    ("severity", &["severity", "level", "priority"]),
    ("category", &["category", "eventcategory"]),
    (
        "eventType",
        &["eventtype", "eventname", "type"],
    ),
];

/// Guess a normalized-field -> column mapping from common header aliases.
pub(crate) fn suggest_mapping(columns: &[String]) -> HashMap<String, String> {
    let mut mapping: HashMap<String, String> = HashMap::new();
    for column in columns {
        let key = canonical_key(column);
        if key.is_empty() {
            continue;
        }
        for (field, aliases) in SUGGESTED_FIELDS.iter() {
            if mapping.contains_key(*field) {
                continue;
            }
            if aliases.iter().any(|alias| canonical_key(alias) == key) {
                mapping.insert((*field).to_string(), column.trim().to_string());
                break;
            }
        }
    }
    mapping
}

fn open_without_bom(path: &Path) -> AppResult<File> {
    let mut file = File::open(path)?;
    let mut head = [0u8; 3];
    let read = file.read(&mut head)?;
    let offset = if read == 3 && head == [0xEF, 0xBB, 0xBF] { 3 } else { 0 };
    file.seek(SeekFrom::Start(offset as u64))?;
    Ok(file)
}

fn count_data_lines(path: &Path, has_header: bool) -> AppResult<i64> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut total = 0i64;
    for line in reader.lines() {
        let line = line?;
        if !line.trim().is_empty() {
            total += 1;
        }
    }
    Ok((total - if has_header { 1 } else { 0 }).max(0))
}

/// Read the first rows of a CSV file for the import wizard.
pub fn preview(path: &str) -> AppResult<CsvPreview> {
    let file_path = Path::new(path);
    if !file_path.is_file() {
        return Err(AppError::msg(format!("file does not exist: {path}")));
    }
    let delimiter = detect_delimiter(file_path)?;
    let file = open_without_bom(file_path)?;
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter as u8)
        .has_headers(false)
        .flexible(true)
        .from_reader(file);

    let mut rows: Vec<Vec<String>> = Vec::new();
    for record in reader.records() {
        let record = match record {
            Ok(record) => record,
            Err(e) => {
                return Err(AppError::msg(format!(
                    "invalid CSV near row {}: {e}",
                    rows.len() + 1
                )))
            }
        };
        rows.push(record.iter().map(|cell| cell.to_string()).collect());
        if rows.len() >= MAX_PREVIEW_ROWS + 1 {
            break;
        }
    }
    if rows.is_empty() {
        return Err(AppError::msg("CSV file contains no rows"));
    }
    let width = rows.iter().map(|row| row.len()).max().unwrap_or(0);
    if width == 0 {
        return Err(AppError::msg("CSV file contains no columns"));
    }
    for row in rows.iter_mut() {
        row.resize(width, String::new());
    }
    if let Some(cell) = rows[0].first_mut() {
        *cell = normalize::strip_bom(cell).to_string();
    }
    let has_header = looks_like_header(&rows[0]);
    let columns: Vec<String> = if has_header {
        rows[0].clone()
    } else {
        (1..=width).map(|i| format!("column_{i}")).collect()
    };
    let data_rows: Vec<Vec<String>> = if has_header {
        rows.split_off(1)
    } else {
        rows
    };
    let mut data_rows = data_rows;
    data_rows.truncate(MAX_PREVIEW_ROWS);
    let suggested_mapping = if has_header {
        suggest_mapping(&columns)
    } else {
        HashMap::new()
    };
    let estimated_rows = count_data_lines(file_path, has_header)?;
    Ok(CsvPreview {
        suggested_mapping,
        estimated_rows: Some(estimated_rows),
        columns,
        rows: data_rows,
        detected_delimiter: delimiter.to_string(),
        has_header,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    SrcIp,
    DstIp,
    SrcPort,
    DstPort,
    Transport,
    AppProto,
    Action,
    Username,
    Hostname,
    ProcessName,
    Message,
    Severity,
    Category,
    EventType,
}

/// Map a mapping key (camelCase or snake_case) to a normalized field.
fn canonical_field(key: &str) -> Option<Field> {
    let field = match key {
        "srcip" | "sourceip" | "srcaddr" | "src" | "source" => Field::SrcIp,
        "dstip" | "destip" | "destinationip" | "dstaddr" | "dst" | "dest" | "destination" => {
            Field::DstIp
        }
        "srcport" | "sourceport" | "sport" | "sp" => Field::SrcPort,
        "dstport" | "destport" | "destinationport" | "dport" | "dp" => Field::DstPort,
        "transport" | "proto" | "protocol" => Field::Transport,
        "appproto" | "app" | "service" | "application" => Field::AppProto,
        "action" | "eventaction" | "outcome" => Field::Action,
        "username" | "user" | "account" => Field::Username,
        "hostname" | "host" | "dnshost" | "desthost" => Field::Hostname,
        "processname" | "process" | "image" | "exe" => Field::ProcessName,
        "message" | "msg" | "description" | "summary" => Field::Message,
        "severity" | "level" | "priority" => Field::Severity,
        "category" | "eventcategory" => Field::Category,
        "eventtype" | "type" | "eventname" => Field::EventType,
        _ => return None,
    };
    Some(field)
}

fn column_index(headers: &[String], name: &str) -> Option<usize> {
    let target = name.trim();
    headers
        .iter()
        .position(|header| header.trim().eq_ignore_ascii_case(target))
}

fn build_plan(headers: &[String], mapping: &CsvMapping) -> (Option<usize>, Vec<(usize, Field)>) {
    let mut ts_index = None;
    if let Some(column) = &mapping.timestamp_column {
        ts_index = column_index(headers, column);
    }
    let mut mapped: Vec<(usize, Field)> = Vec::new();
    for (key, column) in &mapping.column_map {
        let Some(index) = column_index(headers, column) else {
            continue;
        };
        let canonical = canonical_key(key);
        if matches!(canonical.as_str(), "ts" | "timestamp" | "time" | "datetime") {
            if ts_index.is_none() {
                ts_index = Some(index);
            }
            continue;
        }
        if let Some(field) = canonical_field(&canonical) {
            mapped.push((index, field));
        }
    }
    mapped.sort_by_key(|(index, _)| *index);
    (ts_index, mapped)
}

fn normalize_row(
    headers: &[String],
    row: &[String],
    ts_index: usize,
    mapped: &[(usize, Field)],
    timestamp_format: Option<&str>,
) -> Result<NormalizedEvent, String> {
    let cell = |index: usize| row.get(index).map(|s| s.trim()).unwrap_or("");
    let raw_ts = cell(ts_index);
    if raw_ts.is_empty() {
        return Err("empty timestamp value".to_string());
    }
    let ts = normalize::parse_timestamp(raw_ts, timestamp_format)
        .ok_or_else(|| format!("unparsable timestamp '{raw_ts}'"))?;

    let mut event = NormalizedEvent::new(ts, "csv");
    let mut used: HashSet<usize> = HashSet::new();
    used.insert(ts_index);
    for (index, field) in mapped {
        used.insert(*index);
        let value = cell(*index);
        if value.is_empty() || value == "-" || value == "." {
            continue;
        }
        match field {
            Field::SrcIp => event.src_ip = normalize::normalize_ip(value),
            Field::DstIp => event.dst_ip = normalize::normalize_ip(value),
            Field::SrcPort => event.src_port = normalize::normalize_port(value),
            Field::DstPort => event.dst_port = normalize::normalize_port(value),
            Field::Transport => event.transport = normalize::normalize_transport(value),
            Field::AppProto => event.app_proto = Some(value.to_ascii_lowercase()),
            Field::Action => {
                event.action = normalize::normalize_action(value)
                    .or_else(|| Some(value.to_ascii_lowercase()))
            }
            Field::Username => event.username = Some(value.to_string()),
            Field::Hostname => event.hostname = Some(value.to_string()),
            Field::ProcessName => event.process_name = Some(value.to_string()),
            Field::Message => event.message = Some(value.to_string()),
            Field::Severity => {
                event.severity = normalize::normalize_severity(value)
                    .unwrap_or_else(|| "info".to_string())
            }
            Field::Category => event.category = Some(value.to_string()),
            Field::EventType => event.event_type = Some(value.to_string()),
        }
    }

    let mut attrs = Map::new();
    for (index, header) in headers.iter().enumerate() {
        if used.contains(&index) {
            continue;
        }
        let value = cell(index);
        if value.is_empty() {
            continue;
        }
        attrs.insert(header.clone(), Value::String(value.to_string()));
    }

    let mut raw = Map::new();
    for (header, value) in headers.iter().zip(row.iter()) {
        raw.insert(header.clone(), Value::String(value.clone()));
    }
    if row.len() > headers.len() {
        for (offset, value) in row[headers.len()..].iter().enumerate() {
            raw.insert(format!("extra_{}", offset + 1), Value::String(value.clone()));
        }
    }
    event.attrs = Value::Object(attrs);
    event.raw = Value::Object(raw);
    Ok(event)
}

/// Stream a CSV file using an explicit mapping. One bad row never stops the rest.
pub fn stream(
    path: &Path,
    mapping: &CsvMapping,
    sink: &mut dyn FnMut(i64, RecordOutcome) -> AppResult<()>,
) -> AppResult<()> {
    let delimiter = delimiter_byte(&mapping.delimiter)?;
    let file = open_without_bom(path)?;
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter)
        .has_headers(false)
        .flexible(true)
        .from_reader(file);

    let mut headers: Vec<String> = Vec::new();
    let mut ts_index: Option<usize> = None;
    let mut mapped: Vec<(usize, Field)> = Vec::new();
    let timestamp_format = mapping.timestamp_format.clone();
    let mut index = 0i64;

    for record in reader.records() {
        let record = match record {
            Ok(record) => record,
            Err(e) => {
                index += 1;
                sink(index, Err(format!("invalid CSV record: {e}")))?;
                continue;
            }
        };
        let mut row: Vec<String> = record.iter().map(|cell| cell.to_string()).collect();
        if let Some(cell) = row.first_mut() {
            *cell = normalize::strip_bom(cell).to_string();
        }
        if row.iter().all(|cell| cell.trim().is_empty()) {
            continue;
        }
        if headers.is_empty() {
            if mapping.has_header {
                headers = row;
                let (ts, plan) = build_plan(&headers, mapping);
                if ts.is_none() {
                    return Err(AppError::msg(
                        "CSV mapping does not reference a timestamp column (set timestampColumn or map ts)",
                    ));
                }
                ts_index = ts;
                mapped = plan;
                continue;
            }
            headers = (1..=row.len()).map(|i| format!("column_{i}")).collect();
            let (ts, plan) = build_plan(&headers, mapping);
            if ts.is_none() {
                return Err(AppError::msg(
                    "CSV mapping does not reference a timestamp column (set timestampColumn or map ts)",
                ));
            }
            ts_index = ts;
            mapped = plan;
        }
        let ts_column = match ts_index {
            Some(value) => value,
            None => return Err(AppError::msg("CSV mapping has no timestamp column")),
        };
        index += 1;
        let outcome = normalize_row(
            &headers,
            &row,
            ts_column,
            &mapped,
            timestamp_format.as_deref(),
        );
        sink(index, outcome)?;
    }
    if index == 0 {
        return Err(AppError::msg("CSV file contains no data records"));
    }
    Ok(())
}