//! Generic JSON / NDJSON parsers: any object stream is mapped onto NormalizedEvent.

use super::normalize;
use super::RecordOutcome;
use crate::error::AppResult;
use crate::types::NormalizedEvent;
use serde_json::Value;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

const TIMESTAMP_PATHS: &[&str] = &[
    "ts",
    "timestamp",
    "@timestamp",
    "time",
    "event_time",
    "eventtime",
    "datetime",
    "date",
];

const CONSUMED_KEYS: &[&str] = &[
    "ts",
    "timestamp",
    "@timestamp",
    "time",
    "event_time",
    "eventtime",
    "datetime",
    "date",
    "src_ip",
    "source_ip",
    "srcip",
    "src_addr",
    "src",
    "source",
    "dst_ip",
    "dest_ip",
    "destination_ip",
    "dstip",
    "dst_addr",
    "dst",
    "destination",
    "src_port",
    "source_port",
    "srcport",
    "sport",
    "sp",
    "dst_port",
    "dest_port",
    "destination_port",
    "dstport",
    "dport",
    "dp",
    "transport",
    "proto",
    "protocol",
    "app_proto",
    "appproto",
    "service",
    "application",
    "action",
    "event_action",
    "outcome",
    "username",
    "user",
    "user_name",
    "account",
    "hostname",
    "host",
    "dest_host",
    "dst_host",
    "process_name",
    "process",
    "image",
    "exe",
    "message",
    "msg",
    "description",
    "summary",
    "severity",
    "level",
    "priority",
    "category",
    "event_category",
    "event_type",
    "eventtype",
    "event_name",
    "type",
];

/// Normalize one generic JSON object.
pub fn normalize_record(record: &Value, source_type: &str) -> Result<NormalizedEvent, String> {
    if !record.is_object() {
        return Err("record is not a JSON object".to_string());
    }
    let ts = normalize::lookup_timestamp(record, TIMESTAMP_PATHS)
        .ok_or_else(|| "missing or unparsable timestamp".to_string())?;
    let mut event = NormalizedEvent::new(ts, source_type);
    event.category = normalize::lookup_str(record, &["category", "event_category", "cat"]);
    event.event_type = normalize::lookup_str(
        record,
        &["event_type", "eventtype", "event_name", "type"],
    );
    event.severity = normalize::lookup_str(record, &["severity", "level", "priority"])
        .and_then(|s| normalize::normalize_severity(&s))
        .unwrap_or_else(|| "info".to_string());
    event.src_ip = normalize::lookup_str(
        record,
        &[
            "src_ip",
            "source_ip",
            "srcip",
            "src_addr",
            "src",
            "source",
            "source.ip",
            "id.orig_h",
        ],
    )
    .and_then(|s| normalize::normalize_ip(&s));
    event.dst_ip = normalize::lookup_str(
        record,
        &[
            "dst_ip",
            "dest_ip",
            "destination_ip",
            "dstip",
            "dst_addr",
            "dst",
            "destination",
            "destination.ip",
            "id.resp_h",
        ],
    )
    .and_then(|s| normalize::normalize_ip(&s));
    event.src_port = normalize::lookup_i64(
        record,
        &["src_port", "source_port", "srcport", "sport", "sp", "id.orig_p"],
    )
    .and_then(normalize::valid_port);
    event.dst_port = normalize::lookup_i64(
        record,
        &[
            "dst_port",
            "dest_port",
            "destination_port",
            "dstport",
            "dport",
            "dp",
            "id.resp_p",
        ],
    )
    .and_then(normalize::valid_port);
    event.transport = normalize::lookup_str(record, &["transport", "proto", "protocol"])
        .and_then(|s| normalize::normalize_transport(&s));
    event.app_proto = normalize::lookup_str(record, &["app_proto", "appproto", "service", "application"]);
    event.action = normalize::lookup_str(record, &["action", "event_action", "outcome"])
        .and_then(|s| normalize::normalize_action(&s));
    event.username = normalize::lookup_str(record, &["username", "user", "user_name", "account"]);
    event.hostname = normalize::lookup_str(record, &["hostname", "host", "dest_host", "dst_host"]);
    event.process_name = normalize::lookup_str(record, &["process_name", "process", "image", "exe"]);
    event.message = normalize::lookup_str(record, &["message", "msg", "description", "summary"]);
    event.attrs = normalize::object_without(record, CONSUMED_KEYS);
    event.raw = record.clone();
    Ok(event)
}

fn normalize_any(record: &Value, source_type: &str) -> Result<NormalizedEvent, String> {
    // Format detection already decided this is generic JSON, so an event_type
    // field here is user data, not a Suricata EVE marker.
    normalize_record(record, source_type)
}

/// Stream a JSON document that holds an array of records.
pub fn stream_array(
    path: &Path,
    source_type: &str,
    sink: &mut dyn FnMut(i64, RecordOutcome) -> AppResult<()>,
) -> AppResult<()> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| crate::error::AppError::msg(format!("cannot read {}: {e}", path.display())))?;
    let document: Value = serde_json::from_str(&text)
        .map_err(|e| crate::error::AppError::msg(format!("invalid JSON document: {e}")))?;
    let records = match document {
        Value::Array(items) => items,
        Value::Object(map) => vec![Value::Object(map)],
        _ => {
            return Err(crate::error::AppError::msg(
                "JSON document must contain an array of objects",
            ))
        }
    };
    let mut index = 0i64;
    for record in records {
        index += 1;
        sink(index, normalize_any(&record, source_type))?;
    }
    Ok(())
}

/// Stream newline-delimited JSON. Blank lines are ignored; every other line is a record.
pub fn stream_ndjson(
    path: &Path,
    source_type: &str,
    sink: &mut dyn FnMut(i64, RecordOutcome) -> AppResult<()>,
) -> AppResult<()> {
    let file = File::open(path)
        .map_err(|e| crate::error::AppError::msg(format!("cannot open {}: {e}", path.display())))?;
    let reader = BufReader::new(file);
    let mut index = 0i64;
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        index += 1;
        let outcome = match serde_json::from_str::<Value>(trimmed) {
            Ok(record) => normalize_any(&record, source_type),
            Err(e) => Err(format!("invalid JSON: {e}")),
        };
        sink(index, outcome)?;
    }
    Ok(())
}
