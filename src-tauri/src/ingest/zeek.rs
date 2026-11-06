//! Zeek TSV log parser (conn / dns / http / ssl / ssh and generic logs).
//!
//! Zeek writes a header block (#separator, #fields, #types, #path) followed by
//! tab (usually) separated records. Unset values are "-" or ".".

use super::normalize;
use super::RecordOutcome;
use crate::error::{AppError, AppResult};
use crate::types::NormalizedEvent;
use serde_json::{Map, Value};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

const UNMAPPED_BASE: &[&str] = &[
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
];

fn is_set(value: &str) -> bool {
    !(value.is_empty() || value == "-" || value == "." || value == "(empty)")
}

fn field<'a>(fields: &'a [String], values: &'a [String], name: &str) -> Option<&'a str> {
    let index = fields.iter().position(|f| f == name)?;
    values.get(index).map(|v| v.as_str()).filter(|v| is_set(v))
}

fn field_port(fields: &[String], values: &[String], name: &str) -> Option<i64> {
    field(fields, values, name).and_then(normalize::normalize_port)
}

fn field_ip(fields: &[String], values: &[String], name: &str) -> Option<String> {
    field(fields, values, name).and_then(normalize::normalize_ip)
}

fn column_map(fields: &[String], values: &[String], consumed: &[&str]) -> Value {
    let mut map = Map::new();
    for (name, value) in fields.iter().zip(values.iter()) {
        if consumed.contains(&name.as_str()) {
            continue;
        }
        map.insert(name.clone(), Value::String(value.clone()));
    }
    Value::Object(map)
}

fn attr_string(event: &mut NormalizedEvent, key: &str, value: Option<String>) {
    if let (Some(value), Some(attrs)) = (value, event.attrs.as_object_mut()) {
        attrs.insert(key.to_string(), Value::String(value));
    }
}

fn attr_raw<'a>(event: &mut NormalizedEvent, key: &str, value: Option<&'a str>) {
    if let (Some(value), Some(attrs)) = (value, event.attrs.as_object_mut()) {
        attrs.insert(key.to_string(), Value::String(value.to_string()));
    }
}

fn attr_i64(event: &mut NormalizedEvent, key: &str, value: Option<i64>) {
    if let (Some(value), Some(attrs)) = (value, event.attrs.as_object_mut()) {
        attrs.insert(key.to_string(), Value::Number(value.into()));
    }
}

fn consumed_for(kind: &str) -> Vec<&'static str> {
    let mut consumed: Vec<&'static str> = UNMAPPED_BASE.to_vec();
    let extra: &[&'static str] = match kind {
        "conn" => &[
            "duration",
            "orig_bytes",
            "resp_bytes",
            "conn_state",
            "history",
            "orig_pkts",
            "resp_pkts",
            "orig_ip_bytes",
            "resp_ip_bytes",
            "local_orig",
            "local_resp",
            "missed_bytes",
            "tunnel_parents",
        ],
        "dns" => &[
            "trans_id",
            "rtt",
            "query",
            "qclass",
            "qclass_name",
            "qtype",
            "qtype_name",
            "rcode",
            "rcode_name",
            "AA",
            "TC",
            "RD",
            "RA",
            "Z",
            "answers",
            "TTLs",
            "rejected",
        ],
        "http" => &[
            "trans_depth",
            "method",
            "host",
            "uri",
            "referrer",
            "version",
            "user_agent",
            "origin",
            "request_body_len",
            "response_body_len",
            "status_code",
            "status_msg",
            "info_code",
            "info_msg",
            "tags",
            "username",
            "password",
            "proxied",
        ],
        "ssl" => &[
            "version",
            "cipher",
            "curve",
            "server_name",
            "resumed",
            "last_alert",
            "next_protocol",
            "established",
            "cert_chain_fuids",
            "client_cert_chain_fuids",
            "subject",
            "issuer",
            "client_subject",
            "client_issuer",
            "validation_status",
            "ja3",
            "ja3s",
        ],
        "ssh" => &[
            "version",
            "auth_success",
            "auth_attempts",
            "direction",
            "client",
            "server",
            "cipher_alg",
            "mac_alg",
            "kex_alg",
            "host_key_alg",
            "host_key",
        ],
        _ => &[],
    };
    consumed.extend_from_slice(extra);
    consumed
}

/// Infer the Zeek log kind from the #path header or the file name.
pub fn infer_kind(path: &Path, header_path: Option<&str>) -> String {
    let raw = header_path
        .map(|s| s.to_string())
        .or_else(|| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_default()
        .to_ascii_lowercase();
    const KINDS: [&str; 16] = [
        "conn", "dns", "http", "ssl", "ssh", "weird", "notice", "files", "x509", "dhcp", "smtp",
        "ftp", "rdp", "ntp", "sip", "snmp",
    ];
    for kind in KINDS {
        if raw == kind
            || raw.ends_with(&format!("_{kind}"))
            || raw.contains(&format!("{kind}.log"))
            || raw.contains(&format!("{kind}_"))
            || raw.contains(&format!("-{kind}"))
        {
            return kind.to_string();
        }
    }
    "unknown".to_string()
}

/// Normalize one Zeek record. Kind is the log kind (conn, dns, http, ssl, ssh...).
pub fn normalize_record(
    kind: &str,
    fields: &[String],
    values: &[String],
) -> Result<NormalizedEvent, String> {
    let raw_ts = field(fields, values, "ts").ok_or_else(|| "missing timestamp field".to_string())?;
    let ts = normalize::parse_timestamp(raw_ts, None)
        .ok_or_else(|| format!("unparsable timestamp: {raw_ts}"))?;

    let mut event = NormalizedEvent::new(ts, "zeek");
    event.event_type = Some(kind.to_string());
    event.src_ip = field_ip(fields, values, "id.orig_h");
    event.dst_ip = field_ip(fields, values, "id.resp_h");
    event.src_port = field_port(fields, values, "id.orig_p");
    event.dst_port = field_port(fields, values, "id.resp_p");
    event.transport = field(fields, values, "proto").and_then(|s| normalize::normalize_transport(s));
    event.attrs = column_map(fields, values, &consumed_for(kind));

    let mut raw_map = Map::new();
    for (name, value) in fields.iter().zip(values.iter()) {
        raw_map.insert(name.clone(), Value::String(value.clone()));
    }
    event.raw = Value::Object(raw_map);

    match kind {
        "conn" => {
            event.category = Some("network".to_string());
            let conn_state = field(fields, values, "conn_state").unwrap_or("");
            let action = match conn_state {
                "S0" | "REJ" | "RSTO" | "RSTOS0" => "failed",
                _ => "allowed",
            };
            event.action = Some(action.to_string());
            event.app_proto = field(fields, values, "service").map(|s| s.to_string());
            attr_raw(&mut event, "connState", Some(conn_state));
            attr_string(
                &mut event,
                "service",
                field(fields, values, "service").map(|s| s.to_string()),
            );
            attr_raw(&mut event, "history", field(fields, values, "history"));
            attr_raw(&mut event, "duration", field(fields, values, "duration"));
            attr_i64(
                &mut event,
                "origBytes",
                field(fields, values, "orig_bytes").and_then(|s| s.parse().ok()),
            );
            attr_i64(
                &mut event,
                "respBytes",
                field(fields, values, "resp_bytes").and_then(|s| s.parse().ok()),
            );
            attr_i64(
                &mut event,
                "origPkts",
                field(fields, values, "orig_pkts").and_then(|s| s.parse().ok()),
            );
            attr_i64(
                &mut event,
                "respPkts",
                field(fields, values, "resp_pkts").and_then(|s| s.parse().ok()),
            );
        }
        "dns" => {
            event.category = Some("dns".to_string());
            let answers = field(fields, values, "answers");
            let is_response = answers.is_some();
            event.event_type = Some(if is_response { "response" } else { "query" }.to_string());
            let query = field(fields, values, "query").map(|s| s.to_string());
            if let Some(name) = &query {
                event.hostname = Some(name.trim().trim_end_matches('.').to_string());
                event.message = Some(format!(
                    "DNS {} {name}",
                    event.event_type.clone().unwrap_or_default()
                ));
            }
            attr_string(&mut event, "dnsQuery", query);
            let rcode = field(fields, values, "rcode_name")
                .or_else(|| field(fields, values, "rcode"))
                .map(|s| s.trim().to_ascii_uppercase());
            attr_string(&mut event, "dnsRcode", rcode);
            attr_string(
                &mut event,
                "dnsType",
                field(fields, values, "qtype_name").map(|s| s.to_string()),
            );
            attr_raw(&mut event, "answers", answers);
        }
        "http" => {
            event.category = Some("http".to_string());
            let host = field(fields, values, "host").map(|s| s.to_string());
            let uri = field(fields, values, "uri").map(|s| s.to_string());
            let method = field(fields, values, "method").map(|s| s.to_string());
            event.hostname = host.clone();
            let status = field(fields, values, "status_code").and_then(|s| s.parse::<i64>().ok());
            if method.is_some() || uri.is_some() {
                event.message = Some(format!(
                    "{} {}",
                    method.clone().unwrap_or_else(|| "HTTP".to_string()),
                    uri.clone().unwrap_or_else(|| "/".to_string())
                ));
            }
            attr_string(&mut event, "host", host);
            attr_string(&mut event, "uri", uri);
            attr_string(&mut event, "method", method);
            attr_i64(&mut event, "status", status);
            attr_string(
                &mut event,
                "userAgent",
                field(fields, values, "user_agent").map(|s| s.to_string()),
            );
            attr_string(
                &mut event,
                "referrer",
                field(fields, values, "referrer").map(|s| s.to_string()),
            );
        }
        "ssl" | "tls" => {
            event.category = Some("tls".to_string());
            event.event_type = Some("ssl".to_string());
            let sni = field(fields, values, "server_name").map(|s| s.to_string());
            event.hostname = sni.clone();
            if let Some(name) = &sni {
                event.message = Some(format!("TLS {name}"));
            }
            attr_string(&mut event, "sni", sni);
            attr_string(
                &mut event,
                "version",
                field(fields, values, "version").map(|s| s.to_string()),
            );
            attr_string(
                &mut event,
                "cipher",
                field(fields, values, "cipher").map(|s| s.to_string()),
            );
            attr_string(
                &mut event,
                "subject",
                field(fields, values, "subject").map(|s| s.to_string()),
            );
            attr_string(
                &mut event,
                "issuer",
                field(fields, values, "issuer").map(|s| s.to_string()),
            );
            attr_string(
                &mut event,
                "validationStatus",
                field(fields, values, "validation_status").map(|s| s.to_string()),
            );
            attr_string(&mut event, "ja3", field(fields, values, "ja3").map(|s| s.to_string()));
        }
        "ssh" => {
            event.category = Some("authentication".to_string());
            event.app_proto = Some("ssh".to_string());
            let success = field(fields, values, "auth_success");
            let action = match success {
                Some("T") | Some("true") | Some("1") => Some("success"),
                Some("F") | Some("false") | Some("0") => Some("failed"),
                _ => None,
            };
            event.action = action.map(|s| s.to_string());
            event.username = field(fields, values, "user").map(|s| s.to_string());
            let user = event.username.clone().unwrap_or_else(|| "unknown".to_string());
            event.message = Some(format!(
                "SSH authentication {} for user {}",
                event.action.clone().unwrap_or_else(|| "attempt".to_string()),
                user
            ));
            attr_raw(&mut event, "authSuccess", success);
            attr_i64(
                &mut event,
                "authAttempts",
                field(fields, values, "auth_attempts").and_then(|s| s.parse().ok()),
            );
            attr_string(
                &mut event,
                "client",
                field(fields, values, "client").map(|s| s.to_string()),
            );
            attr_string(
                &mut event,
                "server",
                field(fields, values, "server").map(|s| s.to_string()),
            );
        }
        _ => {
            event.category = Some("other".to_string());
        }
    }
    Ok(event)
}

/// Stream a Zeek TSV log. Header lines start with '#'.
pub fn stream(
    path: &Path,
    sink: &mut dyn FnMut(i64, RecordOutcome) -> AppResult<()>,
) -> AppResult<()> {
    let file = File::open(path)
        .map_err(|e| AppError::msg(format!("cannot open {}: {e}", path.display())))?;
    let reader = BufReader::new(file);
    let mut separator = '\t';
    let mut fields: Vec<String> = Vec::new();
    let mut header_path: Option<String> = None;
    let mut kind_cache: Option<String> = None;
    let mut index = 0i64;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('#') {
            if let Some(spec) = rest.strip_prefix("separator") {
                if let Some(sep) = decode_separator(spec.trim()) {
                    separator = sep;
                }
            } else if let Some(spec) = rest.strip_prefix("fields") {
                let spec = spec.strip_prefix(separator).unwrap_or(spec);
                fields = split_line(spec, separator);
            } else if let Some(spec) = rest.strip_prefix("path") {
                let value = spec.trim();
                if !value.is_empty() {
                    header_path = Some(value.to_string());
                }
            }
            continue;
        }
        if fields.is_empty() {
            return Err(AppError::msg(format!(
                "{}: Zeek data row before #fields header (not a Zeek TSV log)",
                path.display()
            )));
        }
        index += 1;
        let values = split_line(&line, separator);
        if values.len() != fields.len() {
            sink(
                index,
                Err(format!(
                    "expected {} Zeek columns, found {}",
                    fields.len(),
                    values.len()
                )),
            )?;
            continue;
        }
        let kind = kind_cache
            .get_or_insert_with(|| infer_kind(path, header_path.as_deref()))
            .clone();
        sink(index, normalize_record(&kind, &fields, &values))?;
    }
    Ok(())
}

fn split_line(line: &str, separator: char) -> Vec<String> {
    line.split(separator).map(|s| s.to_string()).collect()
}

/// Decode a Zeek #separator value such as the literal text \x09 or a real tab.
fn decode_separator(spec: &str) -> Option<char> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    if let Some(hex) = spec.strip_prefix("\\x") {
        let end = hex
            .char_indices()
            .take(2)
            .last()
            .map(|(i, c)| i + c.len_utf8())?;
        let byte = u8::from_str_radix(&hex[..end], 16).ok()?;
        return char::from_u32(byte as u32);
    }
    spec.chars().next()
}
