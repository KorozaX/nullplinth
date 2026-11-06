//! Suricata EVE JSON parser: alert / dns / http / tls / flow / anomaly / ssh / fileinfo.
//!
//! Detection contract (shared with the detection engine):
//!   * alert  -> category "alert", severity from alert.severity 1=high 2=medium 3=low
//!   * dns    -> category "dns", event_type query|response, attrs.dnsQuery, attrs.dnsRcode
//!   * flow   -> category "network", action "allowed", transport set
//!   * anomaly-> category "anomaly"
//!   * ssh    -> category "authentication"

use super::normalize;
use super::RecordOutcome;
use crate::error::{AppError, AppResult};
use crate::types::NormalizedEvent;
use serde_json::{Map, Value};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Top-level EVE keys already mapped onto columns (kept out of attrs).
const CONSUMED_KEYS: &[&str] = &[
    "ts",
    "event_type",
    "src_ip",
    "src_port",
    "dest_ip",
    "dst_ip",
    "dest_port",
    "dst_port",
    "proto",
    "app_proto",
    "hostname",
    "action",
    "flow_id",
    "pcap_cnt",
    "vlan",
    "tx_id",
];

fn attr_string(event: &mut NormalizedEvent, key: &str, value: Option<String>) {
    if let (Some(value), Some(attrs)) = (value, event.attrs.as_object_mut()) {
        attrs.insert(key.to_string(), Value::String(value));
    }
}

fn attr_i64(event: &mut NormalizedEvent, key: &str, value: Option<i64>) {
    if let (Some(value), Some(attrs)) = (value, event.attrs.as_object_mut()) {
        attrs.insert(key.to_string(), Value::Number(value.into()));
    }
}

fn dns_rcode(record: &Value) -> Option<String> {
    let raw = normalize::lookup_str(record, &["dns.rcode", "rcode"])?;
    let upper = raw.trim().to_ascii_uppercase();
    let mapped = match upper.as_str() {
        "NOERROR" | "0" => "NOERROR",
        "FORMERR" | "1" => "FORMERR",
        "SERVFAIL" | "2" => "SERVFAIL",
        "NXDOMAIN" | "3" => "NXDOMAIN",
        "NOTIMP" | "4" => "NOTIMP",
        "REFUSED" | "5" => "REFUSED",
        other => other,
    };
    Some(mapped.to_string())
}

fn trim_dot(name: &str) -> String {
    name.trim().trim_end_matches('.').to_string()
}

/// Normalize a single Suricata EVE record.
pub fn normalize_record(record: &Value) -> Result<NormalizedEvent, String> {
    if !record.is_object() {
        return Err("record is not a JSON object".to_string());
    }
    let ts = normalize::lookup_timestamp(record, &["ts", "timestamp", "time"])
        .ok_or_else(|| "missing or unparsable timestamp".to_string())?;
    let event_type = normalize::lookup_str(record, &["event_type"])
        .ok_or_else(|| "missing event_type (not a Suricata EVE record)".to_string())?;

    let mut event = NormalizedEvent::new(ts, "suricata");
    event.event_type = Some(event_type.clone());
    event.src_ip = normalize::lookup_str(record, &["src_ip", "source_ip"])
        .and_then(|s| normalize::normalize_ip(&s));
    event.dst_ip = normalize::lookup_str(record, &["dest_ip", "dst_ip", "destination_ip"])
        .and_then(|s| normalize::normalize_ip(&s));
    event.src_port = normalize::lookup_i64(record, &["src_port", "source_port"])
        .and_then(normalize::valid_port);
    event.dst_port = normalize::lookup_i64(record, &["dest_port", "dst_port"])
        .and_then(normalize::valid_port);
    event.transport = normalize::lookup_str(record, &["proto", "protocol"])
        .and_then(|s| normalize::normalize_transport(&s));
    event.app_proto = normalize::lookup_str(record, &["app_proto"]);
    event.action = normalize::lookup_str(record, &["action", "event_action"])
        .and_then(|s| normalize::normalize_action(&s));
    event.attrs = normalize::object_without(record, CONSUMED_KEYS);
    if event.attrs.as_object().is_none() {
        event.attrs = Value::Object(Map::new());
    }
    event.raw = record.clone();

    match event_type.as_str() {
        "alert" => {
            event.category = Some("alert".to_string());
            let level = normalize::lookup_i64(record, &["alert.severity", "severity"]).unwrap_or(0);
            let severity = if level > 0 {
                normalize::suricata_severity(level).to_string()
            } else {
                normalize::lookup_str(record, &["alert.severity", "severity", "level"])
                    .and_then(|s| normalize::normalize_severity(&s))
                    .unwrap_or_else(|| "info".to_string())
            };
            event.severity = severity;
            event.message = normalize::lookup_str(record, &["alert.signature"]);
            if event.action.is_none() {
                event.action = Some("blocked".to_string());
            }
            attr_string(&mut event, "signature", normalize::lookup_str(record, &["alert.signature"]));
            attr_string(
                &mut event,
                "alertCategory",
                normalize::lookup_str(record, &["alert.category"]),
            );
            attr_i64(&mut event, "signatureId", normalize::lookup_i64(record, &["alert.signature_id"]));
            attr_i64(&mut event, "generatorId", normalize::lookup_i64(record, &["alert.gid"]));
            attr_i64(&mut event, "rev", normalize::lookup_i64(record, &["alert.rev"]));
        }
        "dns" => {
            event.category = Some("dns".to_string());
            let dns_type = normalize::lookup_str(record, &["dns.type"])
                .map(|s| s.trim().to_ascii_lowercase())
                .unwrap_or_else(|| "query".to_string());
            let event_kind = if dns_type.starts_with("ans") || dns_type == "response" {
                "response"
            } else {
                "query"
            };
            event.event_type = Some(event_kind.to_string());
            let query = normalize::lookup_str(record, &["dns.rrname", "dns.query"]);
            if let Some(name) = &query {
                event.hostname = Some(trim_dot(name));
                event.message = Some(format!("DNS {event_kind} {name}"));
            }
            attr_string(&mut event, "dnsQuery", query.clone());
            attr_string(&mut event, "dnsRcode", dns_rcode(record));
            attr_string(&mut event, "dnsType", normalize::lookup_str(record, &["dns.rrtype"]));
            attr_string(&mut event, "dnsRdata", normalize::lookup_str(record, &["dns.rdata"]));
        }
        "http" => {
            event.category = Some("http".to_string());
            let host = normalize::lookup_str(record, &["http.hostname", "http.dest_host", "hostname"]);
            let url = normalize::lookup_str(record, &["http.url"]);
            let method = normalize::lookup_str(record, &["http.http_method"]);
            event.hostname = host.clone();
            if method.is_some() || url.is_some() {
                event.message = Some(format!(
                    "{} {}",
                    method.clone().unwrap_or_else(|| "HTTP".to_string()),
                    url.clone().unwrap_or_else(|| "/".to_string())
                ));
            }
            attr_string(&mut event, "httpHostname", host);
            attr_string(&mut event, "url", url);
            attr_string(&mut event, "method", method);
            attr_i64(
                &mut event,
                "status",
                normalize::lookup_i64(record, &["http.status", "http.status_code"]),
            );
            attr_string(
                &mut event,
                "userAgent",
                normalize::lookup_str(record, &["http.http_user_agent", "http.user_agent"]),
            );
            attr_string(
                &mut event,
                "referrer",
                normalize::lookup_str(record, &["http.http_refer"]),
            );
            attr_i64(&mut event, "length", normalize::lookup_i64(record, &["http.length"]));
        }
        "tls" => {
            event.category = Some("tls".to_string());
            let sni = normalize::lookup_str(record, &["tls.sni"]);
            event.hostname = sni.clone();
            if let Some(name) = &sni {
                event.message = Some(format!("TLS {name}"));
            }
            attr_string(&mut event, "sni", sni);
            attr_string(&mut event, "subject", normalize::lookup_str(record, &["tls.subject"]));
            attr_string(
                &mut event,
                "issuer",
                normalize::lookup_str(record, &["tls.issuerdn", "tls.issuer"]),
            );
            attr_string(&mut event, "tlsVersion", normalize::lookup_str(record, &["tls.version"]));
            attr_string(&mut event, "cipher", normalize::lookup_str(record, &["tls.cipher"]));
            attr_string(&mut event, "ja3", normalize::lookup_str(record, &["tls.ja3.hash"]));
        }
        "flow" => {
            event.category = Some("network".to_string());
            if event.action.is_none() {
                event.action = Some("allowed".to_string());
            }
            attr_string(&mut event, "flowState", normalize::lookup_str(record, &["flow.state"]));
            attr_i64(
                &mut event,
                "bytesToServer",
                normalize::lookup_i64(record, &["flow.bytes_toserver"]),
            );
            attr_i64(
                &mut event,
                "bytesToClient",
                normalize::lookup_i64(record, &["flow.bytes_toclient"]),
            );
            attr_i64(
                &mut event,
                "pktsToServer",
                normalize::lookup_i64(record, &["flow.pkts_toserver"]),
            );
            attr_i64(
                &mut event,
                "pktsToClient",
                normalize::lookup_i64(record, &["flow.pkts_toclient"]),
            );
        }
        "anomaly" => {
            event.category = Some("anomaly".to_string());
            event.event_type = normalize::lookup_str(record, &["anomaly.type", "anomaly.event"])
                .or(Some("anomaly".to_string()));
            event.message = normalize::lookup_str(record, &["anomaly.event", "anomaly.type"]);
            event.severity = "low".to_string();
        }
        "ssh" => {
            event.category = Some("authentication".to_string());
            event.app_proto = Some("ssh".to_string());
            attr_string(&mut event, "client", normalize::lookup_str(record, &["ssh.client"]));
            attr_string(&mut event, "server", normalize::lookup_str(record, &["ssh.server"]));
        }
        "fileinfo" => {
            event.category = Some("file".to_string());
            event.message = normalize::lookup_str(record, &["fileinfo.filename"]);
            attr_string(
                &mut event,
                "filename",
                normalize::lookup_str(record, &["fileinfo.filename"]),
            );
            attr_string(
                &mut event,
                "fileMagic",
                normalize::lookup_str(record, &["fileinfo.magic"]),
            );
        }
        _ => {
            event.category = Some("other".to_string());
        }
    }
    Ok(event)
}

/// Stream a Suricata EVE file line by line.
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
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        index += 1;
        let outcome = match serde_json::from_str::<Value>(trimmed) {
            Ok(record) => normalize_record(&record),
            Err(e) => Err(format!("invalid JSON: {e}")),
        };
        sink(index, outcome)?;
    }
    Ok(())
}
