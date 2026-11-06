//! CSV and JSON exports. Exports are bounded so a huge result set cannot exhaust memory.

use crate::error::{AppError, AppResult};
use crate::types::ExportRequest;
use rusqlite::Connection;
use std::path::Path;

const EXPORT_ROW_LIMIT: i64 = 100_000;

fn opt(v: &Option<String>) -> String {
    v.clone().unwrap_or_default()
}

pub fn export_events(conn: &Connection, request: &ExportRequest) -> AppResult<String> {
    if request.path.trim().is_empty() {
        return Err(AppError::msg("export path is empty"));
    }
    let rows = crate::query::query_all_events(conn, &request.query, EXPORT_ROW_LIMIT)?;
    let path = Path::new(&request.path);
    match request.format.as_str() {
        "csv" => {
            let mut writer = csv::Writer::from_path(path)?;
            writer.write_record([
                "event_id",
                "timestamp_ms",
                "source_type",
                "category",
                "event_type",
                "severity",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "transport",
                "app_proto",
                "action",
                "username",
                "hostname",
                "process_name",
                "message",
            ])?;
            for e in &rows {
                writer.write_record([
                    e.id.to_string(),
                    e.ts.to_string(),
                    e.source_type.clone(),
                    opt(&e.category),
                    opt(&e.event_type),
                    e.severity.clone(),
                    opt(&e.src_ip),
                    opt(&e.dst_ip),
                    e.src_port.map(|v| v.to_string()).unwrap_or_default(),
                    e.dst_port.map(|v| v.to_string()).unwrap_or_default(),
                    opt(&e.transport),
                    opt(&e.app_proto),
                    opt(&e.action),
                    opt(&e.username),
                    opt(&e.hostname),
                    opt(&e.process_name),
                    opt(&e.message),
                ])?;
            }
            writer.flush()?;
        }
        "json" => {
            let json = serde_json::to_string_pretty(&rows)?;
            std::fs::write(path, json)?;
        }
        other => {
            return Err(AppError::msg(format!(
                "unsupported export format '{other}' (use csv or json)"
            )))
        }
    }
    Ok(request.path.clone())
}

pub fn export_investigation(
    conn: &Connection,
    investigation_id: i64,
    path: &str,
) -> AppResult<String> {
    if path.trim().is_empty() {
        return Err(AppError::msg("export path is empty"));
    }
    let detail = crate::investigation::get(conn, investigation_id)?;
    let mut alerts = Vec::new();
    for alert in &detail.alerts {
        let evidence = crate::detection::get_alert(conn, alert.id)?.evidence;
        alerts.push(serde_json::json!({
            "alert": alert,
            "evidence": evidence,
        }));
    }
    let report = serde_json::json!({
        "product": "NULLPLINTH",
        "reportVersion": 1,
        "generatedAt": crate::db::now_ms(),
        "investigation": detail.investigation,
        "notes": detail.notes,
        "alerts": alerts,
        "disclaimer": "Synthetic and imported data are analysed locally. Findings are heuristic and require analyst review.",
    });
    std::fs::write(path, serde_json::to_string_pretty(&report)?)?;
    Ok(path.to_string())
}
