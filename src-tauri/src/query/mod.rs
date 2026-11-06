//! Structured, parameterised event search plus the overview aggregates.
//!
//! Field names and operators are whitelisted here; every user value is bound as a
//! SQLite parameter. No user input is ever concatenated into SQL.

use crate::error::{AppError, AppResult, blocking};
use crate::types::*;
use rusqlite::types::Value;
use rusqlite::{params_from_iter, Connection};
use std::time::Instant;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Text,
    Int,
    Ip,
}

fn field_def(field: &str) -> Option<(&'static str, Kind)> {
    let def = match field {
        "srcIp" => ("src_ip", Kind::Ip),
        "dstIp" => ("dst_ip", Kind::Ip),
        "srcPort" => ("src_port", Kind::Int),
        "dstPort" => ("dst_port", Kind::Int),
        "transport" | "protocol" => ("transport", Kind::Text),
        "appProto" => ("app_proto", Kind::Text),
        "category" => ("category", Kind::Text),
        "eventType" => ("event_type", Kind::Text),
        "severity" => ("severity", Kind::Text),
        "action" => ("action", Kind::Text),
        "username" => ("username", Kind::Text),
        "hostname" => ("hostname", Kind::Text),
        "processName" => ("process_name", Kind::Text),
        "message" => ("message", Kind::Text),
        "sourceType" => ("source_type", Kind::Text),
        _ => return None,
    };
    Some(def)
}

fn sort_column(sort: &str) -> (&'static str, &'static str) {
    match sort {
        "severity" => (
            "CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3              WHEN 'low' THEN 2 ELSE 1 END",
            "severity",
        ),
        "srcIp" => ("src_ip", "srcIp"),
        "dstIp" => ("dst_ip", "dstIp"),
        "category" => ("category", "category"),
        "eventType" => ("event_type", "eventType"),
        "hostname" => ("hostname", "hostname"),
        "username" => ("username", "username"),
        "appProto" => ("app_proto", "appProto"),
        "message" => ("message", "message"),
        "id" => ("id", "id"),
        _ => ("ts", "ts"),
    }
}

fn valid_value(kind: Kind, op: &str, value: &str) -> AppResult<()> {
    match kind {
        Kind::Int => {
            if op == "exists" || op == "notExists" {
                return Ok(());
            }
            value
                .parse::<i64>()
                .map_err(|_| AppError::msg(format!("'{value}' is not a whole number")))?;
        }
        Kind::Ip => {
            if op == "inCidr" {
                value.parse::<ipnet::IpNet>().map_err(|_| {
                    AppError::msg(format!("'{value}' is not a valid CIDR range (for example 10.0.0.0/8)"))
                })?;
            } else if op != "exists" && op != "notExists" {
                value
                    .parse::<std::net::IpAddr>()
                    .map_err(|_| AppError::msg(format!("'{value}' is not a valid IP address")))?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Build the WHERE clause shared by counting, paging and exporting.
pub fn build_where(q: &EventQuery) -> AppResult<(String, Vec<Value>)> {
    let mut clause = String::from(" WHERE 1 = 1");
    let mut args: Vec<Value> = Vec::new();

    if !q.dataset_ids.is_empty() {
        let marks = vec!["?"; q.dataset_ids.len()].join(",");
        clause.push_str(&format!(" AND dataset_id IN ({marks})"));
        args.extend(q.dataset_ids.iter().map(|v| Value::Integer(*v)));
    }
    if !q.source_types.is_empty() {
        let marks = vec!["?"; q.source_types.len()].join(",");
        clause.push_str(&format!(" AND source_type IN ({marks})"));
        args.extend(q.source_types.iter().map(|v| Value::Text(v.clone())));
    }
    if let Some(from) = q.from_ts {
        clause.push_str(" AND ts >= ?");
        args.push(Value::Integer(from));
    }
    if let Some(to) = q.to_ts {
        clause.push_str(" AND ts <= ?");
        args.push(Value::Integer(to));
    }

    for f in &q.filters {
        let (col, kind) = field_def(f.field.trim()).ok_or_else(|| {
            AppError::msg(format!("unknown field '{}' for this data source", f.field))
        })?;
        valid_value(kind, &f.op, &f.value)?;
        // Text comparison is case-insensitive so "root" matches "Root" and "ROOT".
        // IPv4/IPv6 checks and numeric comparisons stay exact.
        let cmp = if kind == Kind::Text {
            format!("{col} COLLATE NOCASE")
        } else {
            col.to_string()
        };
        let cond = match f.op.as_str() {
            "eq" => Some(format!("{cmp} = ?")),
            "neq" => Some(format!("({col} IS NULL OR {cmp} <> ?)")),
            "contains" => Some(format!("{col} LIKE ? ESCAPE '\\'")),
            "notContains" => Some(format!("({col} IS NULL OR {col} NOT LIKE ? ESCAPE '\\')")),
            "startsWith" => Some(format!("{col} LIKE ? ESCAPE '\\'")),
            "gt" => Some(format!("{cmp} > ?")),
            "lt" => Some(format!("{cmp} < ?")),
            "exists" => Some(format!("{col} IS NOT NULL AND {col} <> ''")),
            "notExists" => Some(format!("({col} IS NULL OR {col} = '')")),
            "inCidr" => Some(format!("ip_in_cidr({col}, ?) = 1")),
            other => {
                return Err(AppError::msg(format!("unknown filter operator '{other}'")));
            }
        };
        clause.push_str(" AND ");
        clause.push_str(&cond.unwrap());
        match (f.op.as_str(), kind) {
            ("exists" | "notExists", _) => {}
            ("contains" | "notContains" | "startsWith", _) => {
                let escaped = f
                    .value
                    .replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_");
                args.push(Value::Text(match f.op.as_str() {
                    "startsWith" => format!("{escaped}%"),
                    _ => format!("%{escaped}%"),
                }));
            }
            ("gt" | "lt", Kind::Int) => args.push(Value::Integer(
                f.value.parse::<i64>().map_err(|_| AppError::msg("expected a number"))?,
            )),
            ("gt" | "lt", _) => args.push(Value::Text(f.value.clone())),
            _ => args.push(Value::Text(f.value.clone())),
        }
    }

    if let Some(text) = q.text.as_ref().map(|t| t.trim()).filter(|t| !t.is_empty()) {
        let fts = fts_query(text);
        if !fts.is_empty() {
            clause.push_str(" AND id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)");
            args.push(Value::Text(fts));
        }
    }
    Ok((clause, args))
}

/// Quote every term so FTS5 operators typed by the user are treated literally.
fn fts_query(text: &str) -> String {
    let mut terms: Vec<String> = Vec::new();
    for term in text.split_whitespace().take(16) {
        let cleaned: String = term.chars().filter(|c| c.is_alphanumeric() || "-._:@/".contains(*c)).collect();
        if cleaned.is_empty() {
            continue;
        }
        terms.push(format!("\"{}\"*", cleaned.replace('"', "")));
    }
    terms.join(" ")
}

const EVENT_COLUMNS: &str = "id, dataset_id, ts, source_type, category, event_type, severity, \
    src_ip, dst_ip, src_port, dst_port, transport, app_proto, action, username, hostname, \
    process_name, message";

pub fn event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EventRow> {
    Ok(EventRow {
        id: row.get("id")?,
        dataset_id: row.get("dataset_id")?,
        ts: row.get("ts")?,
        source_type: row.get("source_type")?,
        category: row.get("category")?,
        event_type: row.get("event_type")?,
        severity: row.get("severity")?,
        src_ip: row.get("src_ip")?,
        dst_ip: row.get("dst_ip")?,
        src_port: row.get("src_port")?,
        dst_port: row.get("dst_port")?,
        transport: row.get("transport")?,
        app_proto: row.get("app_proto")?,
        action: row.get("action")?,
        username: row.get("username")?,
        hostname: row.get("hostname")?,
        process_name: row.get("process_name")?,
        message: row.get("message")?,
    })
}

pub fn count_events(conn: &Connection, q: &EventQuery) -> AppResult<i64> {
    let (clause, args) = build_where(q)?;
    let sql = format!("SELECT COUNT(*) FROM events{clause}");
    let total = conn.query_row(&sql, params_from_iter(args.iter()), |r| r.get(0))?;
    Ok(total)
}

pub fn query_events(conn: &Connection, q: &EventQuery) -> AppResult<EventPage> {
    let started = Instant::now();
    let total = count_events(conn, q)?;
    let (clause, args) = build_where(q)?;
    let (sort_expr, _) = sort_column(q.sort.as_str());
    let dir = if q.sort_dir.eq_ignore_ascii_case("asc") { "ASC" } else { "DESC" };
    let page_size = q.page_size.clamp(1, 500) as i64;
    // Pages are 1-based: page 1 is the first page. The UI shows 1-based numbers too.
    let page = q.page.max(1);
    let offset = (page as i64 - 1) * page_size;
    let sql = format!(
        "SELECT {EVENT_COLUMNS} FROM events{clause} ORDER BY {sort_expr} {dir}, id DESC LIMIT ? OFFSET ?"
    );
    let mut all: Vec<Value> = args;
    all.push(Value::Integer(page_size));
    all.push(Value::Integer(offset));
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(all.iter()), event_from_row)?;
    let mut events = Vec::new();
    for r in rows {
        events.push(r?);
    }
    Ok(EventPage {
        total,
        events,
        page,
        page_size: page_size as u32,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

/// Same filter, every matching row (bounded) - used by export.
pub fn query_all_events(conn: &Connection, q: &EventQuery, limit: i64) -> AppResult<Vec<EventRow>> {
    let (clause, mut args) = build_where(q)?;
    let (sort_expr, _) = sort_column(q.sort.as_str());
    let dir = if q.sort_dir.eq_ignore_ascii_case("asc") { "ASC" } else { "DESC" };
    let sql = format!(
        "SELECT {EVENT_COLUMNS} FROM events{clause} ORDER BY {sort_expr} {dir}, id DESC LIMIT ?"
    );
    args.push(Value::Integer(limit));
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(args.iter()), event_from_row)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn get_event(conn: &Connection, event_id: i64) -> AppResult<EventDetail> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {EVENT_COLUMNS}, attrs, raw, dataset_id AS dsid FROM events WHERE id = ?1"
    ))?;
    let mut rows = stmt.query(rusqlite::params![event_id])?;
    let row = rows
        .next()?
        .ok_or_else(|| AppError::msg(format!("event {event_id} not found")))?;
    let event = event_from_row(row)?;
    let attrs: String = row.get("attrs")?;
    let raw: String = row.get("raw")?;
    let dataset_name = crate::db::get_dataset_name(conn, event.dataset_id)?;
    Ok(EventDetail {
        event,
        attrs: serde_json::from_str(&attrs).unwrap_or(serde_json::Value::Null),
        raw: serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null),
        dataset_name,
    })
}

// ---------------------------------------------------------------- alerts

pub fn alert_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Alert> {
    let threshold: String = row.get("threshold")?;
    let steps: String = row.get("recommended_steps")?;
    Ok(Alert {
        id: row.get("id")?,
        rule: row.get("rule")?,
        title: row.get("title")?,
        severity: row.get("severity")?,
        confidence: row.get("confidence")?,
        explanation: row.get("explanation")?,
        threshold: serde_json::from_str(&threshold).unwrap_or(serde_json::Value::Null),
        recommended_steps: serde_json::from_str(&steps).unwrap_or_default(),
        src_ip: row.get("src_ip")?,
        dst_ip: row.get("dst_ip")?,
        event_count: row.get("event_count")?,
        status: row.get("status")?,
        note: row.get("note")?,
        created_at: row.get("created_at")?,
    })
}

pub const ALERT_COLUMNS: &str = "id, rule, title, severity, confidence, explanation, threshold, \
    recommended_steps, src_ip, dst_ip, event_count, status, note, created_at";

// -------------------------------------------------------------- overview

fn count_by(conn: &Connection, sql: &str) -> AppResult<Vec<Count>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], |r| {
        Ok(Count {
            key: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
            count: r.get(1)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn overview(conn: &Connection) -> AppResult<Overview> {
    let one = |sql: &str| -> AppResult<i64> {
        Ok(conn.query_row(sql, [], |r| r.get(0))?)
    };
    let total_events = one("SELECT COUNT(*) FROM events")?;
    let dataset_count = one("SELECT COUNT(*) FROM datasets")?;
    let capture_count = one("SELECT COUNT(*) FROM packet_captures")?;
    let packet_count = one("SELECT COUNT(*) FROM packets")?;
    let investigation_count = one("SELECT COUNT(*) FROM investigations")?;
    let alert_total = one("SELECT COUNT(*) FROM alerts")?;

    let alerts_by_severity = count_by(
        conn,
        "SELECT severity, COUNT(*) FROM alerts GROUP BY severity          ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 \
         WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",
    )?;
    let top_src_ips = count_by(
        conn,
        "SELECT src_ip, COUNT(*) c FROM events WHERE src_ip IS NOT NULL AND src_ip <> ''          GROUP BY src_ip ORDER BY c DESC LIMIT 5",
    )?;
    let top_dst_ips = count_by(
        conn,
        "SELECT dst_ip, COUNT(*) c FROM events WHERE dst_ip IS NOT NULL AND dst_ip <> ''          GROUP BY dst_ip ORDER BY c DESC LIMIT 5",
    )?;
    let protocol_distribution = count_by(
        conn,
        "SELECT ifnull(transport, 'unknown'), COUNT(*) c FROM events GROUP BY transport          ORDER BY c DESC LIMIT 8",
    )?;
    let category_distribution = count_by(
        conn,
        "SELECT ifnull(category, 'unknown'), COUNT(*) c FROM events GROUP BY category          ORDER BY c DESC LIMIT 8",
    )?;
    let recent_alerts = {
        let sql = format!(
            "SELECT {ALERT_COLUMNS} FROM alerts ORDER BY created_at DESC, id DESC LIMIT 5"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], alert_from_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        out
    };
    let volume_series = {
        let (min_ts, max_ts): (Option<i64>, Option<i64>) = conn.query_row(
            "SELECT MIN(ts), MAX(ts) FROM events",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        match (min_ts, max_ts) {
            (Some(lo), Some(hi)) if hi > lo => {
                let bucket = ((hi - lo) / 23).max(3_600_000);
                let mut stmt = conn.prepare(
                    "SELECT (ts / ?1) * ?1 AS bucket, COUNT(*) FROM events GROUP BY bucket ORDER BY bucket",
                )?;
                let rows = stmt.query_map(rusqlite::params![bucket], |r| {
                    Ok(TimeBucket {
                        ts: r.get(0)?,
                        count: r.get(1)?,
                    })
                })?;
                let mut out = Vec::new();
                for r in rows {
                    out.push(r?);
                }
                out
            }
            _ => vec![],
        }
    };
    let flow_summary = FlowSummary {
        flow_count: one("SELECT COUNT(*) FROM flows")?,
        total_bytes: one("SELECT ifnull(SUM(bytes_total), 0) FROM flows")?,
        tcp_flows: one("SELECT COUNT(*) FROM flows WHERE transport = 'tcp'")?,
        udp_flows: one("SELECT COUNT(*) FROM flows WHERE transport = 'udp'")?,
    };
    Ok(Overview {
        total_events,
        dataset_count,
        capture_count,
        packet_count,
        investigation_count,
        alerts_by_severity,
        alert_total,
        recent_alerts,
        top_src_ips,
        top_dst_ips,
        protocol_distribution,
        category_distribution,
        volume_series,
        flow_summary,
    })
}

/// Helper for callers that need the async wrapper and a fresh connection.
pub async fn with_conn<T, F>(db: crate::db::Db, job: F) -> AppResult<T>
where
    T: Send + 'static,
    F: FnOnce(Connection) -> AppResult<T> + Send + 'static,
{
    blocking(move || {
        let conn = db.conn()?;
        job(conn)
    })
    .await
}