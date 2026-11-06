//! Deterministic, rule-based detection over stored events.
//!
//! Every alert is derived from real event rows and links to them through
//! alert_evidence. Re-running detection dedupes on (rule, entity, time bucket)
//! so alerts are never duplicated and analyst status is preserved.

use crate::db::{get_setting, now_ms, Db};
use crate::error::{AppError, AppResult};
use crate::query::{alert_from_row, ALERT_COLUMNS};
use crate::types::*;
use rusqlite::types::Value;
use rusqlite::{params, params_from_iter, Connection};
use serde_json::json;
use std::time::Instant;
use tauri::Emitter;

pub const RULE_AUTH: &str = "auth-brute-force";
pub const RULE_PORT_SCAN: &str = "port-scan";
pub const RULE_DNS: &str = "dns-nxdomain";
pub const RULE_CONN: &str = "suspicious-connections";

fn load_settings(conn: &Connection) -> AppResult<DetectionSettings> {
    let raw = get_setting(conn, "detection")?;
    Ok(raw
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default())
}

struct Finding {
    rule: &'static str,
    title: String,
    severity: &'static str,
    confidence: f64,
    explanation: String,
    threshold: serde_json::Value,
    steps: Vec<String>,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    event_count: i64,
    dedupe: String,
    /// (event id, short summary, event timestamp)
    evidence: Vec<(i64, String, i64)>,
}

fn insert_alert(conn: &Connection, run_id: &str, f: &Finding) -> AppResult<bool> {
    let changed = conn.execute(
        "INSERT OR IGNORE INTO alerts (run_id, rule, title, severity, confidence, explanation,
             threshold, recommended_steps, src_ip, dst_ip, event_count, status, note,
             dedupe_key, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'new', NULL, ?12, ?13)",
        params![
            run_id,
            f.rule,
            f.title,
            f.severity,
            f.confidence,
            f.explanation,
            f.threshold.to_string(),
            serde_json::to_string(&f.steps)?,
            f.src_ip,
            f.dst_ip,
            f.event_count,
            f.dedupe,
            now_ms()
        ],
    )?;
    if changed == 0 {
        return Ok(false);
    }
    let alert_id = conn.last_insert_rowid();
    let mut stmt = conn.prepare(
        "INSERT INTO alert_evidence (alert_id, kind, ref_id, summary, ts)
         VALUES (?1, 'event', ?2, ?3, ?4)",
    )?;
    for (event_id, summary, ts) in &f.evidence {
        stmt.execute(params![alert_id, event_id, summary, ts])?;
    }
    Ok(true)
}

fn collect_evidence(
    conn: &Connection,
    sql: &str,
    args: Vec<Value>,
) -> AppResult<Vec<(i64, String, i64)>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(params_from_iter(args.iter()), |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            r.get::<_, i64>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

fn rule_auth(conn: &Connection, s: &DetectionSettings, run_id: &str) -> AppResult<i64> {
    let window = (s.brute_force_window_secs as i64) * 1000;
    let threshold = s.brute_force_threshold as i64;
    let mut stmt = conn.prepare(
        "SELECT src_ip, COUNT(*) c, MIN(ts), MAX(ts) FROM events
         WHERE category = 'authentication' AND action = 'failed'
           AND src_ip IS NOT NULL AND src_ip <> ''
         GROUP BY src_ip, ts / ?1 HAVING c >= ?2
         ORDER BY c DESC LIMIT 50",
    )?;
    let groups = stmt.query_map(params![window, threshold], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i64>(3)?,
        ))
    })?;
    let mut created = 0;
    for g in groups {
        let (src, count, first_ts, last_ts) = g?;
        let evidence = collect_evidence(
            conn,
            "SELECT id, ifnull(message, ''), ts FROM events
             WHERE category = 'authentication' AND action = 'failed' AND src_ip = ?1
               AND ts BETWEEN ?2 AND ?3 ORDER BY ts LIMIT 50",
            vec![
                Value::Text(src.clone()),
                Value::Integer(first_ts),
                Value::Integer(last_ts),
            ],
        )?;
        if evidence.is_empty() {
            continue;
        }
        let users: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT username) FROM events
             WHERE category = 'authentication' AND action = 'failed' AND src_ip = ?1
               AND ts BETWEEN ?2 AND ?3",
            params![src, first_ts, last_ts],
            |r| r.get(0),
        )?;
        let f = Finding {
            rule: RULE_AUTH,
            title: format!("Potential brute-force activity from {src}"),
            severity: if count >= threshold * 2 { "high" } else { "medium" },
            confidence: if count >= threshold * 2 { 0.85 } else { 0.7 },
            explanation: format!(
                "{} failed authentication attempts from {} were observed within {} seconds.                  {} distinct username(s) were targeted. This is consistent with a brute-force                  attempt, but a threshold being exceeded does not prove an account was compromised.",
                count, src, s.brute_force_window_secs, users
            ),
            threshold: json!({
                "failedAttempts": threshold,
                "windowSeconds": s.brute_force_window_secs,
                "observed": count
            }),
            steps: vec![
                "Open the supporting events and confirm the targeted accounts.".into(),
                "Check whether any of those accounts later authenticated successfully.".into(),
                "Consider blocking the source address at the network boundary.".into(),
            ],
            src_ip: Some(src.clone()),
            dst_ip: None,
            event_count: count,
            dedupe: format!("{RULE_AUTH}|{src}|{first_ts}"),
            evidence,
        };
        if insert_alert(conn, run_id, &f)? {
            created += 1;
        }
    }
    Ok(created)
}

fn rule_port_scan(conn: &Connection, s: &DetectionSettings, run_id: &str) -> AppResult<i64> {
    let window = (s.port_scan_window_secs as i64) * 1000;
    let threshold = s.port_scan_threshold as i64;
    let mut stmt = conn.prepare(
        "SELECT src_ip, COUNT(DISTINCT dst_port) ports, COUNT(DISTINCT dst_ip) hosts, MIN(ts), MAX(ts)
         FROM events
         WHERE transport = 'tcp' AND src_ip IS NOT NULL AND src_ip <> '' AND dst_port IS NOT NULL
         GROUP BY src_ip, ts / ?1 HAVING ports >= ?2
         ORDER BY ports DESC LIMIT 50",
    )?;
    let groups = stmt.query_map(params![window, threshold], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, i64>(4)?,
        ))
    })?;
    let mut created = 0;
    for g in groups {
        let (src, ports, hosts, first_ts, last_ts) = g?;
        let evidence = collect_evidence(
            conn,
            "SELECT id, ifnull(message, ''), ts FROM events
             WHERE transport = 'tcp' AND src_ip = ?1 AND dst_port IS NOT NULL
               AND ts BETWEEN ?2 AND ?3 ORDER BY ts LIMIT 50",
            vec![
                Value::Text(src.clone()),
                Value::Integer(first_ts),
                Value::Integer(last_ts),
            ],
        )?;
        if evidence.is_empty() {
            continue;
        }
        let host_note = if hosts > 5 {
            format!(" The same source also contacted {} distinct hosts, so this could be a host sweep rather than a pure port scan.", hosts)
        } else {
            String::new()
        };
        let f = Finding {
            rule: RULE_PORT_SCAN,
            title: format!("Possible port scanning from {src}"),
            severity: if ports >= threshold * 2 { "high" } else { "medium" },
            confidence: if hosts > 5 { 0.6 } else { 0.8 },
            explanation: format!(
                "{} distinct destination ports were contacted by {} within {} seconds across {} host(s).{}                  Sequential or wide port connection attempts are consistent with reconnaissance.",
                ports, src, s.port_scan_window_secs, hosts, host_note
            ),
            threshold: json!({
                "distinctPorts": threshold,
                "windowSeconds": s.port_scan_window_secs,
                "observedPorts": ports,
                "observedHosts": hosts
            }),
            steps: vec![
                "Review which ports were probed to infer the scanning intent.".into(),
                "Check whether any probed service accepted a connection.".into(),
                "Confirm whether the source is an authorised scanner.".into(),
            ],
            src_ip: Some(src.clone()),
            dst_ip: None,
            event_count: ports,
            dedupe: format!("{RULE_PORT_SCAN}|{src}|{first_ts}"),
            evidence,
        };
        if insert_alert(conn, run_id, &f)? {
            created += 1;
        }
    }
    Ok(created)
}

fn rule_dns(conn: &Connection, s: &DetectionSettings, run_id: &str) -> AppResult<(i64, Option<String>)> {
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM events WHERE category = 'dns'", [], |r| r.get(0))?;
    if total == 0 {
        return Ok((0, Some("skipped: no DNS telemetry in the imported datasets".into())));
    }
    let window = (s.dns_window_secs as i64) * 1000;
    let threshold = s.dns_nxdomain_threshold as i64;
    let mut stmt = conn.prepare(
        "SELECT src_ip, COUNT(*) c, MIN(ts), MAX(ts) FROM events
         WHERE category = 'dns' AND src_ip IS NOT NULL AND src_ip <> ''
           AND (attrs LIKE '%NXDOMAIN%' OR attrs LIKE '%nxdomain%' OR action = 'nxdomain'
                OR event_type LIKE '%nxdomain%')
         GROUP BY src_ip, ts / ?1 HAVING c >= ?2
         ORDER BY c DESC LIMIT 50",
    )?;
    let groups = stmt.query_map(params![window, threshold], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i64>(3)?,
        ))
    })?;
    let mut created = 0;
    for g in groups {
        let (src, count, first_ts, last_ts) = g?;
        let evidence = collect_evidence(
            conn,
            "SELECT id, ifnull(message, ''), ts FROM events
             WHERE category = 'dns' AND src_ip = ?1 AND ts BETWEEN ?2 AND ?3
               AND (attrs LIKE '%NXDOMAIN%' OR attrs LIKE '%nxdomain%' OR action = 'nxdomain'
                    OR event_type LIKE '%nxdomain%')
             ORDER BY ts LIMIT 50",
            vec![
                Value::Text(src.clone()),
                Value::Integer(first_ts),
                Value::Integer(last_ts),
            ],
        )?;
        if evidence.is_empty() {
            continue;
        }
        let f = Finding {
            rule: RULE_DNS,
            title: format!("DNS NXDOMAIN spike from {src}"),
            severity: "medium",
            confidence: 0.65,
            explanation: format!(
                "{} DNS responses ending in NXDOMAIN were observed from {} within {} seconds.                  Repeated failed name resolutions can indicate domain-generation algorithms,                  mistyped configuration, or reconnaissance.",
                count, src, s.dns_window_secs
            ),
            threshold: json!({
                "nxdomainCount": threshold,
                "windowSeconds": s.dns_window_secs,
                "observed": count
            }),
            steps: vec![
                "Inspect the queried names for random-looking patterns.".into(),
                "Compare against the host's normal DNS behaviour.".into(),
                "Check the device for unwanted software if the spike is unexplained.".into(),
            ],
            src_ip: Some(src.clone()),
            dst_ip: None,
            event_count: count,
            dedupe: format!("{RULE_DNS}|{src}|{first_ts}"),
            evidence,
        };
        if insert_alert(conn, run_id, &f)? {
            created += 1;
        }
    }
    Ok((created, None))
}

fn rule_connections(conn: &Connection, s: &DetectionSettings, run_id: &str) -> AppResult<i64> {
    let window = (s.failed_conn_window_secs as i64) * 1000;
    let threshold = s.failed_conn_threshold as i64;
    let mut stmt = conn.prepare(
        "SELECT src_ip, COUNT(*) c, MIN(ts), MAX(ts) FROM events
         WHERE category = 'network' AND action IN ('blocked', 'failed')
           AND src_ip IS NOT NULL AND src_ip <> ''
         GROUP BY src_ip, ts / ?1 HAVING c >= ?2
         ORDER BY c DESC LIMIT 50",
    )?;
    let groups = stmt.query_map(params![window, threshold], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i64>(3)?,
        ))
    })?;
    let mut created = 0;
    for g in groups {
        let (src, count, first_ts, last_ts) = g?;
        let evidence = collect_evidence(
            conn,
            "SELECT id, ifnull(message, ''), ts FROM events
             WHERE category = 'network' AND action IN ('blocked', 'failed') AND src_ip = ?1
               AND ts BETWEEN ?2 AND ?3 ORDER BY ts LIMIT 50",
            vec![
                Value::Text(src.clone()),
                Value::Integer(first_ts),
                Value::Integer(last_ts),
            ],
        )?;
        if evidence.is_empty() {
            continue;
        }
        let f = Finding {
            rule: RULE_CONN,
            title: format!("Repeated blocked or failed connections from {src}"),
            severity: "medium",
            confidence: 0.6,
            explanation: format!(
                "{} blocked or failed connection attempts originated from {} within {} seconds.                  Repeated failures can indicate misconfiguration, a blocked attack, or beaconing                  towards unreachable infrastructure.",
                count, src, s.failed_conn_window_secs
            ),
            threshold: json!({
                "failedConnections": threshold,
                "windowSeconds": s.failed_conn_window_secs,
                "observed": count
            }),
            steps: vec![
                "Identify the destination hosts and ports that keep failing.".into(),
                "Check whether a firewall rule is the reason the connections fail.".into(),
                "Confirm the source host is expected to make these connections.".into(),
            ],
            src_ip: Some(src.clone()),
            dst_ip: None,
            event_count: count,
            dedupe: format!("{RULE_CONN}|{src}|{first_ts}"),
            evidence,
        };
        if insert_alert(conn, run_id, &f)? {
            created += 1;
        }
    }
    Ok(created)
}

pub fn run(app: &tauri::AppHandle, db: &Db) -> AppResult<DetectionRun> {
    let conn = db.conn()?;
    run_rules(&conn, Some(app))
}

/// Pure rule runner: no Tauri types, so it can be tested against a plain connection.
pub fn run_rules(conn: &Connection, app: Option<&tauri::AppHandle>) -> AppResult<DetectionRun> {
    let started = Instant::now();
    let settings = load_settings(conn)?;
    let run_id = format!("run-{}", now_ms());
    let mut rules = Vec::new();
    let mut total = 0i64;

    let jobs: [(&str, fn(&Connection, &DetectionSettings, &str) -> AppResult<(i64, Option<String>)>); 4] = [
        (RULE_AUTH, |c, s, r| Ok((rule_auth(c, s, r)?, None))),
        (RULE_PORT_SCAN, |c, s, r| Ok((rule_port_scan(c, s, r)?, None))),
        (RULE_DNS, rule_dns),
        (RULE_CONN, |c, s, r| Ok((rule_connections(c, s, r)?, None))),
    ];

    for (name, job) in jobs {
        let (created, skipped) = job(conn, &settings, &run_id)?;
        total += created;
        if let Some(app) = app {
            let _ = app.emit(
                "detection-progress",
                json!({ "rule": name, "alertsCreated": created }),
            );
        }
        rules.push(RuleRunSummary {
            rule: name.to_string(),
            alerts_created: created,
            skipped,
        });
    }

    Ok(DetectionRun {
        run_id,
        alerts_created: total,
        rules,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

fn optional_filter(severity: Option<&str>, status: Option<&str>) -> (String, Vec<Value>) {
    let mut clause = String::new();
    let mut args: Vec<Value> = Vec::new();
    if let Some(s) = severity.filter(|s| !s.is_empty()) {
        clause.push_str(" AND severity = ?");
        args.push(Value::Text(s.to_string()));
    }
    if let Some(s) = status.filter(|s| !s.is_empty()) {
        clause.push_str(" AND status = ?");
        args.push(Value::Text(s.to_string()));
    }
    (clause, args)
}

pub fn list_alerts(
    conn: &Connection,
    severity: Option<&str>,
    status: Option<&str>,
) -> AppResult<Vec<Alert>> {
    let (clause, args) = optional_filter(severity, status);
    let sql = format!(
        "SELECT {ALERT_COLUMNS} FROM alerts WHERE 1 = 1{clause}          ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2          WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, created_at DESC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(args.iter()), alert_from_row)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn get_alert(conn: &Connection, alert_id: i64) -> AppResult<AlertDetail> {
    let sql = format!("SELECT {ALERT_COLUMNS} FROM alerts WHERE id = ?1");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(params![alert_id])?;
    let alert = match rows.next()? {
        Some(r) => alert_from_row(r)?,
        None => return Err(AppError::msg(format!("alert {alert_id} not found"))),
    };
    let mut ev_stmt =
        conn.prepare("SELECT kind, ref_id, summary, ts FROM alert_evidence WHERE alert_id = ?1 ORDER BY ts")?;
    let ev_rows = ev_stmt.query_map(params![alert_id], |r| {
        Ok(AlertEvidence {
            kind: r.get(0)?,
            ref_id: r.get(1)?,
            summary: r.get(2)?,
            ts: r.get(3)?,
        })
    })?;
    let mut evidence = Vec::new();
    for r in ev_rows {
        evidence.push(r?);
    }
    Ok(AlertDetail { alert, evidence })
}

pub fn update_alert(
    conn: &Connection,
    alert_id: i64,
    status: Option<&str>,
    note: Option<&str>,
) -> AppResult<()> {
    if let Some(s) = status {
        if !matches!(s, "new" | "investigating" | "resolved") {
            return Err(AppError::msg(format!(
                "invalid alert status '{s}' (expected new, investigating or resolved)"
            )));
        }
        conn.execute(
            "UPDATE alerts SET status = ?2 WHERE id = ?1",
            params![alert_id, s],
        )?;
    }
    if let Some(n) = note {
        conn.execute(
            "UPDATE alerts SET note = ?2 WHERE id = ?1",
            params![alert_id, n],
        )?;
    }
    Ok(())
}