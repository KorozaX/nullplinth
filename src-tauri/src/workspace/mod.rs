//! Workspace lifecycle: status of the current local workspace and a transactional
//! "start fresh" that clears imported representations without touching user files.
//!
//! Global preferences live in the settings table and are deliberately preserved.

use crate::db::{now_ms, Db};
use crate::error::AppResult;
use crate::types::{AppPreferences, WorkspaceClearResult, WorkspaceState};
use rusqlite::Connection;

pub fn state(conn: &Connection) -> AppResult<WorkspaceState> {
    let count = |table: &str| -> AppResult<i64> {
        Ok(conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?)
    };
    let datasets = count("datasets")?;
    let events = count("events")?;
    let captures = count("packet_captures")?;
    Ok(WorkspaceState {
        has_data: datasets > 0 || events > 0 || captures > 0,
        datasets,
        events,
        captures,
        packets: count("packets")?,
        flows: count("flows")?,
        alerts: count("alerts")?,
        investigations: count("investigations")?,
    })
}

/// Remove every imported and derived record. Returns what was removed.
/// Runs in one transaction: on error nothing is deleted.
pub fn clear(db: &Db, backup_path: Option<&str>) -> AppResult<WorkspaceClearResult> {
    let conn = db.conn()?;
    let before = state(&conn)?;

    let mut backup_used = None;
    if let Some(path) = backup_path.map(|p| p.trim()).filter(|p| !p.is_empty()) {
        // Copying the whole SQLite file keeps every table and the FTS index intact.
        std::fs::copy(db.path(), path)?;
        backup_used = Some(path.to_string());
    }

    let tx = conn.unchecked_transaction()?;
    for table in [
        "alert_evidence",
        "alerts",
        "investigation_notes",
        "investigation_alerts",
        "investigations",
        "saved_filters",
        "packets",
        "flows",
        "packet_captures",
        "events",
        "datasets",
    ] {
        tx.execute(&format!("DELETE FROM {table}"), [])?;
    }
    tx.commit()?;

    Ok(WorkspaceClearResult {
        datasets: before.datasets,
        events: before.events,
        captures: before.captures,
        packets: before.packets,
        flows: before.flows,
        alerts: before.alerts,
        investigations: before.investigations,
        backup_path: backup_used,
    })
}

pub fn preferences(conn: &Connection) -> AppResult<AppPreferences> {
    let raw = crate::db::get_setting(conn, "app.preferences")?;
    Ok(raw
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default())
}

pub fn save_preferences(conn: &Connection, prefs: &AppPreferences) -> AppResult<AppPreferences> {
    let normalized = match prefs.startup_behavior.as_str() {
        "resume" => "resume".to_string(),
        "ask" => "ask".to_string(),
        other => {
            return Err(crate::error::AppError::msg(format!(
                "unknown startup behaviour '{other}' (expected ask or resume)"
            )))
        }
    };
    let prefs = AppPreferences {
        startup_behavior: normalized,
    };
    crate::db::put_setting(conn, "app.preferences", &serde_json::to_string(&prefs)?)?;
    Ok(prefs)
}

/// Timestamp helper used by callers that want a backup name suggestion.
pub fn backup_suggestion() -> String {
    format!("nullplinth-workspace-backup-{}.db", now_ms())
}