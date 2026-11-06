//! Lightweight investigation records: title, description, status, notes and
//! attached alerts. Everything stays in the local database.

use crate::db::now_ms;
use crate::error::{AppError, AppResult};
use crate::query::{alert_from_row, ALERT_COLUMNS};
use crate::types::*;
use rusqlite::{params, Connection};

const STATUSES: [&str; 4] = ["open", "investigating", "resolved", "closed"];

fn row_to_investigation(row: &rusqlite::Row<'_>) -> rusqlite::Result<Investigation> {
    Ok(Investigation {
        id: row.get("id")?,
        title: row.get("title")?,
        description: row.get("description")?,
        status: row.get("status")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
        alert_ids: Vec::new(),
        note_count: 0,
    })
}

fn alert_ids(conn: &Connection, investigation_id: i64) -> AppResult<Vec<i64>> {
    let mut stmt = conn.prepare(
        "SELECT alert_id FROM investigation_alerts WHERE investigation_id = ?1 ORDER BY alert_id",
    )?;
    let rows = stmt.query_map(params![investigation_id], |r| r.get::<_, i64>(0))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

fn note_count(conn: &Connection, investigation_id: i64) -> AppResult<i64> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM investigation_notes WHERE investigation_id = ?1",
        params![investigation_id],
        |r| r.get(0),
    )?)
}

fn hydrate(conn: &Connection, mut inv: Investigation) -> AppResult<Investigation> {
    inv.alert_ids = alert_ids(conn, inv.id)?;
    inv.note_count = note_count(conn, inv.id)?;
    Ok(inv)
}

pub fn create(conn: &Connection, input: NewInvestigation) -> AppResult<InvestigationDetail> {
    let title = input.title.trim();
    if title.is_empty() {
        return Err(AppError::msg("an investigation needs a title"));
    }
    let now = now_ms();
    conn.execute(
        "INSERT INTO investigations (title, description, status, created_at, updated_at)
         VALUES (?1, ?2, 'open', ?3, ?3)",
        params![title, input.description, now],
    )?;
    let id = conn.last_insert_rowid();
    for alert_id in &input.alert_ids {
        conn.execute(
            "INSERT OR IGNORE INTO investigation_alerts (investigation_id, alert_id) VALUES (?1, ?2)",
            params![id, alert_id],
        )?;
    }
    get(conn, id)
}

pub fn list(conn: &Connection) -> AppResult<Vec<Investigation>> {
    let mut stmt = conn.prepare(
        "SELECT id, title, description, status, created_at, updated_at
         FROM investigations ORDER BY updated_at DESC",
    )?;
    let rows = stmt.query_map([], row_to_investigation)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(hydrate(conn, r?)?);
    }
    Ok(out)
}

pub fn get(conn: &Connection, investigation_id: i64) -> AppResult<InvestigationDetail> {
    let mut stmt = conn.prepare(
        "SELECT id, title, description, status, created_at, updated_at
         FROM investigations WHERE id = ?1",
    )?;
    let mut rows = stmt.query(params![investigation_id])?;
    let investigation = match rows.next()? {
        Some(r) => hydrate(conn, row_to_investigation(r)?)?,
        None => {
            return Err(AppError::msg(format!(
                "investigation {investigation_id} not found"
            )))
        }
    };

    let mut notes_stmt = conn.prepare(
        "SELECT id, investigation_id, body, created_at FROM investigation_notes
         WHERE investigation_id = ?1 ORDER BY created_at ASC",
    )?;
    let note_rows = notes_stmt.query_map(params![investigation_id], |r| {
        Ok(InvestigationNote {
            id: r.get(0)?,
            investigation_id: r.get(1)?,
            body: r.get(2)?,
            created_at: r.get(3)?,
        })
    })?;
    let mut notes = Vec::new();
    for r in note_rows {
        notes.push(r?);
    }

    let mut alerts = Vec::new();
    if !investigation.alert_ids.is_empty() {
        let sql = format!(
            "SELECT {ALERT_COLUMNS} FROM alerts WHERE id IN ({}) ORDER BY created_at DESC",
            investigation
                .alert_ids
                .iter()
                .map(|_| "?")
                .collect::<Vec<_>>()
                .join(",")
        );
        let mut alert_stmt = conn.prepare(&sql)?;
        let values: Vec<rusqlite::types::Value> = investigation
            .alert_ids
            .iter()
            .map(|id| rusqlite::types::Value::Integer(*id))
            .collect();
        let alert_rows =
            alert_stmt.query_map(rusqlite::params_from_iter(values.iter()), alert_from_row)?;
        for r in alert_rows {
            alerts.push(r?);
        }
    }

    Ok(InvestigationDetail {
        investigation,
        notes,
        alerts,
    })
}

pub fn update(
    conn: &Connection,
    investigation_id: i64,
    title: Option<&str>,
    description: Option<&str>,
    status: Option<&str>,
) -> AppResult<InvestigationDetail> {
    let mut current = get(conn, investigation_id)?.investigation;
    if let Some(t) = title {
        if t.trim().is_empty() {
            return Err(AppError::msg("an investigation needs a title"));
        }
        current.title = t.trim().to_string();
    }
    if let Some(d) = description {
        current.description = d.to_string();
    }
    if let Some(s) = status {
        if !STATUSES.contains(&s) {
            return Err(AppError::msg(format!(
                "invalid investigation status '{s}' (expected open, investigating, resolved or closed)"
            )));
        }
        current.status = s.to_string();
    }
    conn.execute(
        "UPDATE investigations SET title = ?2, description = ?3, status = ?4, updated_at = ?5
         WHERE id = ?1",
        params![
            investigation_id,
            current.title,
            current.description,
            current.status,
            now_ms()
        ],
    )?;
    get(conn, investigation_id)
}

pub fn add_note(conn: &Connection, investigation_id: i64, body: &str) -> AppResult<InvestigationDetail> {
    if body.trim().is_empty() {
        return Err(AppError::msg("a note cannot be empty"));
    }
    get(conn, investigation_id)?;
    conn.execute(
        "INSERT INTO investigation_notes (investigation_id, body, created_at) VALUES (?1, ?2, ?3)",
        params![investigation_id, body.trim(), now_ms()],
    )?;
    conn.execute(
        "UPDATE investigations SET updated_at = ?2 WHERE id = ?1",
        params![investigation_id, now_ms()],
    )?;
    get(conn, investigation_id)
}

pub fn attach_alert(
    conn: &Connection,
    investigation_id: i64,
    alert_id: i64,
) -> AppResult<InvestigationDetail> {
    get(conn, investigation_id)?;
    let exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM alerts WHERE id = ?1",
        params![alert_id],
        |r| r.get(0),
    )?;
    if exists == 0 {
        return Err(AppError::msg(format!("alert {alert_id} not found")));
    }
    conn.execute(
        "INSERT OR IGNORE INTO investigation_alerts (investigation_id, alert_id) VALUES (?1, ?2)",
        params![investigation_id, alert_id],
    )?;
    conn.execute(
        "UPDATE investigations SET updated_at = ?2 WHERE id = ?1",
        params![investigation_id, now_ms()],
    )?;
    get(conn, investigation_id)
}
