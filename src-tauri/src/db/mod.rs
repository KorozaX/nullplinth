//! SQLite storage. One connection per operation keeps long imports from locking reads.
//! Every query in this crate is parameterised; user input never reaches SQL as text.

use crate::error::{AppError, AppResult};
use crate::types::{Dataset, NormalizedEvent};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};

pub const SCHEMA_VERSION: i64 = 1;
const SCHEMA_SQL: &str = include_str!("schema.sql");

#[derive(Clone)]
pub struct Db {
    path: PathBuf,
}

impl Db {
    pub fn open(path: PathBuf) -> AppResult<Self> {
        let db = Db { path };
        let conn = db.conn()?;
        init_schema(&conn)?;
        Ok(db)
    }

    pub fn conn(&self) -> AppResult<Connection> {
        let conn = Connection::open(&self.path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        Ok(conn)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn init_schema(conn: &Connection) -> AppResult<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version != 0 && version != SCHEMA_VERSION {
        return Err(AppError::msg(format!(
            "unsupported database schema version {version} (expected {SCHEMA_VERSION})"
        )));
    }
    conn.execute_batch(SCHEMA_SQL)?;
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(())
}

pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ------------------------------------------------------------- datasets

pub fn insert_dataset(
    conn: &Connection,
    name: &str,
    file_name: Option<&str>,
    file_hash: Option<&str>,
    file_size: Option<i64>,
    source_type: &str,
) -> AppResult<i64> {
    conn.execute(
        "INSERT INTO datasets (name, file_name, file_hash, file_size, source_type, imported_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![name, file_name, file_hash, file_size, source_type, now_ms()],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn finish_dataset(
    conn: &Connection,
    dataset_id: i64,
    record_count: i64,
    skipped_count: i64,
    warnings: &[String],
    status: &str,
) -> AppResult<()> {
    conn.execute(
        "UPDATE datasets SET record_count = ?2, skipped_count = ?3, warnings = ?4, status = ?5
         WHERE id = ?1",
        params![
            dataset_id,
            record_count,
            skipped_count,
            serde_json::to_string(warnings)?,
            status
        ],
    )?;
    Ok(())
}

fn dataset_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Dataset> {
    let warnings: String = row.get("warnings")?;
    Ok(Dataset {
        id: row.get("id")?,
        name: row.get("name")?,
        file_name: row.get("file_name")?,
        file_hash: row.get("file_hash")?,
        file_size: row.get("file_size")?,
        source_type: row.get("source_type")?,
        record_count: row.get("record_count")?,
        skipped_count: row.get("skipped_count")?,
        status: row.get("status")?,
        warnings: serde_json::from_str(&warnings).unwrap_or_default(),
        imported_at: row.get("imported_at")?,
    })
}

pub fn list_datasets(conn: &Connection) -> AppResult<Vec<Dataset>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, file_name, file_hash, file_size, source_type, record_count,
                skipped_count, status, warnings, imported_at
         FROM datasets ORDER BY imported_at DESC",
    )?;
    let rows = stmt.query_map([], dataset_from_row)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn get_dataset_name(conn: &Connection, id: i64) -> AppResult<Option<String>> {
    let mut stmt = conn.prepare("SELECT name FROM datasets WHERE id = ?1")?;
    let mut rows = stmt.query(params![id])?;
    match rows.next()? {
        Some(r) => Ok(Some(r.get(0)?)),
        None => Ok(None),
    }
}

pub fn delete_dataset(conn: &Connection, dataset_id: i64) -> AppResult<()> {
    let tx = conn.unchecked_transaction()?;
    // Alerts are derived findings: drop those whose evidence no longer exists.
    tx.execute(
        "DELETE FROM alert_evidence WHERE kind = 'event' AND ref_id NOT IN (SELECT id FROM events)
           AND ref_id NOT IN (SELECT id FROM events WHERE dataset_id = ?1)",
        params![dataset_id],
    )?;
    tx.execute("DELETE FROM events WHERE dataset_id = ?1", params![dataset_id])?;
    tx.execute("DELETE FROM datasets WHERE id = ?1", params![dataset_id])?;
    tx.execute(
        "DELETE FROM alerts WHERE id NOT IN (SELECT DISTINCT alert_id FROM alert_evidence)",
        [],
    )?;
    tx.commit()?;
    Ok(())
}

// --------------------------------------------------------------- events

/// Insert normalized events in the caller's transaction. Returns the number of rows written.
pub fn insert_events(
    conn: &Connection,
    dataset_id: i64,
    events: &[NormalizedEvent],
) -> AppResult<usize> {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO events (dataset_id, ts, source_type, category, event_type, severity,
             src_ip, dst_ip, src_port, dst_port, transport, app_proto, action, username,
             hostname, process_name, message, attrs, raw)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
             ?18, ?19)",
    )?;
    let mut written = 0usize;
    for e in events {
        let attrs = if e.attrs.is_null() {
            "{}".to_string()
        } else {
            e.attrs.to_string()
        };
        let raw = if e.raw.is_null() {
            r#"{"_missing":true}"#.to_string()
        } else {
            e.raw.to_string()
        };
        stmt.execute(params![
            dataset_id,
            e.ts,
            e.source_type,
            e.category,
            e.event_type,
            e.severity,
            e.src_ip,
            e.dst_ip,
            e.src_port,
            e.dst_port,
            e.transport,
            e.app_proto,
            e.action,
            e.username,
            e.hostname,
            e.process_name,
            e.message,
            attrs,
            raw
        ])?;
        written += 1;
    }
    Ok(written)
}

// -------------------------------------------------------------- settings

pub fn get_setting(conn: &Connection, key: &str) -> AppResult<Option<String>> {
    let mut stmt = conn.prepare("SELECT value FROM settings WHERE key = ?1")?;
    let mut rows = stmt.query(params![key])?;
    match rows.next()? {
        Some(r) => Ok(Some(r.get(0)?)),
        None => Ok(None),
    }
}

pub fn put_setting(conn: &Connection, key: &str, value: &str) -> AppResult<()> {
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}
