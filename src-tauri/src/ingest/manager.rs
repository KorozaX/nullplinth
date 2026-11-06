//! Import manager: hash, duplicate detection, streaming batches, progress events.

use super::{detect, stream_records, Format};
use crate::db::{self, Db};
use crate::error::{AppError, AppResult};
use crate::types::{ImportOptions, ImportProgress, ImportResult, NormalizedEvent};
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

const BATCH_SIZE: usize = 1000;
const PROGRESS_EVERY: i64 = 500;
const MAX_WARNINGS: usize = 500;

/// Tauri command entry point: imports a log file and emits "import-progress" events.
pub fn import(app: &tauri::AppHandle, db: &Db, options: ImportOptions) -> AppResult<ImportResult> {
    use tauri::Emitter;
    import_with_progress(db, &options, &mut |progress: &ImportProgress| {
        let _ = app.emit("import-progress", progress.clone());
    })
}

/// Testable core of the import manager. The progress callback is called every
/// ~500 records and on phase changes; it never touches the source file.
pub fn import_with_progress(
    db: &Db,
    options: &ImportOptions,
    progress: &mut dyn FnMut(&ImportProgress),
) -> AppResult<ImportResult> {
    let started = Instant::now();
    let path = PathBuf::from(options.path.trim());
    if !path.is_file() {
        return Err(AppError::msg(format!(
            "file does not exist: {}",
            path.display()
        )));
    }
    let format = match options.source_type.as_deref() {
        Some(raw) if !raw.trim().is_empty() => Format::from_source_type(raw).ok_or_else(|| {
            AppError::msg(format!(
                "unknown source type '{raw}' (expected json, ndjson, suricata, zeek or csv)"
            ))
        })?,
        _ => detect::detect(&path)?,
    };
    if format == Format::Csv && options.csv.is_none() {
        return Err(AppError::msg(
            "CSV imports need an explicit column mapping; call preview_csv first",
        ));
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_string());
    let size = std::fs::metadata(&path).map(|meta| meta.len() as i64).unwrap_or(0);
    let dataset_name = options
        .name
        .clone()
        .filter(|name| !name.trim().is_empty())
        .or_else(|| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .map(|stem| stem.to_string())
        })
        .unwrap_or_else(|| "import".to_string());

    progress(&ImportProgress {
        dataset_name: dataset_name.clone(),
        phase: "hashing".to_string(),
        processed: 0,
        total: None,
        message: Some("hashing file".to_string()),
    });
    let file_hash = sha256_file(&path)?;

    let conn = db.conn()?;
    if let Some((id, name)) = find_dataset_by_hash(&conn, &file_hash)? {
        return Err(AppError::msg(format!(
            "duplicate file: this exact file was already imported as dataset '{name}' (id {id}); delete that dataset first to import it again"
        )));
    }
    let dataset_id = db::insert_dataset(
        &conn,
        &dataset_name,
        file_name.as_deref(),
        Some(&file_hash),
        Some(size),
        format.as_str(),
    )?;
    conn.execute(
        "UPDATE datasets SET status = 'importing' WHERE id = ?1",
        params![dataset_id],
    )?;
    drop(conn);

    let mut batcher = Batcher::new(db, dataset_id, &dataset_name, progress);
    let stream_result = stream_records(format, &path, options.csv.as_ref(), &mut |index, outcome| {
        batcher.accept(index, outcome)
    });
    if let Err(err) = stream_result {
        batcher.fail();
        return Err(err);
    }
    batcher.finish(started.elapsed().as_millis() as u64)
}

fn sha256_file(path: &Path) -> AppResult<String> {
    let mut file = File::open(path)
        .map_err(|e| AppError::msg(format!("cannot open {}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1 << 16];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest.iter() {
        hex.push_str(&format!("{byte:02x}"));
    }
    Ok(hex)
}

fn find_dataset_by_hash(
    conn: &rusqlite::Connection,
    hash: &str,
) -> AppResult<Option<(i64, String)>> {
    let mut statement =
        conn.prepare("SELECT id, name FROM datasets WHERE file_hash = ?1 ORDER BY id LIMIT 1")?;
    let mut rows = statement.query(params![hash])?;
    match rows.next()? {
        Some(row) => Ok(Some((row.get(0)?, row.get(1)?))),
        None => Ok(None),
    }
}

struct Batcher<'a, 'b> {
    db: &'a Db,
    dataset_id: i64,
    dataset_name: String,
    progress: &'b mut dyn FnMut(&ImportProgress),
    buffer: Vec<NormalizedEvent>,
    imported: i64,
    skipped: i64,
    warnings: Vec<String>,
    warnings_truncated: bool,
    seen: i64,
}

impl<'a, 'b> Batcher<'a, 'b> {
    fn new(
        db: &'a Db,
        dataset_id: i64,
        dataset_name: &str,
        progress: &'b mut dyn FnMut(&ImportProgress),
    ) -> Self {
        Self {
            db,
            dataset_id,
            dataset_name: dataset_name.to_string(),
            progress,
            buffer: Vec::with_capacity(BATCH_SIZE),
            imported: 0,
            skipped: 0,
            warnings: Vec::new(),
            warnings_truncated: false,
            seen: 0,
        }
    }

    fn accept(&mut self, index: i64, outcome: super::RecordOutcome) -> AppResult<()> {
        self.seen += 1;
        match outcome {
            Ok(mut event) => {
                event.dataset_id = self.dataset_id;
                self.buffer.push(event);
                if self.buffer.len() >= BATCH_SIZE {
                    self.flush()?;
                }
            }
            Err(reason) => {
                self.skipped += 1;
                if self.warnings.len() < MAX_WARNINGS {
                    self.warnings.push(format!("record {index}: {reason}"));
                } else if !self.warnings_truncated {
                    self.warnings_truncated = true;
                    self.warnings.push(format!(
                        "additional skipped-record warnings truncated after {MAX_WARNINGS} entries"
                    ));
                }
            }
        }
        if self.seen % PROGRESS_EVERY == 0 {
            self.emit_progress("importing", Some(format!("{} records processed", self.seen)));
        }
        Ok(())
    }

    fn flush(&mut self) -> AppResult<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let conn = self.db.conn()?;
        let transaction = conn.unchecked_transaction()?;
        let written = db::insert_events(&transaction, self.dataset_id, &self.buffer)?;
        transaction.commit()?;
        self.imported += written as i64;
        self.buffer.clear();
        Ok(())
    }

    fn emit_progress(&mut self, phase: &str, message: Option<String>) {
        let progress = ImportProgress {
            dataset_name: self.dataset_name.clone(),
            phase: phase.to_string(),
            processed: self.seen,
            total: None,
            message,
        };
        (self.progress)(&progress);
    }

    fn finish(mut self, duration_ms: u64) -> AppResult<ImportResult> {
        self.flush()?;
        let conn = self.db.conn()?;
        db::finish_dataset(
            &conn,
            self.dataset_id,
            self.imported,
            self.skipped,
            &self.warnings,
            "completed",
        )?;
        self.emit_progress(
            "done",
            Some(format!(
                "imported {} records, skipped {}",
                self.imported, self.skipped
            )),
        );
        Ok(ImportResult {
            dataset_id: self.dataset_id,
            imported: self.imported,
            skipped: self.skipped,
            warnings: self.warnings,
            duration_ms,
        })
    }

    fn fail(&mut self) {
        self.buffer.clear();
        if let Ok(conn) = self.db.conn() {
            let _ = db::finish_dataset(
                &conn,
                self.dataset_id,
                self.imported,
                self.skipped,
                &self.warnings,
                "failed",
            );
        }
    }
}
