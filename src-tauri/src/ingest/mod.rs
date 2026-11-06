//! Import manager: format detection, parsing, normalization and storage.
//!
//! OWNER: data-engine teammate. The public signatures below are the contract the
//! commands layer calls; keep them stable.

pub mod csv_import;
pub mod detect;
pub mod firewall;
pub mod generic_text;
pub mod json;
pub mod linux_auth;
pub mod manager;
pub mod normalize;
pub mod suricata;
pub mod syslog;
pub mod web_access;
pub mod zeek;

use crate::error::{AppError, AppResult};
use crate::types::{CsvMapping, CsvPreview, ImportOptions, ImportPreview, ImportResult, NormalizedEvent};
use std::path::Path;

pub use detect::Format;
pub use manager::import_with_progress;

/// One parsed record: the normalized event, or the reason it was skipped.
pub type RecordOutcome = Result<NormalizedEvent, String>;

/// OWNER: data-engine. Inspect any file and report the detected format with samples,
/// so the UI can warn before importing an unfamiliar log.
pub fn preview_import(path: &str) -> AppResult<ImportPreview> {
    let detection = detect::detect_full(Path::new(path))?;
    Ok(ImportPreview {
        format: detection.format.as_str().to_string(),
        format_label: detection.format.label().to_string(),
        confidence: detection.confidence,
        sample_lines: detection.sample_lines,
        estimated_records: detection.estimated_records,
        warnings: detection.warnings,
    })
}

/// Read the first rows of a CSV file so the UI can ask the user for a mapping.
pub fn preview_csv(path: &str) -> AppResult<CsvPreview> {
    csv_import::preview(path)
}

/// Import a log file into the database. Emits "import-progress" app events.
pub fn import(
    app: &tauri::AppHandle,
    db: &crate::db::Db,
    options: ImportOptions,
) -> AppResult<ImportResult> {
    manager::import(app, db, options)
}

/// Detect the format of a log file (extension first, then content sniffing).
pub fn detect_format(path: &str) -> AppResult<Format> {
    detect::detect(Path::new(path))
}

/// Parse a whole file without touching the database. Returns the normalized
/// events plus one warning string per skipped record. Used by the test suite.
pub fn parse_all(
    format: Format,
    path: &str,
    csv: Option<&CsvMapping>,
) -> AppResult<(Vec<NormalizedEvent>, Vec<String>)> {
    let mut events = Vec::new();
    let mut warnings = Vec::new();
    stream_records(format, Path::new(path), csv, &mut |index, outcome| {
        match outcome {
            Ok(event) => events.push(event),
            Err(reason) => warnings.push(format!("record {index}: {reason}")),
        }
        Ok(())
    })?;
    Ok((events, warnings))
}

/// Stream records from a file. Parsers report per-record failures through the
/// sink; only I/O and database errors abort the import.
pub(crate) fn stream_records(
    format: Format,
    path: &Path,
    csv: Option<&CsvMapping>,
    sink: &mut dyn FnMut(i64, RecordOutcome) -> AppResult<()>,
) -> AppResult<()> {
    let source_type = format.as_str();
    let mut wrapper = |index: i64, outcome: RecordOutcome| -> AppResult<()> {
        let outcome = outcome.map(|mut event| {
            event.source_type = source_type.to_string();
            event
        });
        sink(index, outcome)
    };
    match format {
        Format::JsonArray => json::stream_array(path, source_type, &mut wrapper),
        Format::Ndjson => json::stream_ndjson(path, source_type, &mut wrapper),
        Format::Suricata => suricata::stream(path, &mut wrapper),
        Format::Zeek => zeek::stream(path, &mut wrapper),
        Format::Csv => match csv {
            Some(mapping) => csv_import::stream(path, mapping, &mut wrapper),
            None => Err(AppError::msg(
                "CSV imports need an explicit column mapping; call preview_csv first",
            )),
        },
        Format::LinuxAuth => linux_auth::stream(path, &mut wrapper),
        Format::Syslog => syslog::stream(path, &mut wrapper),
        Format::WebAccess => web_access::stream(path, &mut wrapper),
        Format::Firewall => firewall::stream(path, &mut wrapper),
        Format::GenericText => generic_text::stream(path, &mut wrapper),
    }
}