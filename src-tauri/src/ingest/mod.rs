//! Import manager: format detection, parsing, normalization and storage.
//!
//! OWNER: data-engine teammate. The public signatures below are the contract the
//! commands layer calls; keep them stable.

use crate::db::Db;
use crate::error::{AppError, AppResult};
use crate::types::{CsvPreview, ImportOptions, ImportResult};

pub fn preview_csv(_path: &str) -> AppResult<CsvPreview> {
    Err(AppError::msg("CSV preview is not implemented yet"))
}

pub fn import(
    _app: &tauri::AppHandle,
    _db: &Db,
    _options: ImportOptions,
) -> AppResult<ImportResult> {
    Err(AppError::msg("import is not implemented yet"))
}
