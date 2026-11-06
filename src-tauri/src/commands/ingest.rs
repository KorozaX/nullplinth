use crate::error::{blocking, AppResult};
use crate::state::AppState;
use crate::types::*;

#[tauri::command]
pub async fn preview_csv(path: String) -> AppResult<CsvPreview> {
    blocking(move || crate::ingest::preview_csv(&path)).await
}

#[tauri::command]
pub async fn import_file(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    options: ImportOptions,
) -> AppResult<ImportResult> {
    let db = state.db.clone();
    blocking(move || crate::ingest::import(&app, &db, options)).await
}
