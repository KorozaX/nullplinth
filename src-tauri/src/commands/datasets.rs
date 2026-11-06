use crate::db;
use crate::error::{blocking, AppResult};
use crate::state::AppState;
use crate::types::{Dataset, DetectionSettings, ImportResult, Overview};

#[tauri::command]
pub async fn list_datasets(state: tauri::State<'_, AppState>) -> AppResult<Vec<Dataset>> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        db::list_datasets(&conn)
    })
    .await
}

#[tauri::command]
pub async fn delete_dataset(state: tauri::State<'_, AppState>, dataset_id: i64) -> AppResult<()> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        db::delete_dataset(&conn, dataset_id)
    })
    .await
}

#[tauri::command]
pub async fn get_overview(state: tauri::State<'_, AppState>) -> AppResult<Overview> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::query::overview(&conn)
    })
    .await
}

#[tauri::command]
pub async fn get_settings(state: tauri::State<'_, AppState>) -> AppResult<DetectionSettings> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        let raw = db::get_setting(&conn, "detection")?;
        Ok(raw
            .and_then(|v| serde_json::from_str(&v).ok())
            .unwrap_or_default())
    })
    .await
}

#[tauri::command]
pub async fn save_settings(
    state: tauri::State<'_, AppState>,
    settings: DetectionSettings,
) -> AppResult<DetectionSettings> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        db::put_setting(&conn, "detection", &serde_json::to_string(&settings)?)?;
        Ok(settings)
    })
    .await
}

#[tauri::command]
pub async fn load_demo_data(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> AppResult<ImportResult> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::demo::load(&app, &conn)
    })
    .await
}