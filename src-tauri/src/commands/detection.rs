use crate::error::{blocking, AppResult};
use crate::state::AppState;
use crate::types::*;

#[tauri::command]
pub async fn run_detection(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> AppResult<DetectionRun> {
    let db = state.db.clone();
    blocking(move || crate::detection::run(&app, &db)).await
}

#[tauri::command]
pub async fn list_alerts(
    state: tauri::State<'_, AppState>,
    severity: Option<String>,
    status: Option<String>,
) -> AppResult<Vec<Alert>> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::detection::list_alerts(&conn, severity.as_deref(), status.as_deref())
    })
    .await
}

#[tauri::command]
pub async fn get_alert(state: tauri::State<'_, AppState>, alert_id: i64) -> AppResult<AlertDetail> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::detection::get_alert(&conn, alert_id)
    })
    .await
}

#[tauri::command]
pub async fn update_alert_status(
    state: tauri::State<'_, AppState>,
    alert_id: i64,
    status: Option<String>,
    note: Option<String>,
) -> AppResult<()> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::detection::update_alert(&conn, alert_id, status.as_deref(), note.as_deref())
    })
    .await
}
