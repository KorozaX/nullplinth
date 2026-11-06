use crate::error::{blocking, AppResult};
use crate::state::AppState;
use crate::types::*;

#[tauri::command]
pub async fn create_investigation(
    state: tauri::State<'_, AppState>,
    input: NewInvestigation,
) -> AppResult<InvestigationDetail> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::investigation::create(&conn, input)
    })
    .await
}

#[tauri::command]
pub async fn list_investigations(
    state: tauri::State<'_, AppState>,
) -> AppResult<Vec<Investigation>> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::investigation::list(&conn)
    })
    .await
}

#[tauri::command]
pub async fn get_investigation(
    state: tauri::State<'_, AppState>,
    investigation_id: i64,
) -> AppResult<InvestigationDetail> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::investigation::get(&conn, investigation_id)
    })
    .await
}

#[tauri::command]
pub async fn update_investigation(
    state: tauri::State<'_, AppState>,
    investigation_id: i64,
    title: Option<String>,
    description: Option<String>,
    status: Option<String>,
) -> AppResult<InvestigationDetail> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::investigation::update(
            &conn,
            investigation_id,
            title.as_deref(),
            description.as_deref(),
            status.as_deref(),
        )
    })
    .await
}

#[tauri::command]
pub async fn add_investigation_note(
    state: tauri::State<'_, AppState>,
    investigation_id: i64,
    body: String,
) -> AppResult<InvestigationDetail> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::investigation::add_note(&conn, investigation_id, &body)
    })
    .await
}

#[tauri::command]
pub async fn attach_alert_to_investigation(
    state: tauri::State<'_, AppState>,
    investigation_id: i64,
    alert_id: i64,
) -> AppResult<InvestigationDetail> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::investigation::attach_alert(&conn, investigation_id, alert_id)
    })
    .await
}

#[tauri::command]
pub async fn export_investigation(
    state: tauri::State<'_, AppState>,
    investigation_id: i64,
    path: String,
) -> AppResult<String> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::export::export_investigation(&conn, investigation_id, &path)
    })
    .await
}
