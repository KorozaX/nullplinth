use crate::error::{blocking, AppResult};
use crate::state::AppState;
use crate::types::*;

#[tauri::command]
pub async fn search_events(
    state: tauri::State<'_, AppState>,
    query: EventQuery,
) -> AppResult<EventPage> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::query::query_events(&conn, &query)
    })
    .await
}

#[tauri::command]
pub async fn get_event(state: tauri::State<'_, AppState>, event_id: i64) -> AppResult<EventDetail> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::query::get_event(&conn, event_id)
    })
    .await
}

#[tauri::command]
pub async fn export_events(
    state: tauri::State<'_, AppState>,
    request: ExportRequest,
) -> AppResult<String> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::export::export_events(&conn, &request)
    })
    .await
}
