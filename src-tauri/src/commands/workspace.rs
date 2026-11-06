use crate::error::{blocking, AppResult};
use crate::state::AppState;
use crate::types::{AppPreferences, WorkspaceClearResult, WorkspaceState};

#[tauri::command]
pub async fn workspace_state(state: tauri::State<'_, AppState>) -> AppResult<WorkspaceState> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::workspace::state(&conn)
    })
    .await
}

#[tauri::command]
pub async fn clear_workspace(
    state: tauri::State<'_, AppState>,
    backup_path: Option<String>,
) -> AppResult<WorkspaceClearResult> {
    let db = state.db.clone();
    blocking(move || crate::workspace::clear(&db, backup_path.as_deref())).await
}

#[tauri::command]
pub async fn get_preferences(state: tauri::State<'_, AppState>) -> AppResult<AppPreferences> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::workspace::preferences(&conn)
    })
    .await
}

#[tauri::command]
pub async fn save_preferences(
    state: tauri::State<'_, AppState>,
    preferences: AppPreferences,
) -> AppResult<AppPreferences> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::workspace::save_preferences(&conn, &preferences)
    })
    .await
}
