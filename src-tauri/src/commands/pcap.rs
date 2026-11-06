use crate::error::{blocking, AppResult};
use crate::state::AppState;
use crate::types::*;

#[tauri::command]
pub async fn import_pcap(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
) -> AppResult<Capture> {
    let db = state.db.clone();
    blocking(move || crate::pcap::import(&app, &db, &path)).await
}

#[tauri::command]
pub async fn list_captures(state: tauri::State<'_, AppState>) -> AppResult<Vec<Capture>> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::pcap::list_captures(&conn)
    })
    .await
}

#[tauri::command]
pub async fn delete_capture(state: tauri::State<'_, AppState>, capture_id: i64) -> AppResult<()> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::pcap::delete_capture(&conn, capture_id)
    })
    .await
}

#[tauri::command]
pub async fn search_packets(
    state: tauri::State<'_, AppState>,
    query: PacketQuery,
) -> AppResult<PacketPage> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::pcap::search_packets(&conn, &query)
    })
    .await
}

#[tauri::command]
pub async fn get_packet(
    state: tauri::State<'_, AppState>,
    packet_id: i64,
) -> AppResult<PacketDetail> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::pcap::get_packet(&conn, packet_id)
    })
    .await
}

#[tauri::command]
pub async fn list_flows(
    state: tauri::State<'_, AppState>,
    capture_id: Option<i64>,
) -> AppResult<Vec<FlowRow>> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::pcap::list_flows(&conn, capture_id)
    })
    .await
}

#[tauri::command]
pub async fn get_flow_packets(
    state: tauri::State<'_, AppState>,
    flow_id: i64,
) -> AppResult<Vec<PacketRow>> {
    let db = state.db.clone();
    blocking(move || {
        let conn = db.conn()?;
        crate::pcap::flow_packets(&conn, flow_id)
    })
    .await
}
