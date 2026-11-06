//! Offline PCAP / PCAPNG parsing, protocol decoding and conversation grouping.
//!
//! OWNER: network teammate. Signatures are the contract used by commands/pcap.rs.

use crate::db::Db;
use crate::error::{AppError, AppResult};
use crate::types::{Capture, FlowRow, PacketDetail, PacketPage, PacketQuery, PacketRow};
use rusqlite::Connection;

pub fn import(_app: &tauri::AppHandle, _db: &Db, _path: &str) -> AppResult<Capture> {
    Err(AppError::msg("PCAP import is not implemented yet"))
}

pub fn list_captures(_conn: &Connection) -> AppResult<Vec<Capture>> {
    Ok(vec![])
}

pub fn delete_capture(_conn: &Connection, _capture_id: i64) -> AppResult<()> {
    Ok(())
}

pub fn search_packets(_conn: &Connection, _query: &PacketQuery) -> AppResult<PacketPage> {
    Err(AppError::msg("packet search is not implemented yet"))
}

pub fn get_packet(_conn: &Connection, _packet_id: i64) -> AppResult<PacketDetail> {
    Err(AppError::msg("packet detail is not implemented yet"))
}

pub fn list_flows(_conn: &Connection, _capture_id: Option<i64>) -> AppResult<Vec<FlowRow>> {
    Ok(vec![])
}

pub fn flow_packets(_conn: &Connection, _flow_id: i64) -> AppResult<Vec<PacketRow>> {
    Ok(vec![])
}
