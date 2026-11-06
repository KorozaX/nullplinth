//! Offline PCAP / PCAPNG parsing, protocol decoding and conversation grouping.
//!
//! OWNER: network teammate. Signatures are the contract used by commands/pcap.rs.
//!
//! Reading and decoding happen in the submodules; this module owns persistence and
//! the query surface. Every user supplied filter value is bound as a SQLite parameter.

mod decode;
mod reader;
mod wifi;

use crate::db::Db;
use crate::error::{AppError, AppResult};
use crate::types::{Capture, FlowRow, LayerNode, PacketDetail, PacketPage, PacketQuery, PacketRow};
use rusqlite::types::Value;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::time::Instant;

const BATCH_SIZE: usize = 500;
/// How many packets between progress events during import.
const PROGRESS_STEP: i64 = 250;

pub const PACKET_COLUMNS: &str = "id, capture_id, packet_no, ts, caplen, origlen, src_ip, dst_ip, \
    src_port, dst_port, protocol, transport, tcp_flags, payload_len, summary, frame_kind, encrypted";
const CAPTURE_COLUMNS: &str = "id, name, file_name, file_hash, file_size, link_type, \
    packet_count, imported_at";
const FLOW_COLUMNS: &str = "id, capture_id, src_ip, src_port, dst_ip, dst_port, transport, \
    packet_count, bytes_total, first_ts, last_ts";

/// Progress payload emitted as the "pcap-progress" Tauri event during a capture import.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PcapProgress {
    pub capture_name: String,
    pub file_name: String,
    pub phase: String,
    pub processed: i64,
    pub total: Option<i64>,
    pub message: Option<String>,
}

// ------------------------------------------------------------------ import

/// Import a capture file. Emits "pcap-progress" events while the packets are stored.
pub fn import(app: &tauri::AppHandle, db: &Db, path: &str) -> AppResult<Capture> {
    use tauri::Emitter;
    let conn = db.conn()?;
    let capture_name = capture_name_hint(path);
    let file_name = file_name_hint(path);
    let mut last_emit: i64 = -1;
    import_with_progress(&conn, path, |processed, total| {
        let done = total.map(|t| processed >= t).unwrap_or(false);
        if done || processed - last_emit >= PROGRESS_STEP {
            last_emit = processed;
            let _ = app.emit(
                "pcap-progress",
                PcapProgress {
                    capture_name: capture_name.clone(),
                    file_name: file_name.clone(),
                    phase: if done { "done" } else { "importing" }.to_string(),
                    processed,
                    total,
                    message: None,
                },
            );
        }
    })
}

/// Core import used by the command layer and by the tests (no Tauri handle needed).
pub fn import_core(conn: &Connection, path: &str) -> AppResult<Capture> {
    import_with_progress(conn, path, |_, _| {})
}

/// Import with a progress callback receiving (packets_stored, total_or_none).
pub fn import_with_progress<F>(conn: &Connection, path: &str, progress: F) -> AppResult<Capture>
where
    F: FnMut(i64, Option<i64>),
{
    import_inner(conn, path, None, progress)
}

/// Import at most max_packets packets. Used to sample very large real-world
/// captures in tests without paying the full decode/storage cost.
pub fn import_core_limited(conn: &Connection, path: &str, max_packets: u32) -> AppResult<Capture> {
    import_inner(conn, path, Some(max_packets as i64), |_, _| {})
}

fn import_inner<F>(
    conn: &Connection,
    path: &str,
    limit: Option<i64>,
    mut progress: F,
) -> AppResult<Capture>
where
    F: FnMut(i64, Option<i64>),
{
    let path_obj = std::path::Path::new(path);
    let metadata = std::fs::metadata(path_obj).map_err(|e| {
        AppError::msg(format!("cannot read capture file '{path}': {e}"))
    })?;
    if !metadata.is_file() {
        return Err(AppError::msg(format!("'{path}' is not a capture file")));
    }
    let file_size = metadata.len() as i64;
    let file_name = file_name_hint(path);
    let name = capture_name_hint(path);
    let file_hash = sha256_file(path)?;

    // Duplicate-file detection: identical bytes already imported -> return that capture.
    let existing: Option<i64> = conn
        .query_row(
            "SELECT id FROM packet_captures WHERE file_hash = ?1 ORDER BY id LIMIT 1",
            params![file_hash],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(capture_id) = existing {
        return get_capture(conn, capture_id);
    }

    conn.execute(
        "INSERT INTO packet_captures (name, file_name, file_hash, file_size, link_type,
            packet_count, imported_at)
         VALUES (?1, ?2, ?3, ?4, NULL, 0, ?5)",
        params![name, file_name, file_hash, file_size, crate::db::now_ms()],
    )?;
    let capture_id = conn.last_insert_rowid();
    progress(0, None);

    let outcome = read_and_store(conn, capture_id, path, limit, &mut progress);
    match outcome {
        Ok((meta, packet_count)) => {
            conn.execute(
                "UPDATE packet_captures SET link_type = ?2, packet_count = ?3 WHERE id = ?1",
                params![capture_id, meta.link_type_label(), packet_count],
            )?;
            progress(packet_count, Some(packet_count));
            let _: &Vec<String> = &meta.warnings;
            get_capture(conn, capture_id)
        }
        Err(e) => {
            // Never leave a half imported capture behind.
            let _ = delete_capture(conn, capture_id);
            Err(e)
        }
    }
}

fn read_and_store<F>(
    conn: &Connection,
    capture_id: i64,
    path: &str,
    limit: Option<i64>,
    progress: &mut F,
) -> AppResult<(reader::CaptureMeta, i64)>
where
    F: FnMut(i64, Option<i64>),
{
    let mut batch: Vec<PendingPacket> = Vec::with_capacity(BATCH_SIZE);
    let mut flows: HashMap<FlowKey, FlowAgg> = HashMap::new();
    let mut processed: i64 = 0;
    let mut stored: i64 = 0;

    let (meta, _total) = reader::read_capture(path, |raw| {
        processed += 1;
        if let Some(limit) = limit {
            if stored >= limit {
                return Ok(());
            }
        }
        let decoded = decode::decode_frame(raw.link_type, &raw.data);
        if let Some(key) = FlowKey::from_decoded(&decoded) {
            let agg = flows.entry(key).or_insert_with(FlowAgg::new);
            agg.packet_count += 1;
            agg.bytes_total += raw.origlen as i64;
            agg.first_ts = agg.first_ts.min(raw.ts_ms);
            agg.last_ts = agg.last_ts.max(raw.ts_ms);
        }
        batch.push(PendingPacket {
            packet_no: raw.packet_no,
            ts: raw.ts_ms,
            caplen: raw.caplen,
            origlen: raw.origlen,
            data: raw.data.clone(),
            decoded,
        });
        stored += 1;
        if batch.len() >= BATCH_SIZE {
            flush_packets(conn, capture_id, &batch)?;
            batch.clear();
        }
        progress(processed, limit);
        Ok(())
    })?;

    flush_packets(conn, capture_id, &batch)?;
    insert_flows(conn, capture_id, &flows)?;
    Ok((meta, stored))
}

struct PendingPacket {
    packet_no: u32,
    ts: i64,
    caplen: u32,
    origlen: u32,
    data: Vec<u8>,
    decoded: decode::Decoded,
}

fn flush_packets(conn: &Connection, capture_id: i64, batch: &[PendingPacket]) -> AppResult<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO packets (capture_id, packet_no, ts, caplen, origlen, src_ip, dst_ip,
                src_port, dst_port, protocol, transport, tcp_flags, payload_len, summary, layers,
                raw_hex, frame_kind, encrypted)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
        )?;
        for p in batch {
            let layers = serde_json::to_string(&p.decoded.layers)?;
            stmt.execute(params![
                capture_id,
                p.packet_no as i64,
                p.ts,
                p.caplen as i64,
                p.origlen as i64,
                p.decoded.src_ip,
                p.decoded.dst_ip,
                p.decoded.src_port,
                p.decoded.dst_port,
                p.decoded.protocol,
                p.decoded.transport,
                p.decoded.tcp_flags,
                p.decoded.payload_len,
                p.decoded.summary,
                layers,
                hex_spaced(&p.data),
                p.decoded.frame_kind,
                p.decoded.encrypted as i64,
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

// ------------------------------------------------------------------- flows

#[derive(Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    src_ip: String,
    src_port: Option<i64>,
    dst_ip: String,
    dst_port: Option<i64>,
    transport: String,
}

impl FlowKey {
    /// Bidirectional key: the two endpoints are sorted so both directions land in
    /// the same conversation. Packets without a transport protocol we group are skipped.
    fn from_decoded(d: &decode::Decoded) -> Option<FlowKey> {
        let src_ip = d.src_ip.clone()?;
        let dst_ip = d.dst_ip.clone()?;
        let transport = match d.transport.as_deref() {
            Some(t) => t.to_ascii_lowercase(),
            None => match d.protocol.as_str() {
                "ICMP" => "icmp".to_string(),
                "ICMPv6" => "icmpv6".to_string(),
                _ => return None,
            },
        };
        let (a, b) = canonical_endpoints((src_ip, d.src_port), (dst_ip, d.dst_port));
        Some(FlowKey {
            src_ip: a.0,
            src_port: a.1,
            dst_ip: b.0,
            dst_port: b.1,
            transport,
        })
    }
}

fn canonical_endpoints(
    a: (String, Option<i64>),
    b: (String, Option<i64>),
) -> ((String, Option<i64>), (String, Option<i64>)) {
    if (a.0.as_str(), a.1) <= (b.0.as_str(), b.1) {
        (a, b)
    } else {
        (b, a)
    }
}

struct FlowAgg {
    packet_count: i64,
    bytes_total: i64,
    first_ts: i64,
    last_ts: i64,
}

impl FlowAgg {
    fn new() -> Self {
        FlowAgg {
            packet_count: 0,
            bytes_total: 0,
            first_ts: i64::MAX,
            last_ts: i64::MIN,
        }
    }
}

fn insert_flows(
    conn: &Connection,
    capture_id: i64,
    flows: &HashMap<FlowKey, FlowAgg>,
) -> AppResult<()> {
    if flows.is_empty() {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO flows (capture_id, src_ip, src_port, dst_ip, dst_port, transport,
                packet_count, bytes_total, first_ts, last_ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )?;
        for (key, agg) in flows {
            if agg.packet_count == 0 {
                continue;
            }
            stmt.execute(params![
                capture_id,
                key.src_ip,
                key.src_port,
                key.dst_ip,
                key.dst_port,
                key.transport,
                agg.packet_count,
                agg.bytes_total,
                if agg.first_ts == i64::MAX { 0 } else { agg.first_ts },
                if agg.last_ts == i64::MIN { 0 } else { agg.last_ts },
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

// ---------------------------------------------------------------- captures

fn capture_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Capture> {
    Ok(Capture {
        id: row.get("id")?,
        name: row.get("name")?,
        file_name: row.get("file_name")?,
        file_hash: row.get("file_hash")?,
        file_size: row.get("file_size")?,
        link_type: row.get("link_type")?,
        packet_count: row.get("packet_count")?,
        imported_at: row.get("imported_at")?,
    })
}

pub fn get_capture(conn: &Connection, capture_id: i64) -> AppResult<Capture> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {CAPTURE_COLUMNS} FROM packet_captures WHERE id = ?1"
    ))?;
    let mut rows = stmt.query(params![capture_id])?;
    match rows.next()? {
        Some(row) => Ok(capture_from_row(row)?),
        None => Err(AppError::msg(format!("capture {capture_id} not found"))),
    }
}

pub fn list_captures(conn: &Connection) -> AppResult<Vec<Capture>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {CAPTURE_COLUMNS} FROM packet_captures ORDER BY imported_at DESC, id DESC"
    ))?;
    let rows = stmt.query_map([], capture_from_row)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

pub fn delete_capture(conn: &Connection, capture_id: i64) -> AppResult<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute("DELETE FROM packets WHERE capture_id = ?1", params![capture_id])?;
    tx.execute("DELETE FROM flows WHERE capture_id = ?1", params![capture_id])?;
    tx.execute("DELETE FROM packet_captures WHERE id = ?1", params![capture_id])?;
    tx.commit()?;
    Ok(())
}

// ---------------------------------------------------------------- queries

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Text,
    Int,
    Ip,
    Bool,
}

fn packet_field(field: &str) -> Option<(&'static str, Kind)> {
    let def = match field {
        "srcIp" => ("src_ip", Kind::Ip),
        "dstIp" => ("dst_ip", Kind::Ip),
        "srcPort" => ("src_port", Kind::Int),
        "dstPort" => ("dst_port", Kind::Int),
        "protocol" => ("protocol", Kind::Text),
        "transport" => ("transport", Kind::Text),
        "tcpFlags" => ("tcp_flags", Kind::Text),
        "summary" => ("summary", Kind::Text),
        "packetLength" => ("origlen", Kind::Int),
        "frameLength" => ("caplen", Kind::Int),
        "payloadLength" => ("payload_len", Kind::Int),
        "frameKind" => ("frame_kind", Kind::Text),
        "encrypted" => ("encrypted", Kind::Bool),
        _ => return None,
    };
    Some(def)
}

fn valid_packet_value(kind: Kind, op: &str, value: &str) -> AppResult<()> {
    match kind {
        Kind::Int => {
            if op == "exists" || op == "notExists" {
                return Ok(());
            }
            value
                .parse::<i64>()
                .map_err(|_| AppError::msg(format!("'{value}' is not a whole number")))?;
        }
        Kind::Ip => {
            if op == "inCidr" {
                value.parse::<ipnet::IpNet>().map_err(|_| {
                    AppError::msg(format!(
                        "'{value}' is not a valid CIDR range (for example 10.0.0.0/8)"
                    ))
                })?;
            } else if op != "exists" && op != "notExists" {
                value.parse::<std::net::IpAddr>().map_err(|_| {
                    AppError::msg(format!("'{value}' is not a valid IP address"))
                })?;
            }
        }
        Kind::Bool => {
            if op == "exists" || op == "notExists" {
                return Ok(());
            }
            match value.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => {}
                "false" | "0" | "no" => {}
                _ => return Err(AppError::msg(format!("'{value}' is not true or false"))),
            }
        }
        Kind::Text => {}
    }
    Ok(())
}

fn build_packet_where(query: &PacketQuery) -> AppResult<(String, Vec<Value>)> {
    let mut clause = String::from(" WHERE 1 = 1");
    let mut args: Vec<Value> = Vec::new();

    if let Some(capture_id) = query.capture_id {
        clause.push_str(" AND capture_id = ?");
        args.push(Value::Integer(capture_id));
    }
    if let Some(from) = query.from_ts {
        clause.push_str(" AND ts >= ?");
        args.push(Value::Integer(from));
    }
    if let Some(to) = query.to_ts {
        clause.push_str(" AND ts <= ?");
        args.push(Value::Integer(to));
    }

    for filter in &query.filters {
        let (col, kind) = packet_field(filter.field.trim()).ok_or_else(|| {
            AppError::msg(format!("unknown packet field '{}'", filter.field))
        })?;
        valid_packet_value(kind, &filter.op, &filter.value)?;
        let cond = match filter.op.as_str() {
            "eq" => Some(format!("{col} = ? COLLATE NOCASE")),
            "neq" => Some(format!("({col} IS NULL OR {col} <> ? COLLATE NOCASE)")),
            "contains" => Some(format!("{col} LIKE ? ESCAPE '\\'")),
            "notContains" => Some(format!("({col} IS NULL OR {col} NOT LIKE ? ESCAPE '\\')")),
            "startsWith" => Some(format!("{col} LIKE ? ESCAPE '\\'")),
            "gt" => Some(format!("{col} > ?")),
            "lt" => Some(format!("{col} < ?")),
            "exists" => Some(format!("({col} IS NOT NULL AND {col} <> '')")),
            "notExists" => Some(format!("({col} IS NULL OR {col} = '')")),
            "inCidr" => Some(format!("ip_in_cidr({col}, ?) = 1")),
            other => {
                return Err(AppError::msg(format!(
                    "unknown filter operator '{other}'"
                )))
            }
        };
        clause.push_str(" AND ");
        clause.push_str(&cond.unwrap());
        match (filter.op.as_str(), kind) {
            ("exists" | "notExists", _) => {}
            ("contains" | "notContains" | "startsWith", _) => {
                let escaped = filter
                    .value
                    .replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_");
                args.push(Value::Text(match filter.op.as_str() {
                    "startsWith" => format!("{escaped}%"),
                    _ => format!("%{escaped}%"),
                }));
            }
            ("gt" | "lt", Kind::Int) => args.push(Value::Integer(filter.value.parse::<i64>().map_err(
                |_| AppError::msg("expected a whole number"),
            )?)),
            ("gt" | "lt", _) => args.push(Value::Text(filter.value.clone())),
            (_, Kind::Bool) => {
                let flag = matches!(
                    filter.value.trim().to_ascii_lowercase().as_str(),
                    "true" | "1" | "yes"
                );
                args.push(Value::Integer(if flag { 1 } else { 0 }));
            }
            _ => args.push(Value::Text(filter.value.clone())),
        }
    }
    Ok((clause, args))
}

fn register_ip_in_cidr(conn: &Connection) {
    use rusqlite::functions::FunctionFlags;
    let flags = FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC;
    // Another module may register the same helper on this connection; ignore that.
    let _ = conn.create_scalar_function("ip_in_cidr", 2, flags, |ctx| {
        let ip: Option<String> = ctx.get(0)?;
        let cidr: String = ctx.get(1)?;
        let Some(ip) = ip.filter(|v| !v.is_empty()) else {
            return Ok(0i64);
        };
        let Ok(ip) = ip.parse::<std::net::IpAddr>() else {
            return Ok(0i64);
        };
        let Ok(net) = cidr.parse::<ipnet::IpNet>() else {
            return Ok(0i64);
        };
        Ok(if net.contains(&ip) { 1i64 } else { 0i64 })
    });
}

fn packet_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PacketRow> {
    Ok(PacketRow {
        frame_kind: row.get("frame_kind")?,
        encrypted: row.get::<_, bool>("encrypted")?,
        id: row.get("id")?,
        capture_id: row.get("capture_id")?,
        packet_no: row.get("packet_no")?,
        ts: row.get("ts")?,
        caplen: row.get("caplen")?,
        origlen: row.get("origlen")?,
        src_ip: row.get("src_ip")?,
        dst_ip: row.get("dst_ip")?,
        src_port: row.get("src_port")?,
        dst_port: row.get("dst_port")?,
        protocol: row.get("protocol")?,
        transport: row.get("transport")?,
        tcp_flags: row.get("tcp_flags")?,
        payload_len: row.get("payload_len")?,
        summary: row.get("summary")?,
    })
}

fn sort_expression(sort: &str) -> &'static str {
    match sort {
        "packetNo" => "packet_no",
        "srcIp" => "src_ip",
        "dstIp" => "dst_ip",
        "srcPort" => "src_port",
        "dstPort" => "dst_port",
        "protocol" => "protocol",
        "transport" => "transport",
        "caplen" => "caplen",
        "origlen" => "origlen",
        "payloadLen" | "payloadLength" => "payload_len",
        "summary" => "summary",
        _ => "ts",
    }
}

pub fn search_packets(conn: &Connection, query: &PacketQuery) -> AppResult<PacketPage> {
    let started = Instant::now();
    register_ip_in_cidr(conn);
    let (clause, args) = build_packet_where(query)?;

    let total: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM packets{clause}"),
        params_from_iter(args.iter()),
        |row| row.get(0),
    )?;

    let sort = sort_expression(query.sort.as_str());
    let dir = if query.sort_dir.eq_ignore_ascii_case("asc") {
        "ASC"
    } else {
        "DESC"
    };
    let page_size = query.page_size.clamp(1, 500) as i64;
    let offset = (query.page as i64) * page_size;
    let sql = format!(
        "SELECT {PACKET_COLUMNS} FROM packets{clause} ORDER BY {sort} {dir}, id DESC LIMIT ? OFFSET ?"
    );
    let mut all = args;
    all.push(Value::Integer(page_size));
    all.push(Value::Integer(offset));
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(all.iter()), packet_from_row)?;
    let mut packets = Vec::new();
    for row in rows {
        packets.push(row?);
    }
    Ok(PacketPage {
        total,
        packets,
        page: query.page,
        page_size: page_size as u32,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

fn unsupported_link_type(link_type: &str) -> Option<String> {
    let supported = link_type.starts_with("Ethernet")
        || link_type.starts_with("Raw IPv4")
        || link_type.starts_with("Raw IPv6")
        || link_type.starts_with("Raw IP")
        || link_type.starts_with("IEEE 802.11");
    if supported {
        None
    } else {
        Some(format!(
            "Unsupported link type {link_type}: raw bytes preserved, payload not decoded"
        ))
    }
}

pub fn get_packet(conn: &Connection, packet_id: i64) -> AppResult<PacketDetail> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {PACKET_COLUMNS}, layers, raw_hex FROM packets WHERE id = ?1"
    ))?;
    let mut rows = stmt.query(params![packet_id])?;
    let row = rows
        .next()?
        .ok_or_else(|| AppError::msg(format!("packet {packet_id} not found")))?;
    let packet = packet_from_row(row)?;
    let layers_json: String = row.get("layers")?;
    let hex: String = row.get("raw_hex")?;
    let layers: Vec<LayerNode> = serde_json::from_str(&layers_json).unwrap_or_default();
    let link_type: Option<String> = conn
        .query_row(
            "SELECT link_type FROM packet_captures WHERE id = ?1",
            params![packet.capture_id],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    let unsupported = match link_type.as_deref() {
        Some(lt) => unsupported_link_type(lt),
        None => None,
    };
    Ok(PacketDetail {
        packet,
        layers,
        ascii: ascii_dump(&hex),
        hex,
        unsupported,
    })
}

// ------------------------------------------------------------------ flows

fn flow_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FlowRow> {
    Ok(FlowRow {
        id: row.get("id")?,
        capture_id: row.get("capture_id")?,
        src_ip: row.get("src_ip")?,
        src_port: row.get("src_port")?,
        dst_ip: row.get("dst_ip")?,
        dst_port: row.get("dst_port")?,
        transport: row.get("transport")?,
        packet_count: row.get("packet_count")?,
        bytes_total: row.get("bytes_total")?,
        first_ts: row.get("first_ts")?,
        last_ts: row.get("last_ts")?,
    })
}

pub fn list_flows(conn: &Connection, capture_id: Option<i64>) -> AppResult<Vec<FlowRow>> {
    let mut out = Vec::new();
    match capture_id {
        Some(id) => {
            let mut stmt = conn.prepare(&format!(
                "SELECT {FLOW_COLUMNS} FROM flows WHERE capture_id = ?1
                 ORDER BY bytes_total DESC, id ASC"
            ))?;
            let rows = stmt.query_map(params![id], flow_from_row)?;
            for row in rows {
                out.push(row?);
            }
        }
        None => {
            let mut stmt = conn.prepare(&format!(
                "SELECT {FLOW_COLUMNS} FROM flows ORDER BY bytes_total DESC, id ASC"
            ))?;
            let rows = stmt.query_map([], flow_from_row)?;
            for row in rows {
                out.push(row?);
            }
        }
    }
    Ok(out)
}

pub fn flow_packets(conn: &Connection, flow_id: i64) -> AppResult<Vec<PacketRow>> {
    let flow = {
        let mut stmt = conn.prepare(&format!(
            "SELECT {FLOW_COLUMNS} FROM flows WHERE id = ?1"
        ))?;
        let mut rows = stmt.query(params![flow_id])?;
        match rows.next()? {
            Some(row) => flow_from_row(row)?,
            None => return Err(AppError::msg(format!("flow {flow_id} not found"))),
        }
    };
    let mut stmt = conn.prepare(&format!(
        "SELECT {PACKET_COLUMNS} FROM packets
         WHERE capture_id = ?1
           AND lower(ifnull(transport, ifnull(protocol, ''))) = ?2
           AND ((src_ip = ?3 AND dst_ip = ?4 AND src_port IS ?5 AND dst_port IS ?6)
             OR (src_ip = ?4 AND dst_ip = ?3 AND src_port IS ?6 AND dst_port IS ?5))
         ORDER BY ts ASC, packet_no ASC"
    ))?;
    let rows = stmt.query_map(
        params![
            flow.capture_id,
            flow.transport,
            flow.src_ip,
            flow.dst_ip,
            flow.src_port,
            flow.dst_port
        ],
        packet_from_row,
    )?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

// --------------------------------------------------------------- utilities

fn capture_name_hint(path: &str) -> String {
    let stem = std::path::Path::new(path)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    if stem.is_empty() {
        "Capture".to_string()
    } else {
        stem
    }
}

fn file_name_hint(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string())
}

fn sha256_file(path: &str) -> AppResult<String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| AppError::msg(format!("cannot open '{path}': {e}")))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| AppError::msg(format!("cannot read '{path}': {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Frame bytes as hex pairs separated by a space, e.g. "00 11 22 33".
fn hex_spaced(data: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(data.len() * 3);
    for (i, byte) in data.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Printable ASCII rendering of a hex string, 16 bytes per line, '.' when not printable.
fn ascii_dump(hex: &str) -> String {
    let bytes: Vec<u8> = hex
        .split_whitespace()
        .filter_map(|pair| u8::from_str_radix(pair, 16).ok())
        .collect();
    let mut out = String::with_capacity(bytes.len() + bytes.len() / 16 + 1);
    for (index, chunk) in bytes.chunks(16).enumerate() {
        if index > 0 {
            out.push('\n');
        }
        for byte in chunk {
            out.push(if (0x20..=0x7e).contains(byte) {
                *byte as char
            } else {
                '.'
            });
        }
    }
    out
}