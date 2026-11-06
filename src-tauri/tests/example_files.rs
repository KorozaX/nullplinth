//! Acceptance harness over the real sample files the user supplied ("Example Files").
//! Skips cleanly when the folder is absent so the suite stays portable.
//!
//! Run the real-file checks: cargo test --test example_files -- --test-threads=1 --include-ignored

use nullplinth_lib::db::{self, Db};
use nullplinth_lib::types::*;
use nullplinth_lib::{ingest, pcap, query};
use std::collections::HashMap;

fn examples_dir() -> Option<std::path::PathBuf> {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("Example Files");
    path.is_dir().then_some(path)
}

fn temp_db(tag: &str) -> Db {
    let mut path = std::env::temp_dir();
    path.push(format!("nullplinth-example-{tag}-{}.db", db::now_ms()));
    let _ = std::fs::remove_file(&path);
    Db::open(path).expect("open db")
}

fn import(db: &Db, path: &std::path::Path, source_type: Option<&str>, csv: Option<CsvMapping>) -> ImportResult {
    let options = ImportOptions {
        path: path.to_string_lossy().to_string(),
        name: None,
        source_type: source_type.map(|s| s.to_string()),
        csv,
    };
    ingest::import_with_progress(db, &options, &mut |_p| {})
        .unwrap_or_else(|e| panic!("import {} failed: {e}", path.display()))
}

#[test]
fn provided_firewall_log_imports_as_structured_events() {
    let Some(dir) = examples_dir() else { return };
    let path = dir.join("firewall.log");
    if !path.is_file() {
        return;
    }
    let db = temp_db("firewall");
    let preview = ingest::preview_import(&path.to_string_lossy()).unwrap();
    eprintln!("PREVIEW firewall.log: format={} confidence={} estimated={:?}", preview.format, preview.confidence, preview.estimated_records);
    assert_eq!(preview.format, "firewall", "key=value firewall log must be detected by content");
    assert!(preview.sample_lines.len() > 0);

    let result = import(&db, &path, None, None);
    eprintln!("IMPORT firewall.log: imported={} skipped={} warnings={}", result.imported, result.skipped, result.warnings.len());
    assert_eq!(result.imported, 500);
    assert_eq!(result.skipped, 0);

    let conn = db.conn().unwrap();
    let mut q = EventQuery { page_size: 500, ..Default::default() };
    let page = query::query_events(&conn, &q).unwrap();
    assert_eq!(page.total, 500);
    assert!(page.events.iter().all(|e| e.category.as_deref() == Some("network")));
    assert!(page.events.iter().all(|e| e.src_ip.is_some() && e.dst_ip.is_some()));
    assert!(page.events.iter().any(|e| e.action.as_deref() == Some("failed")), "rows with failed>0 must be marked failed");
    assert!(page.events.iter().any(|e| e.transport.as_deref() == Some("tcp")));

    q.filters = vec![FilterRow {
        field: "srcIp".into(),
        op: "eq".into(),
        value: "192.168.1.105".into(),
    }];
    let filtered = query::query_events(&conn, &q).unwrap();
    assert!(filtered.total > 0, "firewall source IP filter must work");
}

#[test]
fn provided_windows_event_csv_previews_maps_and_imports() {
    let Some(dir) = examples_dir() else { return };
    let path = dir.join("windows_event.csv");
    if !path.is_file() {
        return;
    }
    let db = temp_db("csv");
    let path_str = path.to_string_lossy().to_string();

    let preview = ingest::preview_csv(&path_str).unwrap();
    eprintln!(
        "PREVIEW windows_event.csv: columns={} delimiter={:?} header={} suggested={:?} estimated={:?}",
        preview.columns.len(),
        preview.detected_delimiter,
        preview.has_header,
        preview.suggested_mapping,
        preview.estimated_rows
    );
    assert!(preview.has_header);
    assert_eq!(preview.columns[0], "EventID");
    assert_eq!(preview.estimated_rows, Some(500));
    let ts_column = preview
        .suggested_mapping
        .get("timestamp")
        .cloned()
        .expect("timestamp column must be suggested from TimeGenerated");
    assert_eq!(ts_column, "TimeGenerated");

    // Build a mapping from the suggestions, exactly like the wizard does.
    let mut column_map: HashMap<String, String> = HashMap::new();
    for (field, column) in &preview.suggested_mapping {
        if field != "timestamp" {
            column_map.insert(field.clone(), column.clone());
        }
    }
    let mapping = CsvMapping {
        delimiter: preview.detected_delimiter.clone(),
        has_header: true,
        timestamp_column: Some(ts_column),
        timestamp_format: None,
        column_map,
    };
    let result = import(&db, &path, Some("csv"), Some(mapping));
    eprintln!("IMPORT windows_event.csv: imported={} skipped={}", result.imported, result.skipped);
    assert_eq!(result.imported, 500);
    assert_eq!(result.skipped, 0);

    let conn = db.conn().unwrap();
    let mut q = EventQuery { page_size: 500, ..Default::default() };
    let page = query::query_events(&conn, &q).unwrap();
    assert_eq!(page.total, 500);
    assert!(page.events.iter().all(|e| e.src_ip.is_some()), "SourceIP must be mapped");
    assert!(page.events.iter().all(|e| e.username.is_some()), "Username must be mapped");

    // Unmapped columns survive as attributes on the raw/attr payload.
    let detail = query::get_event(&conn, page.events[0].id).unwrap();
    let attrs = detail.attrs.to_string();
    assert!(attrs.contains("EventID") || attrs.contains("eventid"), "unmapped columns must be preserved: {attrs}");
}

#[test]
fn provided_ethernet_capture_decodes() {
    let Some(dir) = examples_dir() else { return };
    let path = dir.join("2026-02-28-traffic-analysis-exercise.pcap");
    if !path.is_file() {
        return;
    }
    let db = temp_db("eth");
    let conn = db.conn().unwrap();
    let capture = pcap::import_core(&conn, &path.to_string_lossy()).unwrap();
    eprintln!("PCAP ethernet: capture={} link={:?} packets={}", capture.id, capture.link_type, capture.packet_count);
    assert_eq!(capture.packet_count, 15512);

    let q = PacketQuery {
        capture_id: Some(capture.id),
        filters: vec![],
        from_ts: None,
        to_ts: None,
        sort: "packetNo".into(),
        sort_dir: "asc".into(),
        page: 0,
        page_size: 200,
    };
    let page = pcap::search_packets(&conn, &q).unwrap();
    let with_ip = page.packets.iter().filter(|p| p.src_ip.is_some()).count();
    eprintln!("PCAP ethernet: first {} packets, {} with src_ip", page.packets.len(), with_ip);
    assert!(with_ip as f64 / page.packets.len() as f64 > 0.95);
    assert!(page.packets.iter().any(|p| p.transport.as_deref() == Some("TCP")));
    assert!(page.packets.iter().any(|p| p.transport.as_deref() == Some("UDP")));
    assert!(
        page.packets
            .iter()
            .any(|p| matches!(p.protocol.as_deref(), Some("TCP") | Some("TLS") | Some("DNS") | Some("HTTP"))),
        "application protocols must be labelled"
    );

    let detail = pcap::get_packet(&conn, page.packets[0].id).unwrap();
    assert!(!detail.hex.is_empty() && !detail.layers.is_empty());
}

#[test]
#[ignore = "imports the full 65 MB wireless capture; run with --include-ignored for real-file evidence"]
fn provided_wireless_capture_decodes_in_full() {
    let Some(dir) = examples_dir() else { return };
    let path = dir.join("evidence-defcon2010.pcap");
    if !path.is_file() {
        return;
    }
    let db = temp_db("wifi");
    let conn = db.conn().unwrap();
    let capture = pcap::import_core(&conn, &path.to_string_lossy()).unwrap();
    eprintln!("PCAP wireless: link={:?} packets={}", capture.link_type, capture.packet_count);
    assert_eq!(capture.packet_count, 426_642);

    let frame_kinds: HashMap<String, i64> = {
        let mut stmt = conn
            .prepare("SELECT ifnull(frame_kind, 'none'), COUNT(*) FROM packets WHERE capture_id = ?1 GROUP BY 1")
            .unwrap();
        let rows = stmt
            .query_map([capture.id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .unwrap();
        rows.map(|r| r.unwrap()).collect()
    };
    let encrypted: i64 = conn
        .query_row("SELECT COUNT(*) FROM packets WHERE capture_id = ?1 AND encrypted = 1", [capture.id], |r| r.get(0))
        .unwrap();
    let with_ip: i64 = conn
        .query_row("SELECT COUNT(*) FROM packets WHERE capture_id = ?1 AND src_ip IS NOT NULL", [capture.id], |r| r.get(0))
        .unwrap();
    let protocol_mix: Vec<(String, i64)> = {
        let mut stmt = conn
            .prepare("SELECT ifnull(protocol, 'none'), COUNT(*) c FROM packets WHERE capture_id = ?1 GROUP BY 1 ORDER BY c DESC LIMIT 12")
            .unwrap();
        let rows = stmt.query_map([capture.id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).unwrap();
        rows.map(|r| r.unwrap()).collect()
    };
    eprintln!("PCAP wireless frame kinds: {frame_kinds:?}");
    eprintln!("PCAP wireless encrypted packets: {encrypted}");
    eprintln!("PCAP wireless packets with src_ip: {with_ip}");
    eprintln!("PCAP wireless protocol mix: {protocol_mix:?}");

    let none = frame_kinds.get("none").copied().unwrap_or(0);
    assert_eq!(none, 0, "every wireless packet must be classified");
    assert!(frame_kinds.get("management").copied().unwrap_or(0) > 0);
    assert!(frame_kinds.get("control").copied().unwrap_or(0) > 0);
    assert!(frame_kinds.get("data").copied().unwrap_or(0) > 0);
    assert!(encrypted > 0, "protected frames must be identified");

    // This capture is a WPA2 network: all data frames are protected and the plaintext
    // ones are null-data (no payload), so zero endpoints is the honest result. What must
    // never happen is fabricating addresses for protected frames.
    let fabricated: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM packets WHERE capture_id = ?1 AND encrypted = 1 AND src_ip IS NOT NULL",
            [capture.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(fabricated, 0, "encrypted frames must not get invented endpoints");
    let decoded_plaintext: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM packets WHERE capture_id = ?1 AND encrypted = 0 AND payload_len > 0 AND src_ip IS NOT NULL",
            [capture.id],
            |r| r.get(0),
        )
        .unwrap();
    eprintln!("PCAP wireless decoded plaintext payload packets: {decoded_plaintext}");
    // Sanity bound from the capture itself: it carries no decodable cleartext payload.
    assert_eq!(with_ip, decoded_plaintext.max(0));
    let stats = nullplinth_lib::workspace::state(&conn).unwrap();
    assert_eq!(stats.packets, 426_642);
}
