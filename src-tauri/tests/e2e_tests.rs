//! End-to-end acceptance test for the specification workflow (section 19), executed
//! against a real SQLite database and the committed fixtures:
//!
//! import real log formats -> search and filter -> inspect a raw event ->
//! import a capture -> inspect a decoded packet and its conversation ->
//! run detection -> open an alert -> create an investigation -> export it.
//!
//! The desktop shell itself is smoke-tested separately (docs/USER_GUIDE.md).

use nullplinth_lib::db::{self, Db};
use nullplinth_lib::types::*;
use nullplinth_lib::{demo, detection, export, ingest, investigation, pcap, query};
use std::collections::HashMap;

fn temp_db(tag: &str) -> Db {
    let mut path = std::env::temp_dir();
    path.push(format!("nullplinth-e2e-{tag}-{}.db", db::now_ms()));
    let _ = std::fs::remove_file(&path);
    Db::open(path).expect("open e2e database")
}

fn fixture(relative: &str) -> String {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.push("fixtures");
    path.push(relative);
    assert!(path.is_file(), "missing fixture {relative}");
    path.to_string_lossy().to_string()
}

fn import(db: &Db, relative: &str, source_type: Option<&str>, csv: Option<CsvMapping>) -> ImportResult {
    let options = ImportOptions {
        path: fixture(relative),
        name: None,
        source_type: source_type.map(|s| s.to_string()),
        csv,
    };
    let mut callbacks = 0usize;
    let result = ingest::import_with_progress(db, &options, &mut |_p: &ImportProgress| {
        callbacks += 1;
    });
    let result = result.unwrap_or_else(|e| panic!("import {relative} failed: {e}"));
    assert!(callbacks > 0, "import {relative} reported no progress");
    result
}

fn csv_mapping() -> CsvMapping {
    let mut map = HashMap::new();
    for (field, column) in [
        ("srcIp", "src_ip"),
        ("dstIp", "dst_ip"),
        ("srcPort", "src_port"),
        ("dstPort", "dst_port"),
        ("transport", "proto"),
        ("action", "action"),
        ("username", "username"),
        ("severity", "severity"),
        ("message", "message"),
    ] {
        map.insert(field.to_string(), column.to_string());
    }
    CsvMapping {
        delimiter: ",".into(),
        has_header: true,
        timestamp_column: Some("timestamp".into()),
        timestamp_format: None,
        column_map: map,
    }
}

#[test]
fn full_acceptance_workflow() {
    let db = temp_db("workflow");

    // 1-2. Application starts against an empty database: informative empty state.
    {
        let conn = db.conn().unwrap();
        let empty = query::overview(&conn).unwrap();
        assert_eq!(empty.total_events, 0);
        assert_eq!(empty.dataset_count, 0);
    }

    // 3. Import real log formats that the app supports.
    let suricata = import(&db, "logs/suricata_eve.json", None, None);
    let zeek = import(&db, "logs/zeek_conn.log", None, None);
    let csv = import(&db, "logs/csv_basic.csv", Some("csv"), Some(csv_mapping()));
    assert_eq!(suricata.imported, 7, "suricata fixture has 7 events");
    assert_eq!(zeek.imported, 3, "zeek conn fixture has 3 records");
    assert_eq!(csv.imported, 3, "csv fixture has 3 rows");

    let conn = db.conn().unwrap();
    let datasets = db::list_datasets(&conn).unwrap();
    assert_eq!(datasets.len(), 3);
    assert!(datasets.iter().all(|d| d.record_count > 0));

    // 4-5. Event Explorer: known source IP, then protocol filter.
    let source_ip = "192.0.2.10";
    let mut q = EventQuery {
        page_size: 50,
        ..Default::default()
    };
    q.filters = vec![FilterRow {
        field: "srcIp".into(),
        op: "eq".into(),
        value: source_ip.into(),
    }];
    let hits = query::query_events(&conn, &q).unwrap();
    assert_eq!(hits.total, 7, "all suricata events come from {source_ip}");

    q.filters.push(FilterRow {
        field: "transport".into(),
        op: "eq".into(),
        value: "tcp".into(),
    });
    let tcp_hits = query::query_events(&conn, &q).unwrap();
    assert!(tcp_hits.total > 0 && tcp_hits.total < 7);

    // 6-7. Open an event and inspect the preserved original record.
    let detail = query::get_event(&conn, hits.events[0].id).unwrap();
    assert!(detail.dataset_name.is_some());
    assert!(!detail.raw.is_null(), "original record must be preserved");
    assert_ne!(detail.raw, serde_json::json!({"_missing": true}));

    // Full-text search across messages and raw records.
    let mut text_q = EventQuery {
        page_size: 10,
        text: Some("example".into()),
        ..Default::default()
    };
    let text_hits = query::query_events(&conn, &text_q).unwrap();
    assert!(text_hits.total > 0, "full text search should match fixture content");
    text_q.text = None;

    // 8-11. Network Analyzer: import a capture, decode a packet, inspect its flow.
    let capture = pcap::import_core(&conn, &fixture("pcap/basic.pcap")).unwrap();
    assert!(capture.packet_count > 0, "capture must contain packets");

    let packet_query = PacketQuery {
        capture_id: Some(capture.id),
        filters: vec![FilterRow {
            field: "transport".into(),
            op: "eq".into(),
            value: "tcp".into(),
        }],
        from_ts: None,
        to_ts: None,
        sort: "packetNo".into(),
        sort_dir: "asc".into(),
        page: 0,
        page_size: 50,
    };
    let packets = pcap::search_packets(&conn, &packet_query).unwrap();
    assert!(packets.total > 0, "capture must contain TCP packets");
    let first = &packets.packets[0];
    assert!(first.src_ip.is_some() && first.dst_ip.is_some());

    let packet_detail = pcap::get_packet(&conn, first.id).unwrap();
    assert!(!packet_detail.layers.is_empty(), "decoded layers expected");
    assert!(!packet_detail.hex.is_empty(), "hex view expected");
    assert!(!packet_detail.ascii.is_empty(), "ascii view expected");
    assert!(
        packet_detail
            .layers
            .iter()
            .any(|l| matches!(l.name.as_str(), "eth" | "ip" | "frame")),
        "link/network layer must be decoded, got: {:?}",
        packet_detail.layers.iter().map(|l| l.name.clone()).collect::<Vec<_>>()
    );

    let flows = pcap::list_flows(&conn, Some(capture.id)).unwrap();
    assert!(!flows.is_empty(), "conversations must be grouped");
    let flow_packets = pcap::flow_packets(&conn, flows[0].id).unwrap();
    assert!(!flow_packets.is_empty());

    // 12-13. Detection: the fixtures alone are below threshold, so seed the demo
    // dataset and run the rules over it.
    let baseline = detection::run_rules(&conn, None).unwrap();
    assert_eq!(baseline.alerts_created, 0, "fixtures must not trip thresholds");

    let demo_events = demo::generate();
    let tx = conn.unchecked_transaction().unwrap();
    let demo_id = db::insert_dataset(&tx, "demo", Some("demo.ndjson"), Some("e2e-demo"), None, "demo").unwrap();
    db::insert_events(&tx, demo_id, &demo_events).unwrap();
    db::finish_dataset(&tx, demo_id, demo_events.len() as i64, 0, &[], "completed").unwrap();
    tx.commit().unwrap();

    let run = detection::run_rules(&conn, None).unwrap();
    assert_eq!(run.alerts_created, 4, "each rule fires once on the demo data");
    let alerts = detection::list_alerts(&conn, None, None).unwrap();
    let alert = &alerts[0];
    let alert_detail = detection::get_alert(&conn, alert.id).unwrap();
    assert!(!alert_detail.evidence.is_empty());
    assert!(!alert_detail.alert.explanation.is_empty());
    assert!(!alert_detail.alert.recommended_steps.is_empty());

    // Alert workflow: status change and analyst note.
    detection::update_alert(&conn, alert.id, Some("investigating"), Some("Triaged by E2E test")).unwrap();
    let reopened = detection::get_alert(&conn, alert.id).unwrap();
    assert_eq!(reopened.alert.status, "investigating");
    assert!(reopened.alert.note.is_some());

    // 14-15. Investigation from the alert, note, export.
    let inv = investigation::create(
        &conn,
        NewInvestigation {
            title: "E2E triage".into(),
            description: "Created by the acceptance test".into(),
            alert_ids: vec![alert.id],
        },
    )
    .unwrap();
    let inv = investigation::add_note(&conn, inv.investigation.id, "Evidence reviewed.").unwrap();
    assert_eq!(inv.notes.len(), 1);
    assert_eq!(inv.alerts.len(), 1);

    let report_path = std::env::temp_dir().join(format!("nullplinth-e2e-report-{}.json", db::now_ms()));
    let written = export::export_investigation(&conn, inv.investigation.id, &report_path.to_string_lossy()).unwrap();
    let report: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&written).unwrap()).unwrap();
    assert_eq!(report["investigation"]["title"], "E2E triage");
    assert!(report["alerts"].as_array().map(|a| !a.is_empty()).unwrap_or(false));
    assert!(report["alerts"][0]["evidence"].as_array().map(|a| !a.is_empty()).unwrap_or(false));

    // Data persisted: overview reflects everything that was imported.
    let overview = query::overview(&conn).unwrap();
    assert!(overview.total_events >= 13, "13 log events plus the demo dataset");
    assert_eq!(overview.capture_count, 1);
    assert!(overview.packet_count > 0);
    assert_eq!(overview.investigation_count, 1);

    let _ = std::fs::remove_file(report_path);
}

#[test]
fn malformed_input_never_breaks_the_database() {
    let db = temp_db("malformed");
    let result = import(&db, "logs/malformed.ndjson", None, None);
    assert!(result.imported > 0);
    assert!(result.skipped > 0, "malformed records must be counted, not dropped");
    assert!(!result.warnings.is_empty());

    let conn = db.conn().unwrap();
    let ov = query::overview(&conn).unwrap();
    assert_eq!(ov.total_events, result.imported);

    // A malformed capture reports an error and leaves no partial capture behind.
    let err = pcap::import_core(&conn, &fixture("pcap/malformed.pcap"));
    assert!(err.is_err(), "malformed capture should be rejected");
    assert!(pcap::list_captures(&conn).unwrap().is_empty());
}
