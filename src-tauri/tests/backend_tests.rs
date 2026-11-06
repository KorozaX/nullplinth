//! Lead-owned integration tests: demo data, detection rules, query engine,
//! investigations, exports and storage behaviour.

use nullplinth_lib::db::{self, Db};
use nullplinth_lib::types::*;
use nullplinth_lib::{demo, detection, export, investigation, query};
use rusqlite::Connection;

fn temp_db(tag: &str) -> Db {
    let mut path = std::env::temp_dir();
    path.push(format!("nullplinth-test-{tag}-{}.db", db::now_ms()));
    let _ = std::fs::remove_file(&path);
    Db::open(path).expect("open test database")
}

fn seed(db: &Db, events: Vec<NormalizedEvent>) -> i64 {
    let conn = db.conn().unwrap();
    let tx = conn.unchecked_transaction().unwrap();
    let id = db::insert_dataset(
        &tx,
        "test dataset",
        Some("test.ndjson"),
        Some(&format!("hash-{}", db::now_ms())),
        None,
        "test",
    )
    .unwrap();
    db::insert_events(&tx, id, &events).unwrap();
    db::finish_dataset(&tx, id, events.len() as i64, 0, &[], "completed").unwrap();
    tx.commit().unwrap();
    id
}

fn alert_count(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM alerts", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn schema_creates_fts5_and_indexes() {
    let db = temp_db("schema");
    let conn = db.conn().unwrap();
    let fts: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'events_fts'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(fts, 1, "FTS5 virtual table must exist");
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, db::SCHEMA_VERSION);
}

#[test]
fn demo_dataset_covers_every_rule_once() {
    let db = temp_db("demo-detect");
    let events = demo::generate();
    assert!(events.len() > 150, "demo dataset should be substantial");
    seed(&db, events);
    let conn = db.conn().unwrap();

    let run = detection::run_rules(&conn, None).unwrap();
    assert_eq!(run.alerts_created, 4, "each rule should fire exactly once: {:?}", run.rules);

    for rule in [
        detection::RULE_AUTH,
        detection::RULE_PORT_SCAN,
        detection::RULE_DNS,
        detection::RULE_CONN,
    ] {
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM alerts WHERE rule = ?1", [rule], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "rule {rule} should produce exactly one alert");
    }

    // Every alert must link to real supporting events.
    let alerts = detection::list_alerts(&conn, None, None).unwrap();
    for alert in &alerts {
        let detail = detection::get_alert(&conn, alert.id).unwrap();
        assert!(!detail.evidence.is_empty(), "alert {} has no evidence", alert.id);
        for evidence in &detail.evidence {
            let exists: i64 = conn
                .query_row("SELECT COUNT(*) FROM events WHERE id = ?1", [evidence.ref_id as i64], |r| r.get(0))
                .unwrap();
            assert_eq!(exists, 1, "evidence event {} must exist", evidence.ref_id);
        }
    }

    // Re-running must not duplicate alerts (dedupe key + preserved status).
    let again = detection::run_rules(&conn, None).unwrap();
    assert_eq!(again.alerts_created, 0, "re-running detection must not duplicate alerts");
    assert_eq!(alert_count(&conn), 4);
}

#[test]
fn benign_traffic_produces_no_alerts() {
    let db = temp_db("benign");
    let base = db::now_ms() - 3_600_000;
    let mut events = Vec::new();
    for i in 0..3 {
        let mut e = NormalizedEvent::new(base + i * 1000, "test");
        e.category = Some("authentication".into());
        e.action = Some("failed".into());
        e.src_ip = Some("10.0.0.5".into());
        e.message = Some("failed login".into());
        events.push(e);
    }
    for i in 0..3 {
        let mut e = NormalizedEvent::new(base + i * 1000, "test");
        e.category = Some("dns".into());
        e.attrs = serde_json::json!({"dnsRcode": "NXDOMAIN"});
        e.src_ip = Some("10.0.0.6".into());
        events.push(e);
    }
    seed(&db, events);
    let conn = db.conn().unwrap();
    let run = detection::run_rules(&conn, None).unwrap();
    assert_eq!(run.alerts_created, 0, "benign thresholds must not fire");
}

#[test]
fn threshold_setting_changes_detection_result() {
    let db = temp_db("threshold");
    seed(&db, demo::generate());
    let conn = db.conn().unwrap();
    let mut settings = DetectionSettings::default();
    settings.brute_force_threshold = 50;
    db::put_setting(&conn, "detection", &serde_json::to_string(&settings).unwrap()).unwrap();
    let run = detection::run_rules(&conn, None).unwrap();
    let auth_rule = run.rules.iter().find(|r| r.rule == detection::RULE_AUTH).unwrap();
    assert_eq!(auth_rule.alerts_created, 0, "a higher threshold must suppress the alert");
}

#[test]
fn filtered_event_search_and_cidr() {
    let db = temp_db("search");
    seed(&db, demo::generate());
    let conn = db.conn().unwrap();

    let mut q = EventQuery {
        page_size: 10,
        ..Default::default()
    };
    q.filters = vec![FilterRow {
        field: "srcIp".into(),
        op: "eq".into(),
        value: "203.0.113.44".into(),
    }];
    let page = query::query_events(&conn, &q).unwrap();
    assert_eq!(page.total, 12, "brute force source should have 12 events");
    assert!(page.events.len() <= 10);

    q.filters = vec![FilterRow {
        field: "srcIp".into(),
        op: "inCidr".into(),
        value: "10.0.0.0/24".into(),
    }];
    let internal = query::query_events(&conn, &q).unwrap();
    assert!(internal.total > 5, "CIDR filter should match internal addresses");

    q.filters = vec![FilterRow {
        field: "transport".into(),
        op: "eq".into(),
        value: "tcp".into(),
    }];
    let tcp = query::query_events(&conn, &q).unwrap();
    assert!(tcp.total > 0);

    // Invalid filter input must be rejected, not silently ignored.
    q.filters = vec![FilterRow {
        field: "srcPort".into(),
        op: "eq".into(),
        value: "not-a-port".into(),
    }];
    assert!(query::query_events(&conn, &q).is_err());

    // Full-text search.
    q.filters = vec![];
    q.text = Some("NXDOMAIN".into());
    let text = query::query_events(&conn, &q).unwrap();
    assert!(text.total >= 15, "FTS should find the synthetic NXDOMAIN messages");
}

#[test]
fn overview_reflects_imported_data() {
    let db = temp_db("overview");
    seed(&db, demo::generate());
    let conn = db.conn().unwrap();
    let ov = query::overview(&conn).unwrap();
    assert!(ov.total_events > 150);
    assert_eq!(ov.dataset_count, 1);
    assert!(!ov.protocol_distribution.is_empty());
    assert!(!ov.volume_series.is_empty());
}

#[test]
fn investigation_lifecycle() {
    let db = temp_db("investigation");
    seed(&db, demo::generate());
    let conn = db.conn().unwrap();
    detection::run_rules(&conn, None).unwrap();
    let alerts = detection::list_alerts(&conn, None, None).unwrap();
    assert!(!alerts.is_empty());

    let created = investigation::create(
        &conn,
        NewInvestigation {
            title: "Suspicious brute force".into(),
            description: "Initial triage".into(),
            alert_ids: vec![alerts[0].id],
        },
    )
    .unwrap();
    let id = created.investigation.id;
    assert_eq!(created.investigation.status, "open");
    assert_eq!(created.investigation.alert_ids.len(), 1);

    let noted = investigation::add_note(&conn, id, "Checked the source range.").unwrap();
    assert_eq!(noted.notes.len(), 1);

    let updated = investigation::update(&conn, id, None, None, Some("investigating")).unwrap();
    assert_eq!(updated.investigation.status, "investigating");

    let list = investigation::list(&conn).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].note_count, 1);

    assert!(investigation::update(&conn, id, None, None, Some("bogus")).is_err());
}

#[test]
fn export_writes_csv_and_json() {
    let db = temp_db("export");
    seed(&db, demo::generate());
    let conn = db.conn().unwrap();
    let dir = std::env::temp_dir();

    let csv_path = dir.join(format!("nullplinth-export-{}.csv", db::now_ms()));
    let request = ExportRequest {
        path: csv_path.to_string_lossy().to_string(),
        format: "csv".into(),
        query: EventQuery::default(),
    };
    let written = export::export_events(&conn, &request).unwrap();
    let content = std::fs::read_to_string(&written).unwrap();
    assert!(content.starts_with("event_id,timestamp_ms"));
    assert!(content.lines().count() > 100);

    let json_path = dir.join(format!("nullplinth-export-{}.json", db::now_ms()));
    let request = ExportRequest {
        path: json_path.to_string_lossy().to_string(),
        format: "json".into(),
        query: EventQuery::default(),
    };
    let written = export::export_events(&conn, &request).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&written).unwrap()).unwrap();
    assert!(parsed.as_array().map(|a| !a.is_empty()).unwrap_or(false));

    let _ = std::fs::remove_file(csv_path);
    let _ = std::fs::remove_file(json_path);
}

#[test]
fn deleting_a_dataset_removes_its_events() {
    let db = temp_db("delete");
    let dataset_id = seed(&db, demo::generate());
    let conn = db.conn().unwrap();
    let before = query::overview(&conn).unwrap().total_events;
    db::delete_dataset(&conn, dataset_id).unwrap();
    let after = query::overview(&conn).unwrap().total_events;
    assert_eq!(after, 0);
    assert!(before > 0);
}
/// Regression: the UI asks for page 1 and a search returning exactly one page of
/// rows must show them. Previously the backend treated page 1 as an offset of one
/// page, so such searches appeared empty (the reported "User equals root" bug).
#[test]
fn first_page_returns_matching_rows() {
    let db = temp_db("pagination");
    seed(&db, demo::generate());
    let conn = db.conn().unwrap();

    let mut q = EventQuery {
        page: 1,
        page_size: 12,
        ..Default::default()
    };
    q.filters = vec![FilterRow {
        field: "srcIp".into(),
        op: "eq".into(),
        value: "203.0.113.44".into(),
    }];
    let first = query::query_events(&conn, &q).unwrap();
    assert_eq!(first.total, 12, "filter matches exactly one page of rows");
    assert_eq!(first.events.len(), 12, "page 1 must contain those rows");
    assert_eq!(first.page, 1);

    q.page = 2;
    let second = query::query_events(&conn, &q).unwrap();
    assert!(second.events.is_empty(), "page 2 has no rows left");

    // Page 0 is clamped to the first page rather than skipping data.
    q.page = 0;
    let clamped = query::query_events(&conn, &q).unwrap();
    assert_eq!(clamped.events.len(), 12);
    assert_eq!(clamped.page, 1);
}
