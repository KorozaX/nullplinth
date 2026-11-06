//! Workspace lifecycle, schema migration and data-consistency tests.

use nullplinth_lib::db::{self, Db};
use nullplinth_lib::types::*;
use nullplinth_lib::{demo, detection, investigation, pcap, query, workspace};
use rusqlite::Connection;

fn temp_db(tag: &str) -> Db {
    let mut path = std::env::temp_dir();
    path.push(format!("nullplinth-workspace-{tag}-{}.db", db::now_ms()));
    let _ = std::fs::remove_file(&path);
    Db::open(path).expect("open test database")
}

fn seed_demo(db: &Db) -> i64 {
    let conn = db.conn().unwrap();
    let tx = conn.unchecked_transaction().unwrap();
    let id = db::insert_dataset(&tx, "demo", Some("demo.ndjson"), Some("ws-demo"), None, "demo").unwrap();
    db::insert_events(&tx, id, &demo::generate()).unwrap();
    db::finish_dataset(&tx, id, 1, 0, &[], "completed").unwrap();
    tx.commit().unwrap();
    id
}

#[test]
fn v1_database_migrates_in_place_without_data_loss() {
    // Build a v1-shaped database by hand: only the packets table plus the version stamp.
    let mut path = std::env::temp_dir();
    path.push(format!("nullplinth-v1-{}.db", db::now_ms()));
    let _ = std::fs::remove_file(&path);
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                capture_id INTEGER NOT NULL,
                packet_no INTEGER NOT NULL,
                ts INTEGER NOT NULL,
                caplen INTEGER NOT NULL,
                origlen INTEGER NOT NULL,
                src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
                protocol TEXT, transport TEXT, tcp_flags TEXT,
                payload_len INTEGER NOT NULL DEFAULT 0,
                summary TEXT, layers TEXT NOT NULL DEFAULT '[]',
                raw_hex TEXT NOT NULL DEFAULT ''
             );
             INSERT INTO packets (capture_id, packet_no, ts, caplen, origlen, protocol)
                VALUES (7, 1, 1700000000000, 60, 60, 'TCP');
             PRAGMA user_version = 1;",
        )
        .unwrap();
    }

    let db = Db::open(path.clone()).expect("v1 database must open and migrate");
    let conn = db.conn().unwrap();
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
    assert_eq!(version, 2, "schema version must be upgraded to 2");
    let preserved: i64 = conn.query_row("SELECT COUNT(*) FROM packets", [], |r| r.get(0)).unwrap();
    assert_eq!(preserved, 1, "existing packets must survive the migration");
    let frame_kind: Option<String> = conn
        .query_row("SELECT frame_kind FROM packets WHERE packet_no = 1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(frame_kind, None, "new column defaults to NULL for old rows");
    let encrypted: i64 = conn
        .query_row("SELECT encrypted FROM packets WHERE packet_no = 1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(encrypted, 0);
    let _ = std::fs::remove_file(path);
}

#[test]
fn workspace_state_reports_real_counts_and_clear_empties_workspace() {
    let db = temp_db("clear");
    seed_demo(&db);
    let conn = db.conn().unwrap();
    detection::run_rules(&conn, None).unwrap();
    let alerts = detection::list_alerts(&conn, None, None).unwrap();
    investigation::create(
        &conn,
        NewInvestigation {
            title: "triage".into(),
            description: String::new(),
            alert_ids: vec![alerts[0].id],
        },
    )
    .unwrap();
    db::put_setting(&conn, "detection", "{\"bruteForceThreshold\":5}").unwrap();

    let before = workspace::state(&conn).unwrap();
    assert!(before.has_data);
    assert_eq!(before.datasets, 1);
    assert!(before.events > 100);
    assert_eq!(before.alerts, 4);
    assert_eq!(before.investigations, 1);

    let mut backup = std::env::temp_dir();
    backup.push(format!("nullplinth-backup-{}.db", db::now_ms()));
    let cleared = workspace::clear(&db, Some(&backup.to_string_lossy())).unwrap();
    assert_eq!(cleared.datasets, before.datasets);
    assert_eq!(cleared.events, before.events);
    assert_eq!(cleared.alerts, before.alerts);
    assert_eq!(cleared.investigations, before.investigations);
    assert_eq!(cleared.backup_path.as_deref(), Some(backup.to_string_lossy().as_ref()));
    assert!(backup.is_file(), "backup file must be written before clearing");
    assert!(matches!(Db::open(backup.clone()), Ok(_)), "backup must be a valid database");

    let after = workspace::state(&conn).unwrap();
    assert!(!after.has_data);
    assert_eq!(after.datasets, 0);
    assert_eq!(after.events, 0);
    assert_eq!(after.alerts, 0);
    assert_eq!(after.investigations, 0);

    // Global settings survive a workspace clear.
    let setting = db::get_setting(&conn, "detection").unwrap();
    assert!(setting.is_some(), "detection settings must be preserved");

    // Search index must be empty and consistent, not stale.
    let fts: i64 = conn
        .query_row("SELECT COUNT(*) FROM events_fts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(fts, 0, "FTS index must be empty after clearing");
    let mut q = EventQuery {
        text: Some("login".into()),
        ..Default::default()
    };
    let page = query::query_events(&conn, &q).unwrap();
    assert_eq!(page.total, 0);
    q.text = None;

    let _ = std::fs::remove_file(backup);
}

#[test]
fn clearing_an_empty_workspace_is_safe() {
    let db = temp_db("empty");
    let state = workspace::state(&db.conn().unwrap()).unwrap();
    assert!(!state.has_data);
    let cleared = workspace::clear(&db, None).unwrap();
    assert_eq!(cleared.events, 0);
    assert_eq!(cleared.backup_path, None);
}

#[test]
fn deleting_a_dataset_leaves_no_orphaned_alert_or_investigation_links() {
    let db = temp_db("delete");
    let dataset_id = seed_demo(&db);
    let conn = db.conn().unwrap();
    detection::run_rules(&conn, None).unwrap();
    let alerts = detection::list_alerts(&conn, None, None).unwrap();
    investigation::create(
        &conn,
        NewInvestigation {
            title: "linked".into(),
            description: String::new(),
            alert_ids: vec![alerts[0].id, alerts[1].id],
        },
    )
    .unwrap();

    db::delete_dataset(&conn, dataset_id).unwrap();

    let orphans: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM investigation_alerts WHERE alert_id NOT IN (SELECT id FROM alerts)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(orphans, 0, "investigation links to deleted alerts must be removed");
    let evidence_orphans: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM alert_evidence WHERE alert_id NOT IN (SELECT id FROM alerts)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(evidence_orphans, 0);
    let alerts_left: i64 = conn.query_row("SELECT COUNT(*) FROM alerts", [], |r| r.get(0)).unwrap();
    assert_eq!(alerts_left, 0, "alerts without evidence must not survive their dataset");

    // The investigation itself is an analyst record and stays usable.
    let list = investigation::list(&conn).unwrap();
    assert_eq!(list.len(), 1);
    assert!(list[0].alert_ids.is_empty());
}

#[test]
fn preferences_default_to_ask_and_validate_values() {
    let db = temp_db("prefs");
    let conn = db.conn().unwrap();
    assert_eq!(workspace::preferences(&conn).unwrap().startup_behavior, "ask");
    let saved = workspace::save_preferences(
        &conn,
        &AppPreferences {
            startup_behavior: "resume".into(),
        },
    )
    .unwrap();
    assert_eq!(saved.startup_behavior, "resume");
    assert_eq!(workspace::preferences(&conn).unwrap().startup_behavior, "resume");
    let bad = workspace::save_preferences(
        &conn,
        &AppPreferences {
            startup_behavior: "always".into(),
        },
    );
    assert!(bad.is_err(), "unknown startup preference must be rejected");
    let _ = pcap::list_captures(&conn).unwrap();
}
/// Manual check against a copy of a real, large workspace database.
/// Run: set NULLPLINTH_DB_COPY=<path to a COPY>; cargo test --test workspace_tests -- --ignored
#[test]
#[ignore = "operates on a real database copy supplied via NULLPLINTH_DB_COPY"]
fn clears_a_real_database_copy() {
    use std::path::PathBuf;
    let Ok(path) = std::env::var("NULLPLINTH_DB_COPY") else {
        eprintln!("SKIP: NULLPLINTH_DB_COPY not set");
        return;
    };
    let db = Db::open(PathBuf::from(&path)).expect("open database copy");
    let conn = db.conn().unwrap();
    let before = workspace::state(&conn).unwrap();
    eprintln!("BEFORE: {before:?}");
    assert!(before.has_data);

    let started = std::time::Instant::now();
    let cleared = workspace::clear(&db, None).unwrap();
    eprintln!("CLEAR took {:?}: {cleared:?}", started.elapsed());

    let after = workspace::state(&conn).unwrap();
    eprintln!("AFTER: {after:?}");
    assert!(!after.has_data);
    assert_eq!(after.events, 0);
    assert_eq!(after.packets, 0);
    let fts: i64 = conn.query_row("SELECT COUNT(*) FROM events_fts", [], |r| r.get(0)).unwrap();
    assert_eq!(fts, 0);
    let orphans: i64 = conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM alert_evidence) + (SELECT COUNT(*) FROM investigation_alerts) + (SELECT COUNT(*) FROM investigation_notes)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(orphans, 0);
}
