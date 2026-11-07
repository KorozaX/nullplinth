//! Seeds a review workspace with real data (demo events + the supplied log files +
//! packet captures) so the redesigned screens can be reviewed against genuine records.
//!
//! Run: set NULLPLINTH_REVIEW_DB=<path to a new database>; cargo test --test review_seed -- --ignored
//! Only used for visual review; never touches the user's own database.

use nullplinth_lib::db::{self, Db};
use nullplinth_lib::types::*;
use nullplinth_lib::{demo, detection, ingest, investigation, pcap};
use std::collections::HashMap;
use std::path::PathBuf;

fn examples_dir() -> Option<PathBuf> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("Example Files");
    path.is_dir().then_some(path)
}

fn fixture(relative: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.push("fixtures");
    path.push(relative);
    path
}

fn import(db: &Db, path: &std::path::Path, source_type: Option<&str>, csv: Option<CsvMapping>) {
    if !path.is_file() {
        eprintln!("skip missing file {}", path.display());
        return;
    }
    let options = ImportOptions {
        path: path.to_string_lossy().to_string(),
        name: None,
        source_type: source_type.map(|s| s.to_string()),
        csv,
    };
    match ingest::import_with_progress(db, &options, &mut |_p| {}) {
        Ok(r) => eprintln!("imported {} events from {}", r.imported, path.display()),
        Err(e) => eprintln!("import failed {}: {e}", path.display()),
    }
}

#[test]
#[ignore = "seeds a review workspace; run with NULLPLINTH_REVIEW_DB pointing at a fresh database"]
fn seed_review_workspace() {
    let Ok(path) = std::env::var("NULLPLINTH_REVIEW_DB") else {
        eprintln!("SKIP: NULLPLINTH_REVIEW_DB not set");
        return;
    };
    let _ = std::fs::remove_file(&path);
    let db = Db::open(PathBuf::from(&path)).expect("open review database");
    let conn = db.conn().unwrap();

    // 1. Synthetic demo dataset (deterministic, exercises detection).
    let events = demo::generate();
    let tx = conn.unchecked_transaction().unwrap();
    let dataset_id = db::insert_dataset(
        &tx,
        "Synthetic demonstration dataset",
        Some("demo.ndjson"),
        Some("review-demo"),
        None,
        "demo",
    )
    .unwrap();
    db::insert_events(&tx, dataset_id, &events).unwrap();
    db::finish_dataset(&tx, dataset_id, events.len() as i64, 0, &[], "completed").unwrap();
    tx.commit().unwrap();
    eprintln!("demo dataset: {} events", events.len());

    // 2. Real supplied log files, when present.
    if let Some(dir) = examples_dir() {
        import(&db, &dir.join("firewall.log"), None, None);
        let csv_path = dir.join("windows_event.csv");
        if csv_path.is_file() {
            let preview = ingest::preview_csv(&csv_path.to_string_lossy()).unwrap();
            let mut column_map: HashMap<String, String> = HashMap::new();
            for (field, column) in &preview.suggested_mapping {
                if field != "timestamp" {
                    column_map.insert(field.clone(), column.clone());
                }
            }
            let mapping = CsvMapping {
                delimiter: preview.detected_delimiter.clone(),
                has_header: true,
                timestamp_column: preview.suggested_mapping.get("timestamp").cloned(),
                timestamp_format: None,
                column_map,
            };
            import(&db, &csv_path, Some("csv"), Some(mapping));
        }
        // 3. Ethernet capture with real protocols (fast).
        let cap = dir.join("2026-02-28-traffic-analysis-exercise.pcap");
        if cap.is_file() {
            match pcap::import_core(&conn, &cap.to_string_lossy()) {
                Ok(c) => eprintln!("capture {}: {} packets", c.name, c.packet_count),
                Err(e) => eprintln!("capture failed: {e}"),
            }
        }
    }
    // 4. Wireless fixture so 802.11 frame kinds and encrypted badges are represented.
    let wifi = fixture("pcap/wifi_80211.pcap");
    if wifi.is_file() {
        match pcap::import_core(&conn, &wifi.to_string_lossy()) {
            Ok(c) => eprintln!("capture {}: {} packets", c.name, c.packet_count),
            Err(e) => eprintln!("wifi fixture failed: {e}"),
        }
    }

    // 5. Detection + an investigation so Alerts and Investigations have content.
    let run = detection::run_rules(&conn, None).unwrap();
    eprintln!("detection: {} alerts", run.alerts_created);
    let alerts = detection::list_alerts(&conn, None, None).unwrap();
    if let Some(first) = alerts.first() {
        detection::update_alert(&conn, first.id, Some("investigating"), Some("Triaged during review.")).unwrap();
        let created = investigation::create(
            &conn,
            NewInvestigation {
                title: format!("Review case: {}", first.title),
                description: "Investigation seeded for the visual review.".into(),
                alert_ids: alerts.iter().take(3).map(|a| a.id).collect(),
            },
        )
        .unwrap();
        investigation::add_note(
            &conn,
            created.investigation.id,
            "Reviewed the supporting evidence; the source range is not expected on this network.",
        )
        .unwrap();
        eprintln!("investigation: {}", created.investigation.id);
    }

    // 6. Resume the workspace silently so screenshots skip the welcome dialog.
    db::put_setting(&conn, "app.preferences", "{\"startupBehavior\":\"resume\"}").unwrap();
    let state = nullplinth_lib::workspace::state(&conn).unwrap();
    eprintln!("review workspace ready: {state:?}");
}
