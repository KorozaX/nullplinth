//! Integration tests for the log ingestion pipeline (src-tauri/src/ingest).

use nullplinth_lib::db::{self, Db};
use nullplinth_lib::ingest::{self, Format};
use nullplinth_lib::types::{CsvMapping, ImportOptions, ImportResult};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------- helpers

fn fixture_path(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("logs")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

struct TempDb {
    db: Db,
    path: PathBuf,
}

impl TempDb {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nullplinth-ingest-{}-{}-{}.db",
            std::process::id(),
            nanos,
            counter
        ));
        let db = Db::open(path.clone()).expect("open temp database");
        Self { db, path }
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{}", self.path.display(), suffix));
        }
    }
}

fn import_fixture(
    db: &Db,
    name: &str,
    source_type: Option<&str>,
    csv: Option<CsvMapping>,
) -> ImportResult {
    let options = ImportOptions {
        path: fixture_path(name),
        name: Some(name.to_string()),
        source_type: source_type.map(|value| value.to_string()),
        csv,
    };
    ingest::import_with_progress(db, &options, &mut |_progress| {}).expect("import fixture")
}

fn mapping(
    delimiter: &str,
    has_header: bool,
    ts_column: Option<&str>,
    pairs: &[(&str, &str)],
) -> CsvMapping {
    let mut column_map = HashMap::new();
    for (key, column) in pairs {
        column_map.insert(key.to_string(), column.to_string());
    }
    CsvMapping {
        delimiter: delimiter.to_string(),
        has_header,
        timestamp_column: ts_column.map(|value| value.to_string()),
        timestamp_format: None,
        column_map,
    }
}

#[derive(Debug)]
struct Row {
    ts: i64,
    category: Option<String>,
    event_type: Option<String>,
    severity: String,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    src_port: Option<i64>,
    dst_port: Option<i64>,
    transport: Option<String>,
    app_proto: Option<String>,
    action: Option<String>,
    username: Option<String>,
    hostname: Option<String>,
    message: Option<String>,
    attrs: Value,
    raw: Value,
}

impl Row {
    fn attr_str(&self, key: &str) -> Option<String> {
        self.attrs
            .get(key)
            .and_then(|value| value.as_str())
            .map(|value| value.to_string())
    }

    fn attr_i64(&self, key: &str) -> Option<i64> {
        self.attrs.get(key).and_then(|value| value.as_i64())
    }
}

fn events_of(db: &Db, dataset_id: i64) -> Vec<Row> {
    let conn = db.conn().expect("connection");
    let mut statement = conn
        .prepare(
            "SELECT ts, category, event_type, severity, src_ip, dst_ip, src_port, dst_port,
                    transport, app_proto, action, username, hostname, message, attrs, raw
             FROM events WHERE dataset_id = ?1 ORDER BY id",
        )
        .expect("prepare");
    let rows = statement
        .query_map([dataset_id], |record| {
            let attrs: String = record.get("attrs")?;
            let raw: String = record.get("raw")?;
            Ok(Row {
                ts: record.get("ts")?,
                category: record.get("category")?,
                event_type: record.get("event_type")?,
                severity: record.get("severity")?,
                src_ip: record.get("src_ip")?,
                dst_ip: record.get("dst_ip")?,
                src_port: record.get("src_port")?,
                dst_port: record.get("dst_port")?,
                transport: record.get("transport")?,
                app_proto: record.get("app_proto")?,
                action: record.get("action")?,
                username: record.get("username")?,
                hostname: record.get("hostname")?,
                message: record.get("message")?,
                attrs: serde_json::from_str(&attrs).unwrap_or(Value::Null),
                raw: serde_json::from_str(&raw).unwrap_or(Value::Null),
            })
        })
        .expect("query");
    rows.map(|row| row.expect("row")).collect()
}

fn event_count(db: &Db, dataset_id: i64) -> i64 {
    let conn = db.conn().expect("connection");
    conn.query_row(
        "SELECT COUNT(*) FROM events WHERE dataset_id = ?1",
        [dataset_id],
        |row| row.get(0),
    )
    .expect("count events")
}

fn dataset_counts(db: &Db, dataset_id: i64) -> (i64, i64, String) {
    let conn = db.conn().expect("connection");
    conn.query_row(
        "SELECT record_count, skipped_count, status FROM datasets WHERE id = ?1",
        [dataset_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .expect("dataset counts")
}

// ------------------------------------------------------------- detection

#[test]
fn detects_every_supported_format() {
    assert_eq!(
        ingest::detect_format(&fixture_path("events.json")).unwrap(),
        Format::JsonArray
    );
    assert_eq!(
        ingest::detect_format(&fixture_path("events.ndjson")).unwrap(),
        Format::Ndjson
    );
    assert_eq!(
        ingest::detect_format(&fixture_path("suricata_eve.json")).unwrap(),
        Format::Suricata
    );
    assert_eq!(
        ingest::detect_format(&fixture_path("zeek_conn.log")).unwrap(),
        Format::Zeek
    );
    assert_eq!(
        ingest::detect_format(&fixture_path("csv_basic.csv")).unwrap(),
        Format::Csv
    );
    assert_eq!(Format::from_source_type("suricata"), Some(Format::Suricata));
    assert_eq!(Format::from_source_type("jsonl"), Some(Format::Ndjson));
    assert_eq!(Format::from_source_type("zeek"), Some(Format::Zeek));
    assert_eq!(Format::from_source_type("nonsense"), None);
}

// ------------------------------------------------------------ JSON array

#[test]
fn imports_json_array_and_preserves_unknown_fields() {
    let temp = TempDb::new();
    let result = import_fixture(&temp.db, "events.json", None, None);
    assert_eq!(result.imported, 2);
    assert_eq!(result.skipped, 0);
    assert!(result.warnings.is_empty());
    assert_eq!(event_count(&temp.db, result.dataset_id), 2);
    assert_eq!(dataset_counts(&temp.db, result.dataset_id), (2, 0, "completed".to_string()));

    let rows = events_of(&temp.db, result.dataset_id);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].ts, 1_709_287_200_000);
    assert_eq!(rows[0].src_ip.as_deref(), Some("10.1.1.5"));
    assert_eq!(rows[0].dst_ip.as_deref(), Some("10.2.2.9"));
    assert_eq!(rows[0].src_port, Some(12345));
    assert_eq!(rows[0].dst_port, Some(80));
    assert_eq!(rows[0].transport.as_deref(), Some("tcp"));
    assert_eq!(rows[0].category.as_deref(), Some("network"));
    assert_eq!(rows[0].action.as_deref(), Some("allowed"));
    assert_eq!(rows[0].attr_str("custom_field").as_deref(), Some("keep-me"));
    assert_eq!(
        rows[0].raw.get("custom_field").and_then(|value| value.as_str()),
        Some("keep-me")
    );

    assert_eq!(rows[1].ts, 1_709_294_400_000);
    assert_eq!(rows[1].src_ip.as_deref(), Some("10.1.1.6"));
    assert_eq!(rows[1].category.as_deref(), Some("authentication"));
    assert_eq!(rows[1].action.as_deref(), Some("failed"));
    assert_eq!(rows[1].username.as_deref(), Some("alice"));
    assert_eq!(rows[1].severity, "medium");
}

#[test]
fn imports_ndjson() {
    let temp = TempDb::new();
    let result = import_fixture(&temp.db, "events.ndjson", None, None);
    assert_eq!(result.imported, 2);
    assert_eq!(result.skipped, 0);
    let rows = events_of(&temp.db, result.dataset_id);
    assert_eq!(rows[0].ts, 1_709_287_201_000);
    assert_eq!(rows[0].transport.as_deref(), Some("tcp"));
    assert_eq!(rows[0].event_type.as_deref(), Some("audit"));
    assert_eq!(rows[1].ts, 1_709_287_202_000);
    assert_eq!(rows[1].transport.as_deref(), Some("udp"));
}

// --------------------------------------------------------- Suricata EVE

#[test]
fn imports_all_suricata_event_types() {
    let temp = TempDb::new();
    let result = import_fixture(&temp.db, "suricata_eve.json", None, None);
    assert_eq!(result.imported, 7);
    assert_eq!(result.skipped, 0);
    let rows = events_of(&temp.db, result.dataset_id);
    assert_eq!(rows.len(), 7);

    // alert: severity 1 -> high, action blocked, signature as message
    assert_eq!(rows[0].category.as_deref(), Some("alert"));
    assert_eq!(rows[0].severity, "high");
    assert_eq!(rows[0].action.as_deref(), Some("blocked"));
    assert_eq!(
        rows[0].message.as_deref(),
        Some("ET POLICY TLS possible bad certificate")
    );
    assert_eq!(rows[0].attr_i64("signatureId"), Some(2_027_865));
    assert_eq!(rows[0].transport.as_deref(), Some("tcp"));

    // dns query with NXDOMAIN
    assert_eq!(rows[1].category.as_deref(), Some("dns"));
    assert_eq!(rows[1].event_type.as_deref(), Some("query"));
    assert_eq!(rows[1].attr_str("dnsQuery").as_deref(), Some("evil.example.com"));
    assert_eq!(rows[1].attr_str("dnsRcode").as_deref(), Some("NXDOMAIN"));
    assert_eq!(rows[1].hostname.as_deref(), Some("evil.example.com"));

    // dns answer -> response
    assert_eq!(rows[2].event_type.as_deref(), Some("response"));
    assert_eq!(rows[2].attr_str("dnsRcode").as_deref(), Some("NOERROR"));
    assert_eq!(rows[2].attr_str("dnsQuery").as_deref(), Some("www.example.com"));

    // http
    assert_eq!(rows[3].category.as_deref(), Some("http"));
    assert_eq!(rows[3].hostname.as_deref(), Some("www.example.com"));
    assert_eq!(rows[3].message.as_deref(), Some("POST /login"));
    assert_eq!(rows[3].attr_i64("status"), Some(200));
    assert_eq!(rows[3].attr_str("userAgent").as_deref(), Some("Mozilla/5.0"));

    // tls
    assert_eq!(rows[4].category.as_deref(), Some("tls"));
    assert_eq!(rows[4].hostname.as_deref(), Some("secure.example.org"));
    assert_eq!(rows[4].attr_str("sni").as_deref(), Some("secure.example.org"));

    // flow -> network/allowed
    assert_eq!(rows[5].category.as_deref(), Some("network"));
    assert_eq!(rows[5].action.as_deref(), Some("allowed"));
    assert_eq!(rows[5].transport.as_deref(), Some("tcp"));

    // anomaly
    assert_eq!(rows[6].category.as_deref(), Some("anomaly"));
    assert_eq!(rows[6].event_type.as_deref(), Some("applayer"));
}

#[test]
fn malformed_suricata_records_are_skipped_not_fatal() {
    let temp = TempDb::new();
    let result = import_fixture(&temp.db, "malformed_suricata.json", None, None);
    assert_eq!(result.imported, 2);
    assert_eq!(result.skipped, 2);
    assert_eq!(result.warnings.len(), 2);
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("record 2") && warning.contains("timestamp")),
        "warnings: {:?}",
        result.warnings
    );
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("record 3") && warning.contains("JSON object")),
        "warnings: {:?}",
        result.warnings
    );
    let rows = events_of(&temp.db, result.dataset_id);
    assert_eq!(rows.len(), 2);
    // alert.severity 2 -> medium
    assert_eq!(rows[0].severity, "medium");
    assert_eq!(rows[0].category.as_deref(), Some("alert"));
    // numeric rcode 3 -> NXDOMAIN, ISO timestamp with +0000 offset parsed
    assert_eq!(rows[1].attr_str("dnsRcode").as_deref(), Some("NXDOMAIN"));
    assert_eq!(rows[1].ts, 1_709_287_201_000);
}

// ------------------------------------------------------------ Zeek TSV

#[test]
fn imports_zeek_conn_with_contract_actions() {
    let temp = TempDb::new();
    let result = import_fixture(&temp.db, "zeek_conn.log", None, None);
    assert_eq!(result.imported, 3);
    assert_eq!(result.skipped, 0);
    let rows = events_of(&temp.db, result.dataset_id);

    assert_eq!(rows[0].category.as_deref(), Some("network"));
    assert_eq!(rows[0].action.as_deref(), Some("allowed"));
    assert_eq!(rows[0].transport.as_deref(), Some("tcp"));
    assert_eq!(rows[0].src_ip.as_deref(), Some("10.1.1.5"));
    assert_eq!(rows[0].dst_ip.as_deref(), Some("10.2.2.9"));
    assert_eq!(rows[0].src_port, Some(49152));
    assert_eq!(rows[0].dst_port, Some(80));
    assert_eq!(rows[0].app_proto.as_deref(), Some("http"));
    assert_eq!(rows[0].attr_str("connState").as_deref(), Some("SF"));
    assert_eq!(rows[0].ts, 1_709_287_200_000);

    // REJ -> failed
    assert_eq!(rows[1].action.as_deref(), Some("failed"));
    assert_eq!(rows[1].attr_str("connState").as_deref(), Some("REJ"));
    assert_eq!(rows[1].transport.as_deref(), Some("tcp"));

    // S0 over udp -> failed
    assert_eq!(rows[2].action.as_deref(), Some("failed"));
    assert_eq!(rows[2].transport.as_deref(), Some("udp"));
}

#[test]
fn imports_zeek_dns_with_rcode_and_query() {
    let temp = TempDb::new();
    let result = import_fixture(&temp.db, "zeek_dns.log", None, None);
    assert_eq!(result.imported, 2);
    let rows = events_of(&temp.db, result.dataset_id);

    assert_eq!(rows[0].category.as_deref(), Some("dns"));
    assert_eq!(rows[0].event_type.as_deref(), Some("query"));
    assert_eq!(rows[0].attr_str("dnsQuery").as_deref(), Some("evil.example.com"));
    assert_eq!(rows[0].attr_str("dnsRcode").as_deref(), Some("NXDOMAIN"));
    assert_eq!(rows[0].hostname.as_deref(), Some("evil.example.com"));
    assert_eq!(rows[0].transport.as_deref(), Some("udp"));
    assert_eq!(rows[0].ts, 1_709_287_200_100);

    assert_eq!(rows[1].event_type.as_deref(), Some("response"));
    assert_eq!(rows[1].attr_str("dnsRcode").as_deref(), Some("NOERROR"));
    assert_eq!(rows[1].hostname.as_deref(), Some("example.com"));
}

#[test]
fn imports_zeek_http() {
    let temp = TempDb::new();
    let result = import_fixture(&temp.db, "zeek_http.log", None, None);
    assert_eq!(result.imported, 1);
    let rows = events_of(&temp.db, result.dataset_id);
    assert_eq!(rows[0].category.as_deref(), Some("http"));
    assert_eq!(rows[0].hostname.as_deref(), Some("example.com"));
    assert_eq!(rows[0].message.as_deref(), Some("GET /index.html"));
    assert_eq!(rows[0].attr_i64("status"), Some(200));
    assert_eq!(rows[0].src_port, Some(53200));
}

#[test]
fn imports_zeek_ssl() {
    let temp = TempDb::new();
    let result = import_fixture(&temp.db, "zeek_ssl.log", None, None);
    assert_eq!(result.imported, 1);
    let rows = events_of(&temp.db, result.dataset_id);
    assert_eq!(rows[0].category.as_deref(), Some("tls"));
    assert_eq!(rows[0].event_type.as_deref(), Some("ssl"));
    assert_eq!(rows[0].hostname.as_deref(), Some("example.org"));
    assert_eq!(rows[0].attr_str("sni").as_deref(), Some("example.org"));
    assert_eq!(rows[0].attr_str("validationStatus").as_deref(), Some("ok"));
    // Zeek ssl.log has no proto column: transport stays NULL.
    assert_eq!(rows[0].transport, None);
}

#[test]
fn imports_zeek_ssh_authentication() {
    let temp = TempDb::new();
    let result = import_fixture(&temp.db, "zeek_ssh.log", None, None);
    assert_eq!(result.imported, 2);
    let rows = events_of(&temp.db, result.dataset_id);
    assert_eq!(rows[0].category.as_deref(), Some("authentication"));
    assert_eq!(rows[0].action.as_deref(), Some("failed"));
    assert_eq!(rows[0].app_proto.as_deref(), Some("ssh"));
    assert!(
        rows[0]
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("failed")
    );
    assert_eq!(rows[1].action.as_deref(), Some("success"));
    assert_eq!(rows[1].category.as_deref(), Some("authentication"));
}

// ---------------------------------------------------------------- CSV

#[test]
fn imports_csv_with_explicit_mapping() {
    let temp = TempDb::new();
    let map = mapping(
        ",",
        true,
        Some("timestamp"),
        &[
            ("srcIp", "src_ip"),
            ("dstIp", "dst_ip"),
            ("srcPort", "src_port"),
            ("dstPort", "dst_port"),
            ("transport", "proto"),
            ("action", "action"),
            ("username", "username"),
            ("severity", "severity"),
            ("message", "message"),
        ],
    );
    let result = import_fixture(&temp.db, "csv_basic.csv", Some("csv"), Some(map));
    assert_eq!(result.imported, 3);
    assert_eq!(result.skipped, 0);
    let rows = events_of(&temp.db, result.dataset_id);
    assert_eq!(rows.len(), 3);

    assert_eq!(rows[0].ts, 1_709_287_200_000);
    assert_eq!(rows[0].src_ip.as_deref(), Some("10.1.1.5"));
    assert_eq!(rows[0].dst_ip.as_deref(), Some("10.2.2.9"));
    assert_eq!(rows[0].src_port, Some(12345));
    assert_eq!(rows[0].dst_port, Some(443));
    assert_eq!(rows[0].transport.as_deref(), Some("tcp"));
    assert_eq!(rows[0].action.as_deref(), Some("allowed"));
    assert_eq!(rows[0].username.as_deref(), Some("alice"));
    assert_eq!(rows[0].severity, "info");
    assert_eq!(rows[0].message.as_deref(), Some("login ok"));
    // unmapped column preserved in attrs and the full row in raw
    assert_eq!(rows[0].attr_str("extra_note").as_deref(), Some("note-a"));
    assert_eq!(
        rows[0].raw.get("extra_note").and_then(|value| value.as_str()),
        Some("note-a")
    );

    // "warning" normalizes to medium
    assert_eq!(rows[1].severity, "medium");
    assert_eq!(rows[1].action.as_deref(), Some("blocked"));

    // invalid IP / port are dropped to NULL, the record is still imported
    assert_eq!(rows[2].src_ip, None);
    assert_eq!(rows[2].src_port, None);
    assert_eq!(rows[2].severity, "high");
}

#[test]
fn preview_csv_detects_semicolon_and_imports() {
    let preview = ingest::preview_csv(&fixture_path("csv_semicolon.csv")).expect("preview");
    assert_eq!(preview.detected_delimiter, ";");
    assert!(preview.has_header);
    assert_eq!(preview.columns, vec!["ts", "user", "action", "host"]);
    assert_eq!(preview.rows.len(), 2);

    let temp = TempDb::new();
    let map = mapping(
        ";",
        true,
        Some("ts"),
        &[
            ("username", "user"),
            ("action", "action"),
            ("hostname", "host"),
        ],
    );
    let result = import_fixture(&temp.db, "csv_semicolon.csv", None, Some(map));
    assert_eq!(result.imported, 2);
    let rows = events_of(&temp.db, result.dataset_id);
    assert_eq!(rows[0].ts, 1_709_287_200_000);
    assert_eq!(rows[0].username.as_deref(), Some("dave"));
    assert_eq!(rows[0].action.as_deref(), Some("failed"));
    assert_eq!(rows[0].hostname.as_deref(), Some("server-1"));
    assert_eq!(rows[1].action.as_deref(), Some("success"));
}

#[test]
fn preview_csv_without_header_generates_column_names() {
    let preview = ingest::preview_csv(&fixture_path("csv_no_header.csv")).expect("preview");
    assert_eq!(preview.detected_delimiter, ",");
    assert!(!preview.has_header);
    assert_eq!(preview.columns, vec!["column_1", "column_2", "column_3"]);
    assert_eq!(preview.rows.len(), 2);
    assert_eq!(preview.rows[0][0], "1709287200");
}

#[test]
fn csv_without_mapping_is_rejected() {
    let temp = TempDb::new();
    let options = ImportOptions {
        path: fixture_path("csv_basic.csv"),
        name: None,
        source_type: Some("csv".to_string()),
        csv: None,
    };
    let error = ingest::import_with_progress(&temp.db, &options, &mut |_progress| {})
        .expect_err("CSV import without a mapping must fail");
    assert!(
        error.to_string().contains("mapping"),
        "unexpected error: {error}"
    );
}

// --------------------------------------------------- malformed / recovery

#[test]
fn malformed_ndjson_records_are_skipped_not_fatal() {
    let temp = TempDb::new();
    let result = import_fixture(&temp.db, "malformed.ndjson", None, None);
    assert_eq!(result.imported, 2);
    assert_eq!(result.skipped, 2);
    assert_eq!(result.warnings.len(), 2);
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("record 2") && warning.contains("invalid JSON")),
        "warnings: {:?}",
        result.warnings
    );
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("record 3") && warning.contains("timestamp")),
        "warnings: {:?}",
        result.warnings
    );
    assert_eq!(event_count(&temp.db, result.dataset_id), 2);
    assert_eq!(
        dataset_counts(&temp.db, result.dataset_id),
        (2, 2, "completed".to_string())
    );

    let datasets = db::list_datasets(&temp.db.conn().expect("connection")).expect("datasets");
    assert_eq!(datasets.len(), 1);
    assert_eq!(datasets[0].record_count, 2);
    assert_eq!(datasets[0].skipped_count, 2);
    assert_eq!(datasets[0].warnings.len(), 2);
}

#[test]
fn duplicate_file_hash_is_rejected() {
    let temp = TempDb::new();
    let first = import_fixture(&temp.db, "events.json", None, None);
    assert_eq!(first.imported, 2);

    let options = ImportOptions {
        path: fixture_path("events.json"),
        name: Some("again".to_string()),
        source_type: None,
        csv: None,
    };
    let error = ingest::import_with_progress(&temp.db, &options, &mut |_progress| {})
        .expect_err("second import of the same file must fail");
    assert!(
        error.to_string().contains("duplicate file"),
        "unexpected error: {error}"
    );
    assert_eq!(event_count(&temp.db, first.dataset_id), 2);
    let datasets = db::list_datasets(&temp.db.conn().expect("connection")).expect("datasets");
    assert_eq!(datasets.len(), 1);
}

// ---------------------------------------------------- normalization units

#[test]
fn timestamp_normalization_matrix() {
    use nullplinth_lib::ingest::normalize::{
        normalize_ip, normalize_port, normalize_severity, normalize_transport, parse_timestamp,
    };

    assert_eq!(
        parse_timestamp("2024-03-01T10:00:00Z", None),
        Some(1_709_287_200_000)
    );
    assert_eq!(
        parse_timestamp("2024-03-01T10:00:00.123Z", None),
        Some(1_709_287_200_123)
    );
    // Suricata EVE offset form without a colon
    assert_eq!(
        parse_timestamp("2024-03-01T10:00:00.100000+0000", None),
        Some(1_709_287_200_100)
    );
    // epoch seconds, epoch milliseconds, Zeek float seconds
    assert_eq!(parse_timestamp("1709287200", None), Some(1_709_287_200_000));
    assert_eq!(
        parse_timestamp("1709287200000", None),
        Some(1_709_287_200_000)
    );
    assert_eq!(
        parse_timestamp("1709287200.5", None),
        Some(1_709_287_200_500)
    );
    // naive UTC
    assert_eq!(
        parse_timestamp("2024-03-01 10:00:00", None),
        Some(1_709_287_200_000)
    );
    // explicit CSV format
    assert_eq!(
        parse_timestamp("01/03/2024 10:00:00", Some("%d/%m/%Y %H:%M:%S")),
        Some(1_709_287_200_000)
    );
    assert_eq!(parse_timestamp("not-a-time", None), None);
    assert_eq!(parse_timestamp("", None), None);

    assert_eq!(normalize_ip("10.0.0.1"), Some("10.0.0.1".to_string()));
    assert_eq!(normalize_ip("999.1.1.1"), None);
    assert_eq!(normalize_ip("2001:db8::1"), Some("2001:db8::1".to_string()));
    assert_eq!(normalize_port("70000"), None);
    assert_eq!(normalize_port("-"), None);
    assert_eq!(normalize_transport("TCP"), Some("tcp".to_string()));
    assert_eq!(normalize_transport("17"), Some("udp".to_string()));
    assert_eq!(normalize_severity("warning"), Some("medium".to_string()));
    assert_eq!(normalize_severity("HIGH"), Some("high".to_string()));
    assert_eq!(normalize_severity("bogus"), None);
}

#[test]
fn parse_all_reports_per_record_warnings_without_database() {
    let (events, warnings) =
        ingest::parse_all(Format::Ndjson, &fixture_path("malformed.ndjson"), None).expect("parse");
    assert_eq!(events.len(), 2);
    assert_eq!(warnings.len(), 2);
    assert_eq!(events[0].source_type, "ndjson");
    assert_eq!(events[0].ts, 1_709_287_200_000);
}
