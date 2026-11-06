//! Performance requirement from the specification: import and query 100,000 events.
//!
//! Run with: cargo test --test perf_tests -- --nocapture
//! Measurements are printed and asserted against deliberately generous budgets so a
//! very slow CI machine fails loudly instead of silently regressing.

use nullplinth_lib::db::{self, Db};
use nullplinth_lib::query;
use nullplinth_lib::types::*;
use std::time::Instant;

const EVENT_COUNT: usize = 100_000;

fn temp_db(tag: &str) -> Db {
    let mut path = std::env::temp_dir();
    path.push(format!("nullplinth-perf-{tag}-{}.db", db::now_ms()));
    let _ = std::fs::remove_file(&path);
    Db::open(path).expect("open perf database")
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn pick(&mut self, len: usize) -> usize {
        (self.next() as usize) % len.max(1)
    }
}

fn generate(count: usize, base: i64) -> Vec<NormalizedEvent> {
    let mut rng = Rng(0x4e554c4c504c494e);
    let users = ["alice", "bob", "carol", "dave", "erin", "frank"];
    let hosts = ["ws-01", "ws-02", "srv-dc01", "srv-files", "web-01"];
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let mut e = NormalizedEvent::new(base + (i as i64) * 500, "perf");
        e.category = Some(
            ["authentication", "network", "dns", "http"][rng.pick(4)].to_string(),
        );
        e.action = Some(if rng.next() % 5 == 0 { "failed" } else { "allowed" }.to_string());
        e.severity = ["info", "low", "medium"][rng.pick(3)].to_string();
        e.src_ip = Some(format!("10.0.{}.{}", rng.next() % 8, rng.next() % 250));
        e.dst_ip = Some(format!("198.51.100.{}", rng.next() % 250));
        e.src_port = Some(1024 + (rng.next() % 60000) as i64);
        e.dst_port = Some([443, 80, 53, 445, 22][rng.pick(5)]);
        e.transport = Some(if rng.next() % 3 == 0 { "udp" } else { "tcp" }.to_string());
        e.app_proto = Some(["http", "dns", "tls"][rng.pick(3)].to_string());
        e.username = Some(users[rng.pick(users.len())].to_string());
        e.hostname = Some(hosts[rng.pick(hosts.len())].to_string());
        e.message = Some(format!(
            "synthetic perf event {i} user {} host {}",
            users[i % users.len()],
            hosts[i % hosts.len()]
        ));
        e.attrs = serde_json::json!({"perf": true, "index": i});
        e.raw = serde_json::json!({"event": "perf", "index": i});
        out.push(e);
    }
    out
}

#[test]
fn import_and_query_one_hundred_thousand_events() {
    let db = temp_db("100k");
    let base = 1_700_000_000_000i64;
    let events = generate(EVENT_COUNT, base);

    let started = Instant::now();
    {
        let conn = db.conn().unwrap();
        let tx = conn.unchecked_transaction().unwrap();
        let dataset_id = db::insert_dataset(
            &tx,
            "performance dataset",
            Some("perf.ndjson"),
            Some("perf-v1"),
            None,
            "perf",
        )
        .unwrap();
        for chunk in events.chunks(1_000) {
            db::insert_events(&tx, dataset_id, chunk).unwrap();
        }
        db::finish_dataset(&tx, dataset_id, EVENT_COUNT as i64, 0, &[], "completed").unwrap();
        tx.commit().unwrap();
    }
    let import_ms = started.elapsed().as_millis();

    let conn = db.conn().unwrap();
    let total = query::overview(&conn).unwrap().total_events;
    assert_eq!(total, EVENT_COUNT as i64, "every generated event must be stored");

    // Indexed equality filter.
    let mut q = EventQuery {
        page_size: 50,
        ..Default::default()
    };
    q.filters = vec![FilterRow {
        field: "srcIp".into(),
        op: "eq".into(),
        value: "10.0.3.42".into(),
    }];
    let t = Instant::now();
    let page = query::query_events(&conn, &q).unwrap();
    let exact_filter_ms = t.elapsed().as_millis();

    // Time range plus protocol filter, the most common analyst query.
    let mut q2 = EventQuery {
        page_size: 50,
        ..Default::default()
    };
    q2.from_ts = Some(base + 1_000_000);
    q2.to_ts = Some(base + 20_000_000);
    q2.filters = vec![FilterRow {
        field: "transport".into(),
        op: "eq".into(),
        value: "tcp".into(),
    }];
    let t = Instant::now();
    let ranged = query::query_events(&conn, &q2).unwrap();
    let range_filter_ms = t.elapsed().as_millis();

    // Full-text search.
    let mut q3 = EventQuery {
        page_size: 50,
        text: Some("user alice".into()),
        ..Default::default()
    };
    let t = Instant::now();
    let fts = query::query_events(&conn, &q3).unwrap();
    let fts_ms = t.elapsed().as_millis();
    q3.text = None;

    // Pagination deep in the result set.
    let mut q4 = EventQuery {
        page_size: 100,
        page: 500,
        ..Default::default()
    };
    let t = Instant::now();
    let deep_page = query::query_events(&conn, &q4).unwrap();
    let deep_page_ms = t.elapsed().as_millis();
    q4.page = 0;

    let db_bytes = std::fs::metadata(db.path()).map(|m| m.len()).unwrap_or(0);
    println!("PERF import_100k_ms={import_ms}");
    println!("PERF exact_ip_filter_ms={exact_filter_ms} matches={}", page.total);
    println!("PERF range_protocol_filter_ms={range_filter_ms} matches={}", ranged.total);
    println!("PERF fts_query_ms={fts_ms} matches={}", fts.total);
    println!("PERF deep_pagination_ms={deep_page_ms} rows={}", deep_page.events.len());
    println!("PERF db_size_mb={:.1}", db_bytes as f64 / (1024.0 * 1024.0));

    assert!(page.total > 0, "expected matches for the generated address");
    assert!(ranged.total > 0, "expected matches in the time range");
    assert!(fts.total > 0, "expected full text matches");
    assert!(
        import_ms < 180_000,
        "import of 100k events took {import_ms} ms, budget is 180000 ms"
    );
    for (label, ms) in [
        ("exact filter", exact_filter_ms),
        ("range filter", range_filter_ms),
        ("full-text", fts_ms),
        ("deep pagination", deep_page_ms),
    ] {
        assert!(ms < 2_000, "{label} took {ms} ms, budget is 2000 ms");
    }
}
