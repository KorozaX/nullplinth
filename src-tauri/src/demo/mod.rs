//! Deterministic synthetic demonstration dataset.
//!
//! The generator uses a fixed seed and fixed content. All records are labelled as
//! synthetic in their message and in the dataset warning. Reloading is idempotent.

use crate::db::{finish_dataset, insert_dataset, insert_events, now_ms};
use crate::error::AppResult;
use crate::types::NormalizedEvent;
use rusqlite::{Connection, OptionalExtension};
use serde_json::json;
use tauri::Emitter;

const DEMO_HASH: &str = "demo-v1";

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

fn ev(ts: i64, category: &str, action: &str) -> NormalizedEvent {
    let mut e = NormalizedEvent::new(ts, "demo");
    e.category = Some(category.to_string());
    e.action = Some(action.to_string());
    e.severity = "info".to_string();
    e
}

fn raw(record: serde_json::Value) -> serde_json::Value {
    record
}

pub fn load(app: &tauri::AppHandle, conn: &Connection) -> AppResult<i64> {
    if let Some(id) = conn
        .query_row(
            "SELECT id FROM datasets WHERE file_hash = ?1 LIMIT 1",
            [DEMO_HASH],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
    {
        return Ok(id);
    }

    let base = now_ms() - 6 * 3_600_000;
    let mut rng = Rng(0x4e554c4c504c494e);
    let mut events: Vec<NormalizedEvent> = Vec::new();

    let users = ["alice", "bob", "carol", "dave", "erin"];
    let hosts = ["ws-01", "ws-02", "ws-03", "ws-04", "srv-files", "srv-dc01"];
    let internal = ["10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14", "10.0.0.15"];

    // 1. Benign authentication traffic.
    for i in 0..40 {
        let ts = base + i as i64 * 300_000 + (rng.next() % 60_000) as i64;
        let user = users[rng.pick(users.len())];
        let host = hosts[rng.pick(hosts.len())];
        let src = internal[rng.pick(internal.len())];
        let mut e = ev(ts, "authentication", "success");
        e.event_type = Some("login".into());
        e.username = Some(user.into());
        e.hostname = Some(host.into());
        e.src_ip = Some(src.into());
        e.dst_port = Some(445);
        e.transport = Some("tcp".into());
        e.message = Some(format!("[synthetic] successful login for {user} on {host}"));
        e.raw = raw(json!({"event_type": "authentication", "outcome": "success", "user": user, "host": host, "source": src}));
        events.push(e);
    }

    // 2. Benign sporadic authentication failures, below the detection threshold.
    for (i, src) in ["10.0.0.19", "10.0.0.21"].iter().enumerate() {
        let ts = base + 7_200_000 + i as i64 * 900_000;
        let mut e = ev(ts, "authentication", "failed");
        e.event_type = Some("login".into());
        e.username = Some("svc-backup".into());
        e.hostname = Some("srv-files".into());
        e.src_ip = Some((*src).to_string());
        e.dst_port = Some(445);
        e.transport = Some("tcp".into());
        e.severity = "low".into();
        e.message = Some(format!("[synthetic] failed login for svc-backup from {src}"));
        e.raw = raw(json!({"event_type": "authentication", "outcome": "failure", "user": "svc-backup", "source": src}));
        events.push(e);
    }

    // 3. Brute force burst: 12 failures from 203.0.113.44 in 60 seconds.
    for i in 0..12 {
        let ts = base + 3_600_000 + i as i64 * 5_000;
        let mut e = ev(ts, "authentication", "failed");
        e.event_type = Some("login".into());
        e.username = Some("admin".into());
        e.hostname = Some("srv-dc01".into());
        e.src_ip = Some("203.0.113.44".into());
        e.dst_ip = Some("10.0.0.15".into());
        e.dst_port = Some(3389);
        e.transport = Some("tcp".into());
        e.severity = "medium".into();
        e.message = Some(format!("[synthetic] failed RDP login for admin from 203.0.113.44 (attempt {})", i + 1));
        e.attrs = json!({"attempt": i + 1, "protocol": "rdp"});
        e.raw = raw(json!({"event_type": "authentication", "outcome": "failure", "user": "admin", "source": "203.0.113.44", "attempt": i + 1}));
        events.push(e);
    }

    // 4. Port scan: 25 distinct TCP ports from 198.51.100.23 to one host in 90 seconds.
    for i in 0..25 {
        let ts = base + 5_400_000 + i as i64 * 3_600;
        let port = 20 + i as i64;
        let mut e = ev(ts, "network", "allowed");
        e.event_type = Some("connection".into());
        e.src_ip = Some("198.51.100.23".into());
        e.dst_ip = Some("10.0.0.15".into());
        e.src_port = Some(40000 + i as i64);
        e.dst_port = Some(port);
        e.transport = Some("tcp".into());
        e.severity = "low".into();
        e.message = Some(format!("[synthetic] TCP SYN to 10.0.0.15:{port} from 198.51.100.23"));
        e.attrs = json!({"tcp_flags": "SYN"});
        e.raw = raw(json!({"event_type": "network", "action": "allowed", "src": "198.51.100.23", "dst": "10.0.0.15", "dport": port}));
        events.push(e);
    }

    // 5. DNS NXDOMAIN spike from 203.0.113.66.
    for i in 0..15 {
        let ts = base + 7_800_000 + i as i64 * 4_000;
        let mut e = ev(ts, "dns", "response");
        e.event_type = Some("response".into());
        e.src_ip = Some("203.0.113.66".into());
        e.dst_ip = Some("10.0.0.5".into());
        e.dst_port = Some(53);
        e.transport = Some("udp".into());
        e.app_proto = Some("dns".into());
        e.severity = "low".into();
        let name = format!("node{}.sync-update.example", rng.next() % 9999);
        e.message = Some(format!("[synthetic] DNS response NXDOMAIN for {name}"));
        e.attrs = json!({"dnsRcode": "NXDOMAIN", "dnsQuery": name});
        e.raw = raw(json!({"event_type": "dns", "rcode": "NXDOMAIN", "query": name, "source": "203.0.113.66"}));
        events.push(e);
    }

    // 6. Normal DNS traffic.
    for i in 0..30 {
        let ts = base + i as i64 * 420_000 + 30_000;
        let mut e = ev(ts, "dns", "response");
        e.event_type = Some("response".into());
        e.src_ip = Some(internal[rng.pick(internal.len())].to_string());
        e.dst_ip = Some("10.0.0.5".into());
        e.dst_port = Some(53);
        e.transport = Some("udp".into());
        e.app_proto = Some("dns".into());
        let name = ["intranet.example", "files.example", "update.example"][rng.pick(3)];
        e.message = Some(format!("[synthetic] DNS response NOERROR for {name}"));
        e.attrs = json!({"dnsRcode": "NOERROR", "dnsQuery": name});
        e.raw = raw(json!({"event_type": "dns", "rcode": "NOERROR", "query": name}));
        events.push(e);
    }

    // 7. HTTP requests.
    for i in 0..35 {
        let ts = base + i as i64 * 500_000 + 12_000;
        let mut e = ev(ts, "http", "allowed");
        e.event_type = Some("request".into());
        e.src_ip = Some(internal[rng.pick(internal.len())].to_string());
        e.dst_ip = Some("198.51.100.80".into());
        e.dst_port = Some(80);
        e.transport = Some("tcp".into());
        e.app_proto = Some("http".into());
        let path = ["/", "/status", "/assets/app.js", "/login"][rng.pick(4)];
        e.message = Some(format!("[synthetic] GET {path} to 198.51.100.80"));
        e.attrs = json!({"httpMethod": "GET", "httpHost": "portal.example", "httpUrl": path});
        e.raw = raw(json!({"event_type": "http", "method": "GET", "url": path, "host": "portal.example"}));
        events.push(e);
    }

    // 8. Benign allowed connections.
    for i in 0..45 {
        let ts = base + i as i64 * 360_000 + 20_000;
        let mut e = ev(ts, "network", "allowed");
        e.event_type = Some("connection".into());
        e.src_ip = Some(internal[rng.pick(internal.len())].to_string());
        e.dst_ip = Some(["10.0.0.5", "10.0.0.6", "198.51.100.80"][rng.pick(3)].to_string());
        e.dst_port = Some([443, 445, 53][rng.pick(3)]);
        e.transport = Some(if rng.next() % 4 == 0 { "udp".to_string() } else { "tcp".to_string() });
        e.message = Some("[synthetic] connection established".into());
        e.raw = raw(json!({"event_type": "network", "action": "allowed"}));
        events.push(e);
    }

    // 9. Repeated blocked connections from one source (rule 4).
    for i in 0..14 {
        let ts = base + 9_000_000 + i as i64 * 4_000;
        let mut e = ev(ts, "network", "blocked");
        e.event_type = Some("connection".into());
        e.src_ip = Some("198.51.100.77".into());
        e.dst_ip = Some("10.0.0.6".into());
        e.dst_port = Some(22);
        e.transport = Some("tcp".into());
        e.severity = "low".into();
        e.message = Some("[synthetic] connection blocked by firewall policy".into());
        e.raw = raw(json!({"event_type": "network", "action": "blocked", "dst": "10.0.0.6", "dport": 22}));
        events.push(e);
    }

    // 10. A few Suricata-style alerts (context, not generated by our rules).
    for (i, (sev, sig)) in [
        ("high", "ET SCAN Potential SSH Scan"),
        ("medium", "ET POLICY Suspicious User Agent"),
        ("low", "ET INFO Outbound TLS Certificate Observed"),
    ]
    .iter()
    .enumerate()
    {
        let ts = base + 10_800_000 + i as i64 * 120_000;
        let mut e = ev(ts, "alert", "allowed");
        e.event_type = Some("alert".into());
        e.severity = (*sev).to_string();
        e.src_ip = Some("198.51.100.23".into());
        e.dst_ip = Some("10.0.0.15".into());
        e.app_proto = Some("tls".into());
        e.message = Some(format!("[synthetic] {sig}"));
        e.attrs = json!({"signature": sig});
        e.raw = raw(json!({"event_type": "alert", "signature": sig, "severity": sev}));
        events.push(e);
    }

    let tx = conn.unchecked_transaction()?;
    let dataset_id = insert_dataset(
        &tx,
        "Synthetic demonstration dataset",
        Some("demo.ndjson"),
        Some(DEMO_HASH),
        None,
        "demo",
    )?;
    let count = insert_events(&tx, dataset_id, &events)?;
    finish_dataset(
        &tx,
        dataset_id,
        count as i64,
        0,
        &["Synthetic data generated for demonstration only. It is not real telemetry.".to_string()],
        "completed",
    )?;
    tx.commit()?;

    let _ = app.emit(
        "import-progress",
        json!({
            "datasetName": "Synthetic demonstration dataset",
            "phase": "completed",
            "processed": count,
            "total": count,
            "message": "Demo dataset loaded",
        }),
    );
    Ok(dataset_id)
}