-- NULLPLINTH schema v1. All local: this database never leaves the machine.

CREATE TABLE IF NOT EXISTS datasets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  file_name TEXT,
  file_hash TEXT,
  file_size INTEGER,
  source_type TEXT NOT NULL,
  record_count INTEGER NOT NULL DEFAULT 0,
  skipped_count INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'completed',
  warnings TEXT NOT NULL DEFAULT '[]',
  imported_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  dataset_id INTEGER NOT NULL,
  ts INTEGER NOT NULL,
  source_type TEXT NOT NULL,
  category TEXT,
  event_type TEXT,
  severity TEXT NOT NULL DEFAULT 'info',
  src_ip TEXT,
  dst_ip TEXT,
  src_port INTEGER,
  dst_port INTEGER,
  transport TEXT,
  app_proto TEXT,
  action TEXT,
  username TEXT,
  hostname TEXT,
  process_name TEXT,
  message TEXT,
  attrs TEXT NOT NULL DEFAULT '{}',
  raw TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_dataset ON events(dataset_id);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON events(dst_ip);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
CREATE INDEX IF NOT EXISTS idx_events_transport ON events(transport);
CREATE INDEX IF NOT EXISTS idx_events_app_proto ON events(app_proto);

CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
  message,
  raw,
  content='events',
  content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
  INSERT INTO events_fts(rowid, message, raw) VALUES (new.id, ifnull(new.message, ''), new.raw);
END;

CREATE TRIGGER IF NOT EXISTS events_ad AFTER DELETE ON events BEGIN
  INSERT INTO events_fts(events_fts, rowid, message, raw)
    VALUES ('delete', old.id, ifnull(old.message, ''), old.raw);
END;

CREATE TRIGGER IF NOT EXISTS events_au AFTER UPDATE ON events BEGIN
  INSERT INTO events_fts(events_fts, rowid, message, raw)
    VALUES ('delete', old.id, ifnull(old.message, ''), old.raw);
  INSERT INTO events_fts(rowid, message, raw) VALUES (new.id, ifnull(new.message, ''), new.raw);
END;

CREATE TABLE IF NOT EXISTS packet_captures (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  file_name TEXT,
  file_hash TEXT,
  file_size INTEGER,
  link_type TEXT,
  packet_count INTEGER NOT NULL DEFAULT 0,
  imported_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS packets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  capture_id INTEGER NOT NULL,
  packet_no INTEGER NOT NULL,
  ts INTEGER NOT NULL,
  caplen INTEGER NOT NULL,
  origlen INTEGER NOT NULL,
  src_ip TEXT,
  dst_ip TEXT,
  src_port INTEGER,
  dst_port INTEGER,
  protocol TEXT,
  transport TEXT,
  tcp_flags TEXT,
  payload_len INTEGER NOT NULL DEFAULT 0,
  summary TEXT,
  layers TEXT NOT NULL DEFAULT '[]',
  raw_hex TEXT NOT NULL DEFAULT '',
  frame_kind TEXT,
  encrypted INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_packets_capture ON packets(capture_id);
CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts);
CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip);
CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip);
CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);
CREATE INDEX IF NOT EXISTS idx_packets_transport ON packets(transport);

CREATE TABLE IF NOT EXISTS flows (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  capture_id INTEGER NOT NULL,
  src_ip TEXT,
  src_port INTEGER,
  dst_ip TEXT,
  dst_port INTEGER,
  transport TEXT NOT NULL,
  packet_count INTEGER NOT NULL DEFAULT 0,
  bytes_total INTEGER NOT NULL DEFAULT 0,
  first_ts INTEGER NOT NULL,
  last_ts INTEGER NOT NULL,
  UNIQUE(capture_id, src_ip, src_port, dst_ip, dst_port, transport)
);
CREATE INDEX IF NOT EXISTS idx_flows_capture ON flows(capture_id);

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  rule TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence REAL NOT NULL,
  explanation TEXT NOT NULL,
  threshold TEXT NOT NULL DEFAULT '{}',
  recommended_steps TEXT NOT NULL DEFAULT '[]',
  src_ip TEXT,
  dst_ip TEXT,
  event_count INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'new',
  note TEXT,
  dedupe_key TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);

CREATE TABLE IF NOT EXISTS alert_evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_id INTEGER NOT NULL,
  kind TEXT NOT NULL,
  ref_id INTEGER NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  ts INTEGER
);
CREATE INDEX IF NOT EXISTS idx_evidence_alert ON alert_evidence(alert_id);

CREATE TABLE IF NOT EXISTS investigations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS investigation_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  investigation_id INTEGER NOT NULL,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_investigation ON investigation_notes(investigation_id);

CREATE TABLE IF NOT EXISTS investigation_alerts (
  investigation_id INTEGER NOT NULL,
  alert_id INTEGER NOT NULL,
  PRIMARY KEY (investigation_id, alert_id)
);

CREATE TABLE IF NOT EXISTS saved_filters (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  query TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);