//! Shared data contracts between the Rust backend and the React frontend.
//!
//! Every struct here is serialised with camelCase keys and is mirrored by
//! `src/types/contracts.ts`. Change both sides together.

use serde::{Deserialize, Serialize};

pub fn default_severity() -> String {
    "info".to_string()
}

// ---------------------------------------------------------------- datasets

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dataset {
    pub id: i64,
    pub name: String,
    pub file_name: Option<String>,
    pub file_hash: Option<String>,
    pub file_size: Option<i64>,
    pub source_type: String,
    pub record_count: i64,
    pub skipped_count: i64,
    pub status: String,
    pub warnings: Vec<String>,
    pub imported_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportOptions {
    pub path: String,
    pub name: Option<String>,
    /// Force a format instead of auto-detecting: json | ndjson | suricata | zeek | csv.
    pub source_type: Option<String>,
    pub csv: Option<CsvMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub dataset_id: i64,
    pub imported: i64,
    pub skipped: i64,
    pub warnings: Vec<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportProgress {
    pub dataset_name: String,
    pub phase: String,
    pub processed: i64,
    pub total: Option<i64>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CsvMapping {
    pub delimiter: String,
    pub has_header: bool,
    pub timestamp_column: Option<String>,
    pub timestamp_format: Option<String>,
    /// Normalized field name -> CSV column name.
    pub column_map: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CsvPreview {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub detected_delimiter: String,
    pub has_header: bool,
    /// Normalized field name -> column name, guessed from common header aliases.
    #[serde(default)]
    pub suggested_mapping: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub estimated_rows: Option<i64>,
}

/// What a file looks like before it is imported, shown in the import wizard.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    /// Registry key: suricata, zeek, json, ndjson, csv, linux_auth, syslog, web_access,
    /// firewall, generic_text.
    pub format: String,
    pub format_label: String,
    /// high | medium | low - how sure the detector is about the format.
    pub confidence: String,
    pub sample_lines: Vec<String>,
    pub estimated_records: Option<i64>,
    pub warnings: Vec<String>,
}

// ------------------------------------------------------------------ events

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedEvent {
    #[serde(default)]
    pub dataset_id: i64,
    pub ts: i64,
    pub source_type: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub event_type: Option<String>,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub src_ip: Option<String>,
    #[serde(default)]
    pub dst_ip: Option<String>,
    #[serde(default)]
    pub src_port: Option<i64>,
    #[serde(default)]
    pub dst_port: Option<i64>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub app_proto: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub process_name: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    /// Fields that do not fit the common schema are preserved here.
    #[serde(default)]
    pub attrs: serde_json::Value,
    /// The untouched original record.
    #[serde(default)]
    pub raw: serde_json::Value,
}

impl NormalizedEvent {
    pub fn new(ts: i64, source_type: impl Into<String>) -> Self {
        Self {
            dataset_id: 0,
            ts,
            source_type: source_type.into(),
            category: None,
            event_type: None,
            severity: default_severity(),
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            transport: None,
            app_proto: None,
            action: None,
            username: None,
            hostname: None,
            process_name: None,
            message: None,
            attrs: serde_json::Value::Object(Default::default()),
            raw: serde_json::Value::Null,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventRow {
    pub id: i64,
    pub dataset_id: i64,
    pub ts: i64,
    pub source_type: String,
    pub category: Option<String>,
    pub event_type: Option<String>,
    pub severity: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<i64>,
    pub dst_port: Option<i64>,
    pub transport: Option<String>,
    pub app_proto: Option<String>,
    pub action: Option<String>,
    pub username: Option<String>,
    pub hostname: Option<String>,
    pub process_name: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventDetail {
    pub event: EventRow,
    pub attrs: serde_json::Value,
    pub raw: serde_json::Value,
    pub dataset_name: Option<String>,
}

// ------------------------------------------------------------------ query

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilterRow {
    pub field: String,
    pub op: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventQuery {
    #[serde(default)]
    pub dataset_ids: Vec<i64>,
    #[serde(default)]
    pub source_types: Vec<String>,
    pub from_ts: Option<i64>,
    pub to_ts: Option<i64>,
    #[serde(default)]
    pub filters: Vec<FilterRow>,
    pub text: Option<String>,
    #[serde(default = "default_sort")]
    pub sort: String,
    #[serde(default = "default_sort_dir")]
    pub sort_dir: String,
    /// 1-based page number: 1 is the first page.
    #[serde(default)]
    pub page: u32,
    #[serde(default = "default_page_size")]
    pub page_size: u32,
}

pub fn default_sort() -> String {
    "ts".to_string()
}
pub fn default_sort_dir() -> String {
    "desc".to_string()
}
pub fn default_page_size() -> u32 {
    50
}

impl Default for EventQuery {
    fn default() -> Self {
        Self {
            dataset_ids: vec![],
            source_types: vec![],
            from_ts: None,
            to_ts: None,
            filters: vec![],
            text: None,
            sort: default_sort(),
            sort_dir: default_sort_dir(),
            page: 0,
            page_size: default_page_size(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventPage {
    pub total: i64,
    pub events: Vec<EventRow>,
    pub page: u32,
    pub page_size: u32,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Count {
    pub key: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeBucket {
    pub ts: i64,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Overview {
    pub total_events: i64,
    pub dataset_count: i64,
    pub capture_count: i64,
    pub packet_count: i64,
    pub investigation_count: i64,
    pub alerts_by_severity: Vec<Count>,
    pub alert_total: i64,
    pub recent_alerts: Vec<Alert>,
    pub top_src_ips: Vec<Count>,
    pub top_dst_ips: Vec<Count>,
    pub protocol_distribution: Vec<Count>,
    pub category_distribution: Vec<Count>,
    pub volume_series: Vec<TimeBucket>,
    pub flow_summary: FlowSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowSummary {
    pub flow_count: i64,
    pub total_bytes: i64,
    pub tcp_flows: i64,
    pub udp_flows: i64,
}

// ----------------------------------------------------------------- packets

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capture {
    pub id: i64,
    pub name: String,
    pub file_name: Option<String>,
    pub file_hash: Option<String>,
    pub file_size: Option<i64>,
    pub link_type: Option<String>,
    pub packet_count: i64,
    pub imported_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketRow {
    pub id: i64,
    pub capture_id: i64,
    pub packet_no: i64,
    pub ts: i64,
    pub caplen: i64,
    pub origlen: i64,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<i64>,
    pub dst_port: Option<i64>,
    pub protocol: Option<String>,
    pub transport: Option<String>,
    pub tcp_flags: Option<String>,
    pub payload_len: i64,
    pub summary: Option<String>,
    /// 802.11 frame class: management | control | data.
    #[serde(default)]
    pub frame_kind: Option<String>,
    /// True when the wireless frame is protected/encrypted (payload not decodable).
    #[serde(default)]
    pub encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtoField {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LayerNode {
    pub name: String,
    pub label: String,
    pub fields: Vec<ProtoField>,
    #[serde(default)]
    pub children: Vec<LayerNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketDetail {
    pub packet: PacketRow,
    pub layers: Vec<LayerNode>,
    /// Full frame bytes as hex pairs grouped by byte.
    pub hex: String,
    /// Printable ASCII rendering, 16 bytes per line, '.' for non-printable.
    pub ascii: String,
    pub unsupported: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketQuery {
    pub capture_id: Option<i64>,
    #[serde(default)]
    pub filters: Vec<FilterRow>,
    pub from_ts: Option<i64>,
    pub to_ts: Option<i64>,
    #[serde(default = "default_sort")]
    pub sort: String,
    #[serde(default = "default_sort_dir")]
    pub sort_dir: String,
    #[serde(default)]
    pub page: u32,
    #[serde(default = "default_page_size")]
    pub page_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketPage {
    pub total: i64,
    pub packets: Vec<PacketRow>,
    pub page: u32,
    pub page_size: u32,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowRow {
    pub id: i64,
    pub capture_id: i64,
    pub src_ip: Option<String>,
    pub src_port: Option<i64>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<i64>,
    pub transport: String,
    pub packet_count: i64,
    pub bytes_total: i64,
    pub first_ts: i64,
    pub last_ts: i64,
}

// ------------------------------------------------------------------ alerts

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Alert {
    pub id: i64,
    pub rule: String,
    pub title: String,
    pub severity: String,
    pub confidence: f64,
    pub explanation: String,
    pub threshold: serde_json::Value,
    pub recommended_steps: Vec<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub event_count: i64,
    pub status: String,
    pub note: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertEvidence {
    pub kind: String,
    pub ref_id: i64,
    pub summary: String,
    pub ts: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertDetail {
    pub alert: Alert,
    pub evidence: Vec<AlertEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleRunSummary {
    pub rule: String,
    pub alerts_created: i64,
    pub skipped: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectionRun {
    pub run_id: String,
    pub alerts_created: i64,
    pub rules: Vec<RuleRunSummary>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectionSettings {
    pub brute_force_threshold: u32,
    pub brute_force_window_secs: u32,
    pub port_scan_threshold: u32,
    pub port_scan_window_secs: u32,
    pub dns_nxdomain_threshold: u32,
    pub dns_window_secs: u32,
    pub failed_conn_threshold: u32,
    pub failed_conn_window_secs: u32,
}

impl Default for DetectionSettings {
    fn default() -> Self {
        Self {
            brute_force_threshold: 5,
            brute_force_window_secs: 300,
            port_scan_threshold: 15,
            port_scan_window_secs: 300,
            dns_nxdomain_threshold: 10,
            dns_window_secs: 300,
            failed_conn_threshold: 10,
            failed_conn_window_secs: 300,
        }
    }
}

// ---------------------------------------------------------- investigations

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationNote {
    pub id: i64,
    pub investigation_id: i64,
    pub body: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Investigation {
    pub id: i64,
    pub title: String,
    pub description: String,
    pub status: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub alert_ids: Vec<i64>,
    pub note_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationDetail {
    pub investigation: Investigation,
    pub notes: Vec<InvestigationNote>,
    pub alerts: Vec<Alert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewInvestigation {
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub alert_ids: Vec<i64>,
}

// ----------------------------------------------------------------- export

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportRequest {
    pub path: String,
    /// csv | json
    pub format: String,
    pub query: EventQuery,
}

// --------------------------------------------------------------- workspace

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceState {
    pub has_data: bool,
    pub datasets: i64,
    pub events: i64,
    pub captures: i64,
    pub packets: i64,
    pub flows: i64,
    pub alerts: i64,
    pub investigations: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceClearResult {
    pub datasets: i64,
    pub events: i64,
    pub captures: i64,
    pub packets: i64,
    pub flows: i64,
    pub alerts: i64,
    pub investigations: i64,
    pub backup_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppPreferences {
    /// "ask" (default) or "resume".
    pub startup_behavior: String,
}

impl Default for AppPreferences {
    fn default() -> Self {
        Self {
            startup_behavior: "ask".to_string(),
        }
    }
}