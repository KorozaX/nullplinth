// Typed mirror of src-tauri/src/types.rs. Keep both sides in sync.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type AlertStatus = "new" | "investigating" | "resolved";
export type InvestigationStatus = "open" | "investigating" | "resolved" | "closed";

export interface Dataset {
  id: number;
  name: string;
  fileName: string | null;
  fileHash: string | null;
  fileSize: number | null;
  sourceType: string;
  recordCount: number;
  skippedCount: number;
  status: string;
  warnings: string[];
  importedAt: number;
}

export interface ImportOptions {
  path: string;
  name?: string | null;
  sourceType?: string | null;
  csv?: CsvMapping | null;
}

export interface ImportResult {
  datasetId: number;
  imported: number;
  skipped: number;
  warnings: string[];
  durationMs: number;
}

export interface ImportProgress {
  datasetName: string;
  phase: string;
  processed: number;
  total: number | null;
  message: string | null;
}

export interface CsvMapping {
  delimiter: string;
  hasHeader: boolean;
  timestampColumn: string | null;
  timestampFormat: string | null;
  columnMap: Record<string, string>;
}

export interface CsvPreview {
  columns: string[];
  rows: string[][];
  detectedDelimiter: string;
  hasHeader: boolean;
  /** Normalized field name -> column name guessed from common header aliases. */
  suggestedMapping: Record<string, string>;
  estimatedRows: number | null;
}

/** Detected format, confidence and samples shown before importing a file. */
export interface ImportPreview {
  format: string;
  formatLabel: string;
  confidence: "high" | "medium" | "low" | string;
  sampleLines: string[];
  estimatedRecords: number | null;
  warnings: string[];
}

export interface NormalizedEvent {
  datasetId: number;
  ts: number;
  sourceType: string;
  category?: string | null;
  eventType?: string | null;
  severity: Severity;
  srcIp?: string | null;
  dstIp?: string | null;
  srcPort?: number | null;
  dstPort?: number | null;
  transport?: string | null;
  appProto?: string | null;
  action?: string | null;
  username?: string | null;
  hostname?: string | null;
  processName?: string | null;
  message?: string | null;
  attrs?: unknown;
  raw?: unknown;
}

export interface EventRow {
  id: number;
  datasetId: number;
  ts: number;
  sourceType: string;
  category: string | null;
  eventType: string | null;
  severity: string;
  srcIp: string | null;
  dstIp: string | null;
  srcPort: number | null;
  dstPort: number | null;
  transport: string | null;
  appProto: string | null;
  action: string | null;
  username: string | null;
  hostname: string | null;
  processName: string | null;
  message: string | null;
}

export interface EventDetail {
  event: EventRow;
  attrs: unknown;
  raw: unknown;
  datasetName: string | null;
}

export type FilterOp =
  | "eq"
  | "neq"
  | "contains"
  | "notContains"
  | "startsWith"
  | "gt"
  | "lt"
  | "exists"
  | "notExists"
  | "inCidr";

export interface FilterRow {
  field: string;
  op: FilterOp;
  value: string;
}

export interface EventQuery {
  datasetIds: number[];
  sourceTypes: string[];
  fromTs: number | null;
  toTs: number | null;
  filters: FilterRow[];
  text: string | null;
  sort: string;
  sortDir: "asc" | "desc";
  /** 1-based page number: 1 is the first page. */
  page: number;
  pageSize: number;
}

export interface EventPage {
  total: number;
  events: EventRow[];
  page: number;
  pageSize: number;
  durationMs: number;
}

export interface Count {
  key: string;
  count: number;
}

export interface TimeBucket {
  ts: number;
  count: number;
}

export interface FlowSummary {
  flowCount: number;
  totalBytes: number;
  tcpFlows: number;
  udpFlows: number;
}

export interface Overview {
  totalEvents: number;
  datasetCount: number;
  captureCount: number;
  packetCount: number;
  investigationCount: number;
  alertsBySeverity: Count[];
  alertTotal: number;
  recentAlerts: Alert[];
  topSrcIps: Count[];
  topDstIps: Count[];
  protocolDistribution: Count[];
  categoryDistribution: Count[];
  eventSeverityDistribution: Count[];
  topPorts: Count[];
  topHosts: Count[];
  volumeSeries: TimeBucket[];
  flowSummary: FlowSummary;
}

export interface Capture {
  id: number;
  name: string;
  fileName: string | null;
  fileHash: string | null;
  fileSize: number | null;
  linkType: string | null;
  packetCount: number;
  importedAt: number;
}

export interface PacketRow {
  id: number;
  captureId: number;
  packetNo: number;
  ts: number;
  caplen: number;
  origlen: number;
  srcIp: string | null;
  dstIp: string | null;
  srcPort: number | null;
  dstPort: number | null;
  protocol: string | null;
  transport: string | null;
  tcpFlags: string | null;
  payloadLen: number;
  summary: string | null;
  /** 802.11 frame class: management | control | data. */
  frameKind: string | null;
  /** Wireless frame is protected/encrypted: payload is not decodable. */
  encrypted: boolean;
}

export interface ProtoField {
  name: string;
  value: string;
}

export interface LayerNode {
  name: string;
  label: string;
  fields: ProtoField[];
  children: LayerNode[];
}

export interface PacketDetail {
  packet: PacketRow;
  layers: LayerNode[];
  hex: string;
  ascii: string;
  unsupported: string | null;
}

export interface PacketQuery {
  captureId: number | null;
  filters: FilterRow[];
  fromTs: number | null;
  toTs: number | null;
  sort: string;
  sortDir: "asc" | "desc";
  /** 1-based page number: 1 is the first page. */
  page: number;
  pageSize: number;
}

export interface PacketPage {
  total: number;
  packets: PacketRow[];
  page: number;
  pageSize: number;
  durationMs: number;
}

export interface FlowRow {
  id: number;
  captureId: number;
  srcIp: string | null;
  srcPort: number | null;
  dstIp: string | null;
  dstPort: number | null;
  transport: string;
  packetCount: number;
  bytesTotal: number;
  firstTs: number;
  lastTs: number;
}

export interface Alert {
  id: number;
  rule: string;
  title: string;
  severity: string;
  confidence: number;
  explanation: string;
  threshold: unknown;
  recommendedSteps: string[];
  srcIp: string | null;
  dstIp: string | null;
  eventCount: number;
  status: string;
  note: string | null;
  createdAt: number;
}

export interface AlertEvidence {
  kind: string;
  refId: number;
  summary: string;
  ts: number | null;
}

export interface AlertDetail {
  alert: Alert;
  evidence: AlertEvidence[];
}

export interface RuleRunSummary {
  rule: string;
  alertsCreated: number;
  skipped: string | null;
}

export interface DetectionRun {
  runId: string;
  alertsCreated: number;
  rules: RuleRunSummary[];
  durationMs: number;
}

export interface DetectionSettings {
  bruteForceThreshold: number;
  bruteForceWindowSecs: number;
  portScanThreshold: number;
  portScanWindowSecs: number;
  dnsNxdomainThreshold: number;
  dnsWindowSecs: number;
  failedConnThreshold: number;
  failedConnWindowSecs: number;
}

export interface InvestigationNote {
  id: number;
  investigationId: number;
  body: string;
  createdAt: number;
}

export interface Investigation {
  id: number;
  title: string;
  description: string;
  status: string;
  createdAt: number;
  updatedAt: number;
  alertIds: number[];
  noteCount: number;
}

export interface InvestigationDetail {
  investigation: Investigation;
  notes: InvestigationNote[];
  alerts: Alert[];
}

export interface NewInvestigation {
  title: string;
  description?: string;
  alertIds?: number[];
}

export interface ExportRequest {
  path: string;
  format: "csv" | "json";
  query: EventQuery;
}
export interface WorkspaceState {
  hasData: boolean;
  datasets: number;
  events: number;
  captures: number;
  packets: number;
  flows: number;
  alerts: number;
  investigations: number;
}

export interface WorkspaceClearResult {
  datasets: number;
  events: number;
  captures: number;
  packets: number;
  flows: number;
  alerts: number;
  investigations: number;
  backupPath: string | null;
}

export interface AppPreferences {
  /** "ask" (default) or "resume". */
  startupBehavior: "ask" | "resume" | string;
}
export interface TopologyNode {
  /** IP address, also the edge endpoint id. */
  id: string;
  label: string;
  kind: "internal" | "external" | "unknown" | string;
  events: number;
  alerts: number;
  /** Worst alert severity on this entity, or "none". */
  severity: string;
  lastSeen: number;
}

export interface TopologyEdge {
  source: string;
  target: string;
  events: number;
  transport: string | null;
  appProto: string | null;
  severity: string;
}

export interface Topology {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  truncated: boolean;
}
