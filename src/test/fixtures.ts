import type {
  Alert,
  Capture,
  Dataset,
  DetectionSettings,
  EventDetail,
  EventRow,
  FlowRow,
  Investigation,
  Overview,
  PacketRow,
} from "../types/contracts";

export function eventRow(id: number, overrides: Partial<EventRow> = {}): EventRow {
  return {
    id,
    datasetId: 1,
    ts: 1767225845000,
    sourceType: "suricata",
    category: "authentication",
    eventType: "alert",
    severity: "high",
    srcIp: "203.0.113.44",
    dstIp: "10.0.0.5",
    srcPort: 51234,
    dstPort: 443,
    transport: "TCP",
    appProto: "tls",
    action: "failed",
    username: "jdoe",
    hostname: "workstation-01",
    processName: null,
    message: "Failed login attempt",
    ...overrides,
  };
}

export function eventDetail(event: EventRow): EventDetail {
  return {
    event,
    attrs: { device: "fw-01", rule: "auth-fail" },
    raw: { device: "fw-01", message: event.message, event_type: event.eventType },
    datasetName: "Synthetic demo dataset",
  };
}

export function packetRow(id: number): PacketRow {
  return {
    id,
    captureId: 1,
    packetNo: id,
    ts: 1767225845000,
    caplen: 74,
    origlen: 74,
    srcIp: "10.0.0.10",
    dstIp: "10.0.0.20",
    srcPort: 51515,
    dstPort: 443,
    protocol: "TCP",
    transport: "TCP",
    tcpFlags: "SYN",
    payloadLen: 0,
    summary: "TCP SYN",
  };
}

export function flowRow(id: number): FlowRow {
  return {
    id,
    captureId: 1,
    srcIp: "10.0.0.30",
    srcPort: 40000,
    dstIp: "10.0.0.40",
    dstPort: 80,
    transport: "TCP",
    packetCount: 4,
    bytesTotal: 2048,
    firstTs: 1767225845000,
    lastTs: 1767225849000,
  };
}

export const demoDataset: Dataset = {
  id: 1,
  name: "Synthetic demo dataset",
  fileName: "demo-logs.json",
  fileHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  fileSize: 24576,
  sourceType: "json",
  recordCount: 600,
  skippedCount: 2,
  status: "complete",
  warnings: ["record 12: missing timestamp"],
  importedAt: 1767225845000,
};

export const demoCapture: Capture = {
  id: 1,
  name: "demo-capture.pcap",
  fileName: "demo-capture.pcap",
  fileHash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
  fileSize: 8192,
  linkType: "Ethernet",
  packetCount: 42,
  importedAt: 1767225845000,
};

export const bruteForceAlert: Alert = {
  id: 3,
  rule: "auth_bruteforce",
  title: "Repeated authentication failures",
  severity: "critical",
  confidence: 0.92,
  explanation: "Many failed logins from 203.0.113.44 in a short window.",
  threshold: { attempts: 10, windowSecs: 300 },
  recommendedSteps: ["Block the source IP", "Check the targeted accounts"],
  srcIp: "203.0.113.44",
  dstIp: "10.0.0.5",
  eventCount: 27,
  status: "new",
  note: null,
  createdAt: 1767225845000,
};

export const demoInvestigation: Investigation = {
  id: 7,
  title: "Suspicious outbound traffic",
  description: "Check 10.0.0.5 against the firewall logs.",
  status: "open",
  createdAt: 1767225845000,
  updatedAt: 1767225845000,
  alertIds: [3],
  noteCount: 0,
};

export const defaultSettings: DetectionSettings = {
  bruteForceThreshold: 10,
  bruteForceWindowSecs: 300,
  portScanThreshold: 25,
  portScanWindowSecs: 120,
  dnsNxdomainThreshold: 20,
  dnsWindowSecs: 300,
  failedConnThreshold: 15,
  failedConnWindowSecs: 300,
};

export const emptyOverview: Overview = {
  totalEvents: 0,
  datasetCount: 0,
  captureCount: 0,
  packetCount: 0,
  investigationCount: 0,
  alertsBySeverity: [],
  alertTotal: 0,
  recentAlerts: [],
  topSrcIps: [],
  topDstIps: [],
  protocolDistribution: [],
  categoryDistribution: [],
  volumeSeries: [],
  flowSummary: { flowCount: 0, totalBytes: 0, tcpFlows: 0, udpFlows: 0 },
};

export const populatedOverview: Overview = {
  totalEvents: 1234,
  datasetCount: 1,
  captureCount: 1,
  packetCount: 42,
  investigationCount: 1,
  alertsBySeverity: [
    { key: "critical", count: 2 },
    { key: "high", count: 1 },
  ],
  alertTotal: 3,
  recentAlerts: [bruteForceAlert],
  topSrcIps: [{ key: "203.0.113.44", count: 27 }],
  topDstIps: [{ key: "10.0.0.5", count: 19 }],
  protocolDistribution: [{ key: "tls", count: 12 }],
  categoryDistribution: [{ key: "authentication", count: 27 }],
  volumeSeries: [
    { ts: 1767218400000, count: 10 },
    { ts: 1767222000000, count: 42 },
  ],
  flowSummary: { flowCount: 5, totalBytes: 123456, tcpFlows: 4, udpFlows: 1 },
};
