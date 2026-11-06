import type { Mode } from "./mode";

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function pad(value: number, width = 2): string {
  return String(value).padStart(width, "0");
}

/** Mode-aware timestamp: beginners get a readable clock, analysts get millisecond precision. */
export function formatTimestamp(ts: number | null | undefined, mode: Mode): string {
  if (ts === null || ts === undefined || !Number.isFinite(ts)) return "\u2014";
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return "\u2014";
  const day = pad(date.getDate());
  const month = MONTHS[date.getMonth()];
  const year = date.getFullYear();
  const clock = pad(date.getHours()) + ":" + pad(date.getMinutes()) + ":" + pad(date.getSeconds());
  if (mode === "beginner") return day + " " + month + " " + year + " " + clock.slice(0, 5);
  return year + "-" + pad(date.getMonth() + 1) + "-" + day + " " + clock + "." + pad(date.getMilliseconds(), 3);
}

export function formatIsoTimestamp(ts: number | null | undefined): string {
  if (ts === null || ts === undefined || !Number.isFinite(ts)) return "\u2014";
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return "\u2014";
  return date.toISOString();
}

export function formatRelativeTime(ts: number | null | undefined, now: number = Date.now()): string {
  if (ts === null || ts === undefined || !Number.isFinite(ts)) return "\u2014";
  const delta = Math.max(0, now - ts);
  const seconds = Math.floor(delta / 1000);
  if (seconds < 45) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return String(minutes) + " min ago";
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return String(hours) + " h ago";
  const days = Math.floor(hours / 24);
  if (days < 30) return String(days) + " d ago";
  return formatTimestamp(ts, "beginner");
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "\u2014";
  return value.toLocaleString("en-US");
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return "\u2014";
  if (bytes < 1024) return String(bytes) + " B";
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = -1;
  do {
    value = value / 1024;
    unit += 1;
  } while (value >= 1024 && unit < units.length - 1);
  return value.toFixed(value >= 10 ? 0 : 1) + " " + units[unit];
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return "\u2014";
  if (ms < 1000) return String(Math.round(ms)) + " ms";
  if (ms < 60000) return (ms / 1000).toFixed(2) + " s";
  const minutes = Math.floor(ms / 60000);
  const seconds = Math.round((ms % 60000) / 1000);
  return String(minutes) + "m " + pad(seconds) + "s";
}

export function formatPercent(ratio: number | null | undefined): string {
  if (ratio === null || ratio === undefined || !Number.isFinite(ratio)) return "\u2014";
  const clamped = Math.min(1, Math.max(0, ratio));
  return String(Math.round(clamped * 100)) + "%";
}

export function pluralize(count: number, singular: string, plural?: string): string {
  return count === 1 ? singular : plural ?? singular + "s";
}

export function capitalize(text: string): string {
  if (text.length === 0) return text;
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function fileName(path: string | null | undefined): string {
  if (!path) return "\u2014";
  const parts = path.split(/[\\/]/);
  const last = parts[parts.length - 1];
  return last && last.length > 0 ? last : path;
}

export function shortHash(hash: string | null | undefined, length = 12): string {
  if (!hash) return "\u2014";
  return hash.length <= length ? hash : hash.slice(0, length) + "\u2026";
}

const FIELD_LABELS: Record<string, string> = {
  id: "ID",
  datasetId: "Dataset",
  ts: "Timestamp",
  sourceType: "Source format",
  category: "Category",
  eventType: "Event type",
  severity: "Severity",
  srcIp: "Source IP",
  dstIp: "Destination IP",
  srcPort: "Source port",
  dstPort: "Destination port",
  transport: "Transport",
  appProto: "Application protocol",
  action: "Action",
  username: "User",
  hostname: "Host",
  processName: "Process",
  message: "Message",
  attrs: "Unmapped attributes",
  raw: "Original record",
  packetNo: "Packet",
  caplen: "Captured length",
  origlen: "Original length",
  protocol: "Protocol",
  tcpFlags: "TCP flags",
  payloadLen: "Payload length",
  summary: "Summary",
  captureId: "Capture",
  bytesTotal: "Bytes",
  packetCount: "Packets",
  firstTs: "First seen",
  lastTs: "Last seen",
  createdAt: "Created",
  updatedAt: "Updated",
  confidence: "Confidence",
  rule: "Rule",
  eventCount: "Events",
  noteCount: "Notes",
  fileSize: "File size",
  recordCount: "Records",
  skippedCount: "Skipped",
  importedAt: "Imported",
  fileName: "File",
  fileHash: "File hash",
  linkType: "Link type",
};

export function formatFieldLabel(field: string): string {
  const known = FIELD_LABELS[field];
  if (known) return known;
  const spaced = field.replace(/([a-z0-9])([A-Z])/g, "$1 $2");
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

/** Render an arbitrary contract value as plain text. Never returns HTML. */
export function formatValue(value: unknown): string {
  if (value === null || value === undefined || value === "") return "\u2014";
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : "\u2014";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

export function formatJson(value: unknown): string {
  if (value === null || value === undefined) return "null";
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

export function formatEndpoint(ip: string | null | undefined, port: number | null | undefined): string {
  if (!ip) return "\u2014";
  return port === null || port === undefined ? ip : ip + ":" + String(port);
}

/** "06 Nov" without a year, used by compact chart labels and legends. */
export function formatDateShort(ts: number): string {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return "\u2014";
  return pad(date.getDate()) + " " + MONTHS[date.getMonth()];
}

/**
 * Short local axis label. Intraday ranges show only a clock, multi-day ranges
 * add the day, long ranges drop the clock. Never prints epoch milliseconds.
 */
export function formatAxisTimestamp(ts: number, spanMs: number): string {
  if (!Number.isFinite(ts)) return "\u2014";
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return "\u2014";
  const clock = pad(date.getHours()) + ":" + pad(date.getMinutes());
  const span = Number.isFinite(spanMs) && spanMs > 0 ? spanMs : 0;
  if (span < 20 * 3600 * 1000) return clock;
  if (span < 30 * 24 * 3600 * 1000) return formatDateShort(ts) + " " + clock;
  if (span < 365 * 24 * 3600 * 1000) return formatDateShort(ts);
  return MONTHS[date.getMonth()] + " " + String(date.getFullYear());
}

/** Compact "06 Nov, 17:00 - 22:00" range for chart legends. */
export function formatRangeLabel(from: number, to: number): string {
  if (!Number.isFinite(from) || !Number.isFinite(to)) return "\u2014";
  const start = new Date(from);
  const end = new Date(to);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) return "\u2014";
  const clock = (value: Date) => pad(value.getHours()) + ":" + pad(value.getMinutes());
  const sameDay =
    start.getFullYear() === end.getFullYear() &&
    start.getMonth() === end.getMonth() &&
    start.getDate() === end.getDate();
  if (sameDay) return formatDateShort(from) + ", " + clock(start) + " - " + clock(end);
  return formatDateShort(from) + " " + clock(start) + " - " + formatDateShort(to) + " " + clock(end);
}
