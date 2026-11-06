import type { Severity } from "../types/contracts";

export type SeverityKey = "critical" | "high" | "medium" | "low" | "info";
export type ProtocolKind = "tcp" | "udp" | "dns" | "http" | "tls" | "icmp" | "eth" | "ip" | "other";

export const SEVERITY_ORDER: readonly SeverityKey[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_LABELS: Record<SeverityKey, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const SEVERITY_RANK: Record<SeverityKey, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const PROTOCOL_ALIASES: Record<string, ProtocolKind> = {
  tcp: "tcp",
  udp: "udp",
  dns: "dns",
  http: "http",
  https: "http",
  tls: "tls",
  ssl: "tls",
  quic: "tls",
  icmp: "icmp",
  icmpv6: "icmp",
  ethernet: "eth",
  eth: "eth",
  arp: "eth",
  "8021q": "eth",
  vlan: "eth",
  "80211": "eth",
  wifi: "eth",
  ipv4: "ip",
  ipv6: "ip",
  ip: "ip",
};

export function normalizeSeverity(value: string | null | undefined): SeverityKey {
  const lowered = (value ?? "info").toLowerCase();
  return (SEVERITY_ORDER as readonly string[]).includes(lowered) ? (lowered as SeverityKey) : "info";
}

export function severityLabel(value: string | null | undefined): string {
  return SEVERITY_LABELS[normalizeSeverity(value)];
}

export function severityRank(value: string | null | undefined): number {
  return SEVERITY_RANK[normalizeSeverity(value)];
}

export function severityClass(value: string | null | undefined): string {
  return "chip--" + normalizeSeverity(value);
}

/** CSS colour reference for charts and inline bars. */
export function severityColor(value: string | null | undefined): string {
  return "var(--sev-" + normalizeSeverity(value) + ")";
}

export function severityTone(value: string | null | undefined): Severity {
  return normalizeSeverity(value);
}

export function protocolKind(value: string | null | undefined): ProtocolKind {
  const key = (value ?? "").toLowerCase().replace(/[^a-z0-9]/g, "");
  const alias = PROTOCOL_ALIASES[key];
  return alias ?? "other";
}

export function protocolLabel(value: string | null | undefined): string {
  const raw = value ?? "";
  if (raw.trim().length === 0) return "\u2014";
  return raw.toUpperCase();
}

export function protocolClass(value: string | null | undefined): string {
  return "chip--" + protocolKind(value);
}

export function protocolColor(value: string | null | undefined): string {
  return "var(--proto-" + protocolKind(value) + ")";
}

export function frameKindClass(value: string | null | undefined): string {
  const kind = (value ?? "").toLowerCase();
  if (kind === "management" || kind === "control" || kind === "data") return "chip--" + kind;
  return "chip--data";
}

export function statusClass(value: string | null | undefined): string {
  const status = (value ?? "").toLowerCase();
  switch (status) {
    case "new":
    case "investigating":
    case "resolved":
    case "closed":
    case "open":
      return "chip--status-" + status;
    default:
      return "chip--info";
  }
}

export function confidenceClass(value: string | null | undefined): string {
  const confidence = (value ?? "").toLowerCase();
  if (confidence === "high" || confidence === "medium" || confidence === "low") {
    return "chip--confidence-" + confidence;
  }
  return "chip--info";
}

/** Fixed protocol legend order used by the overview distribution. */
export const PROTOCOL_LEGEND: ReadonlyArray<{ kind: ProtocolKind; label: string }> = [
  { kind: "tcp", label: "TCP" },
  { kind: "udp", label: "UDP" },
  { kind: "dns", label: "DNS" },
  { kind: "http", label: "HTTP" },
  { kind: "tls", label: "TLS" },
  { kind: "icmp", label: "ICMP" },
  { kind: "eth", label: "Ethernet" },
  { kind: "ip", label: "IP" },
  { kind: "other", label: "Other" },
];
