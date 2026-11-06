import type { FilterOp, FilterRow } from "../types/contracts";

export type FieldKind = "text" | "number" | "ip" | "enum";

export interface FieldDef {
  field: string;
  label: string;
  kind: FieldKind;
  options?: readonly string[];
  placeholder?: string;
}

export interface OpDef {
  op: FilterOp;
  label: string;
  needsValue: boolean;
}

export const OPERATORS: readonly OpDef[] = [
  { op: "eq", label: "equals", needsValue: true },
  { op: "neq", label: "does not equal", needsValue: true },
  { op: "contains", label: "contains", needsValue: true },
  { op: "notContains", label: "does not contain", needsValue: true },
  { op: "startsWith", label: "starts with", needsValue: true },
  { op: "gt", label: "greater than", needsValue: true },
  { op: "lt", label: "less than", needsValue: true },
  { op: "inCidr", label: "in subnet", needsValue: true },
  { op: "exists", label: "is present", needsValue: false },
  { op: "notExists", label: "is absent", needsValue: false },
];

const OPS_BY_KIND: Record<FieldKind, readonly FilterOp[]> = {
  text: ["eq", "neq", "contains", "notContains", "startsWith", "exists", "notExists"],
  number: ["eq", "neq", "gt", "lt", "exists", "notExists"],
  ip: ["eq", "neq", "inCidr", "exists", "notExists"],
  enum: ["eq", "neq", "exists", "notExists"],
};

export const EVENT_FIELDS: readonly FieldDef[] = [
  { field: "message", label: "Message", kind: "text", placeholder: "text to find in the message" },
  { field: "srcIp", label: "Source IP", kind: "ip", placeholder: "10.0.0.5 or 10.0.0.0/8" },
  { field: "dstIp", label: "Destination IP", kind: "ip", placeholder: "192.0.2.10" },
  { field: "srcPort", label: "Source port", kind: "number", placeholder: "443" },
  { field: "dstPort", label: "Destination port", kind: "number", placeholder: "443" },
  { field: "severity", label: "Severity", kind: "enum", options: ["critical", "high", "medium", "low", "info"] },
  { field: "category", label: "Category", kind: "text", placeholder: "authentication" },
  { field: "eventType", label: "Event type", kind: "text", placeholder: "alert, dns, http" },
  { field: "action", label: "Action", kind: "text", placeholder: "failed" },
  { field: "username", label: "User", kind: "text", placeholder: "jdoe" },
  { field: "hostname", label: "Host", kind: "text", placeholder: "workstation-01" },
  { field: "processName", label: "Process", kind: "text", placeholder: "powershell.exe" },
  { field: "transport", label: "Transport", kind: "text", placeholder: "TCP or UDP" },
  { field: "appProto", label: "Application protocol", kind: "text", placeholder: "dns, http, tls" },
  { field: "sourceType", label: "Source format", kind: "text", placeholder: "suricata, zeek, csv" },
];

export const PACKET_FIELDS: readonly FieldDef[] = [
  { field: "srcIp", label: "Source IP", kind: "ip", placeholder: "10.0.0.5" },
  { field: "dstIp", label: "Destination IP", kind: "ip", placeholder: "192.0.2.10" },
  { field: "srcPort", label: "Source port", kind: "number", placeholder: "443" },
  { field: "dstPort", label: "Destination port", kind: "number", placeholder: "443" },
  { field: "protocol", label: "Protocol", kind: "text", placeholder: "TCP, DNS, TLS" },
  { field: "transport", label: "Transport", kind: "text", placeholder: "TCP or UDP" },
  { field: "tcpFlags", label: "TCP flags", kind: "text", placeholder: "SYN, ACK" },
  { field: "packetLength", label: "Packet length", kind: "number", placeholder: "128" },
];

export function operatorsFor(field: FieldDef | undefined): readonly OpDef[] {
  if (!field) return [];
  const allowed = OPS_BY_KIND[field.kind];
  return OPERATORS.filter((candidate) => allowed.includes(candidate.op));
}

export function findField(fields: readonly FieldDef[], name: string): FieldDef | undefined {
  return fields.find((candidate) => candidate.field === name);
}

export function defaultFilterRow(fields: readonly FieldDef[]): FilterRow {
  const field = fields[0];
  const ops = operatorsFor(field);
  return { field: field ? field.field : "message", op: ops[0] ? ops[0].op : "eq", value: "" };
}

const IPV4 = /^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$/;
const IPV6 = /^[0-9a-fA-F:]+$/;

export function isIpAddress(value: string): boolean {
  const trimmed = value.trim();
  if (IPV4.test(trimmed)) return true;
  if (!trimmed.includes(":") || !IPV6.test(trimmed)) return false;
  const groups = trimmed.split(":");
  return groups.length >= 3 && groups.length <= 9;
}

export function isCidr(value: string): boolean {
  const trimmed = value.trim();
  const slash = trimmed.lastIndexOf("/");
  if (slash < 1) return false;
  const address = trimmed.slice(0, slash);
  const prefixText = trimmed.slice(slash + 1);
  if (!/^[0-9]{1,3}$/.test(prefixText)) return false;
  if (!isIpAddress(address)) return false;
  const prefix = Number(prefixText);
  const max = address.includes(":") ? 128 : 32;
  return prefix >= 0 && prefix <= max;
}

const NUMERIC = /^-?[0-9]+$/;

/** Returns a human-readable problem, or null when the row can be sent to the backend. */
export function validateFilterRow(row: FilterRow, fields: readonly FieldDef[]): string | null {
  const field = findField(fields, row.field);
  if (!field) return "Choose a field";
  const op = OPERATORS.find((candidate) => candidate.op === row.op);
  if (!op) return "Choose an operator";
  if (!operatorsFor(field).some((candidate) => candidate.op === row.op)) {
    return "That operator does not apply to " + field.label;
  }
  if (!op.needsValue) return null;
  const value = row.value.trim();
  if (value.length === 0) return "Add a value";
  if (field.kind === "number") {
    return NUMERIC.test(value) ? null : "Value must be a whole number";
  }
  if (field.kind === "ip") {
    if (row.op === "inCidr") return isCidr(value) ? null : "Enter a subnet such as 10.0.0.0/8";
    return isIpAddress(value) ? null : "Enter a valid IP address";
  }
  if (field.kind === "enum" && field.options) {
    return field.options.includes(value) ? null : "Choose a valid option";
  }
  return null;
}
