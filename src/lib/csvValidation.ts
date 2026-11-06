import type { CsvPreview } from "../types/contracts";
import type { CsvWizardDraft } from "./csvMapping";
import { CSV_FIELDS, derivedPreview } from "./csvMapping";
import { formatNumber } from "./format";
import { isIpAddress } from "./filterFields";

function canonicalKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

const TS_KEYS = ["ts", "timestamp", "time", "datetime", "eventtime", "eventtimestamp"];

const FIELD_ALIASES: Record<string, string> = {
  srcip: "srcIp",
  sourceip: "srcIp",
  src: "srcIp",
  source: "srcIp",
  srcaddr: "srcIp",
  dstip: "dstIp",
  destip: "dstIp",
  destinationip: "dstIp",
  dst: "dstIp",
  dest: "dstIp",
  dstaddr: "dstIp",
  srcport: "srcPort",
  sourceport: "srcPort",
  sport: "srcPort",
  sp: "srcPort",
  dstport: "dstPort",
  destport: "dstPort",
  destinationport: "dstPort",
  dport: "dstPort",
  dp: "dstPort",
  transport: "transport",
  proto: "transport",
  protocol: "transport",
  appproto: "appProto",
  app: "appProto",
  application: "appProto",
  applicationprotocol: "appProto",
  service: "appProto",
  action: "action",
  eventaction: "action",
  outcome: "action",
  username: "username",
  user: "username",
  account: "username",
  hostname: "hostname",
  host: "hostname",
  dnshost: "hostname",
  eventtype: "eventType",
  type: "eventType",
  eventname: "eventType",
  category: "category",
  eventcategory: "category",
  severity: "severity",
  level: "severity",
  priority: "severity",
  message: "message",
  msg: "message",
  description: "message",
  summary: "message",
};

const KNOWN_FIELDS = CSV_FIELDS.map((field) => field.key);

/** Turn the backend's suggested mapping into a draft, ignoring columns that are not in the preview. */
export function suggestedDraft(preview: CsvPreview): CsvWizardDraft {
  const draft: CsvWizardDraft = {
    hasHeader: preview.hasHeader,
    timestampColumn: "",
    timestampFormat: "auto",
    customFormat: "",
    columnMap: {},
  };
  const columns = preview.columns.map((column) => column.trim());
  for (const [rawKey, rawColumn] of Object.entries(preview.suggestedMapping ?? {})) {
    const key = canonicalKey(rawKey);
    const column = columns.find((candidate) => candidate.toLowerCase() === rawColumn.trim().toLowerCase());
    if (!column) continue;
    if (TS_KEYS.includes(key)) {
      if (draft.timestampColumn.length === 0) draft.timestampColumn = column;
      continue;
    }
    const field = FIELD_ALIASES[key];
    if (field && KNOWN_FIELDS.includes(field)) draft.columnMap[field] = column;
  }
  return draft;
}

export interface SampleInspection {
  sampledRows: number;
  unparsableTimestamps: number;
  invalidIps: number;
  invalidPorts: number;
  estimatedSkipped: number;
  warnings: string[];
}

function looksLikeTimestamp(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) return false;
  if (/^-?[0-9]+(\.[0-9]+)?$/.test(trimmed)) return true;
  return !Number.isNaN(Date.parse(trimmed));
}

function looksLikePort(value: string): boolean {
  const trimmed = value.trim();
  if (!/^[0-9]{1,5}$/.test(trimmed)) return false;
  return Number(trimmed) <= 65535;
}

function columnIndex(columns: readonly string[], column: string): number {
  if (!column) return -1;
  return columns.findIndex((candidate) => candidate === column);
}

/** Inspect the sample rows for values the importer would reject or silently drop. */
export function inspectSamples(preview: CsvPreview, draft: CsvWizardDraft): SampleInspection {
  const derived = derivedPreview(preview, draft.hasHeader);
  const sampledRows = derived.rows.length;
  const tsIndex = columnIndex(derived.columns, draft.timestampColumn);
  const ipColumns = [draft.columnMap.srcIp, draft.columnMap.dstIp].filter(
    (column): column is string => Boolean(column),
  );
  const portColumns = [draft.columnMap.srcPort, draft.columnMap.dstPort].filter(
    (column): column is string => Boolean(column),
  );

  let unparsableTimestamps = 0;
  let invalidIps = 0;
  let invalidPorts = 0;

  for (const row of derived.rows) {
    if (tsIndex >= 0 && !looksLikeTimestamp(row[tsIndex] ?? "")) unparsableTimestamps += 1;
    for (const column of ipColumns) {
      const cell = row[columnIndex(derived.columns, column)] ?? "";
      if (cell.trim().length > 0 && !isIpAddress(cell)) invalidIps += 1;
    }
    for (const column of portColumns) {
      const cell = row[columnIndex(derived.columns, column)] ?? "";
      if (cell.trim().length > 0 && !looksLikePort(cell)) invalidPorts += 1;
    }
  }

  const estimatedSkipped =
    sampledRows > 0 && preview.estimatedRows
      ? Math.round((unparsableTimestamps / sampledRows) * preview.estimatedRows)
      : unparsableTimestamps;

  const warnings: string[] = [];
  if (unparsableTimestamps > 0) {
    warnings.push(
      String(unparsableTimestamps) +
        " of " +
        String(sampledRows) +
        " sample rows have an unparsable timestamp; those rows will be skipped.",
    );
    if (preview.estimatedRows) {
      warnings.push(
        "About " +
          formatNumber(estimatedSkipped) +
          " of " +
          formatNumber(preview.estimatedRows) +
          " estimated rows will be skipped.",
      );
    }
  }
  if (invalidIps > 0) {
    warnings.push(
      String(invalidIps) +
        " sample " +
        (invalidIps === 1 ? "IP value is" : "IP values are") +
        " not a valid IP address and will be left empty.",
    );
  }
  if (invalidPorts > 0) {
    warnings.push(
      String(invalidPorts) +
        " sample " +
        (invalidPorts === 1 ? "port value is" : "port values are") +
        " outside 0-65535 and will be left empty.",
    );
  }
  if (!preview.hasHeader && draft.hasHeader) {
    warnings.push("The header toggle is on but the detector did not find a header row; confirm the column names.");
  }

  return { sampledRows, unparsableTimestamps, invalidIps, invalidPorts, estimatedSkipped, warnings };
}
