import type { CsvMapping, CsvPreview } from "../types/contracts";

export interface CsvFieldDef {
  key: string;
  label: string;
}

/** Normalized fields a CSV column can be mapped to. Order matches the wizard layout. */
export const CSV_FIELDS: readonly CsvFieldDef[] = [
  { key: "srcIp", label: "Source IP" },
  { key: "dstIp", label: "Destination IP" },
  { key: "srcPort", label: "Source port" },
  { key: "dstPort", label: "Destination port" },
  { key: "transport", label: "Transport" },
  { key: "appProto", label: "Application protocol" },
  { key: "action", label: "Action" },
  { key: "username", label: "User" },
  { key: "hostname", label: "Host" },
  { key: "eventType", label: "Event type" },
  { key: "category", label: "Category" },
  { key: "severity", label: "Severity" },
  { key: "message", label: "Message" },
];

export interface TimestampFormatDef {
  value: string;
  label: string;
  format: string | null;
  help: string;
}

/**
 * The backend treats timestampFormat as a chrono pattern tried before its own
 * auto-detection. Empty means auto-detect, which also scales numeric epochs.
 */
export const TIMESTAMP_FORMATS: readonly TimestampFormatDef[] = [
  { value: "auto", label: "Auto-detect", format: null, help: "Let the importer detect ISO 8601, common date formats or numeric epochs." },
  { value: "iso", label: "ISO 8601 / RFC 3339", format: "%Y-%m-%dT%H:%M:%S%.f%z", help: "For example 2026-01-31T14:05:00Z." },
  { value: "space", label: "YYYY-MM-DD HH:MM:SS", format: "%Y-%m-%d %H:%M:%S", help: "For example 2026-01-31 14:05:00." },
  { value: "epoch_s", label: "Epoch seconds", format: null, help: "Numeric epochs are scaled automatically by the importer." },
  { value: "epoch_ms", label: "Epoch milliseconds", format: null, help: "Numeric epochs are scaled automatically by the importer." },
  { value: "custom", label: "Custom pattern", format: null, help: "Chrono pattern, for example %d/%m/%Y %H:%M:%S." },
];

export interface CsvWizardDraft {
  hasHeader: boolean;
  timestampColumn: string;
  timestampFormat: string;
  customFormat: string;
  columnMap: Record<string, string>;
}

export interface DerivedPreview {
  columns: string[];
  rows: string[][];
}

export function initialDraft(preview: CsvPreview): CsvWizardDraft {
  return {
    hasHeader: preview.hasHeader,
    timestampColumn: "",
    timestampFormat: "auto",
    customFormat: "",
    columnMap: {},
  };
}

/**
 * Preview columns depend on whether the first row is a header, and the backend
 * preview cannot take that flag. Re-derive the first row locally when the toggle
 * differs from what the detector guessed, so the mapping names always match the
 * importer's view of the file.
 */
export function derivedPreview(preview: CsvPreview, hasHeader: boolean): DerivedPreview {
  if (preview.hasHeader === hasHeader) {
    return { columns: preview.columns.slice(), rows: preview.rows.slice() };
  }
  if (hasHeader && !preview.hasHeader) {
    const firstRow = preview.rows.length > 0 ? preview.rows[0] : [];
    const columns = firstRow.map((value, index) =>
      value.trim().length > 0 ? value.trim() : "column_" + String(index + 1),
    );
    return { columns, rows: preview.rows.slice(1) };
  }
  const columns = preview.columns.map((_column, index) => "column_" + String(index + 1));
  return { columns, rows: [preview.columns.slice(), ...preview.rows] };
}

export function delimiterLabel(delimiter: string): string {
  switch (delimiter) {
    case ",":
      return "comma";
    case ";":
      return "semicolon";
    case "|":
      return "pipe";
    case "\t":
      return "tab";
    default:
      return delimiter;
  }
}

export function mappedCount(draft: CsvWizardDraft): number {
  return Object.values(draft.columnMap).filter((column) => column.length > 0).length;
}

export function buildCsvMapping(preview: CsvPreview, draft: CsvWizardDraft): CsvMapping {
  const selected = TIMESTAMP_FORMATS.find((candidate) => candidate.value === draft.timestampFormat);
  let timestampFormat: string | null = selected ? selected.format : null;
  if (draft.timestampFormat === "custom") {
    const custom = draft.customFormat.trim();
    timestampFormat = custom.length > 0 ? custom : null;
  }
  const columnMap: Record<string, string> = {};
  for (const field of CSV_FIELDS) {
    const column = draft.columnMap[field.key];
    if (column && column.length > 0) columnMap[field.key] = column;
  }
  return {
    delimiter: preview.detectedDelimiter,
    hasHeader: draft.hasHeader,
    timestampColumn: draft.timestampColumn.length > 0 ? draft.timestampColumn : null,
    timestampFormat,
    columnMap,
  };
}

/** Returns a plain-language problem that blocks the import, or null when valid. */
export function validateDraft(draft: CsvWizardDraft, columns: readonly string[]): string | null {
  if (draft.timestampColumn.length === 0) {
    return "Map the timestamp column before importing.";
  }
  if (!columns.includes(draft.timestampColumn)) {
    return "The timestamp column is no longer in the preview. Choose a column again.";
  }
  if (mappedCount(draft) < 1) {
    return "Map at least one other field so the events carry meaning.";
  }
  if (draft.timestampFormat === "custom" && draft.customFormat.trim().length === 0) {
    return "Enter a timestamp pattern such as %Y-%m-%d %H:%M:%S.";
  }
  for (const field of CSV_FIELDS) {
    const column = draft.columnMap[field.key];
    if (column && column.length > 0 && !columns.includes(column)) {
      return "Column \u201C" + column + "\u201D is not in the preview (" + field.label + ").";
    }
  }
  return null;
}
