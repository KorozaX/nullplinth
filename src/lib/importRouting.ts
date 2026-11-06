export type ImportKind = "csv" | "log" | "pcap" | "unsupported";

const CSV_EXTENSIONS = ["csv", "tsv"];
const LOG_EXTENSIONS = ["json", "jsonl", "ndjson", "log", "eve", "txt", "suricata", "zeek"];
const PCAP_EXTENSIONS = ["pcap", "pcapng", "cap"];

export function fileExtension(path: string): string {
  const name = path.split(/[\\/]/).pop() ?? path;
  const dot = name.lastIndexOf(".");
  if (dot < 0 || dot === name.length - 1) return "";
  return name.slice(dot + 1).toLowerCase();
}

export function classifyFile(path: string): ImportKind {
  const extension = fileExtension(path);
  if (CSV_EXTENSIONS.includes(extension)) return "csv";
  if (PCAP_EXTENSIONS.includes(extension)) return "pcap";
  if (LOG_EXTENSIONS.includes(extension)) return "log";
  return "unsupported";
}

export const ACCEPTED_EXTENSIONS: readonly string[] = [
  "csv",
  "tsv",
  "json",
  "jsonl",
  "ndjson",
  "log",
  "eve",
  "pcap",
  "pcapng",
];

export const ACCEPTED_LABEL = "CSV, TSV, JSON, NDJSON, log, PCAP, PCAPNG";

export const LOG_FILE_FILTERS = [
  { name: "Log files", extensions: ["json", "jsonl", "ndjson", "log", "eve", "txt"] },
  { name: "CSV files", extensions: ["csv", "tsv"] },
  { name: "Packet captures", extensions: ["pcap", "pcapng", "cap"] },
];
