export type RangePreset = "all" | "15m" | "1h" | "24h" | "7d" | "30d" | "custom";

export interface RangePresetDef {
  id: RangePreset;
  label: string;
  ms: number | null;
}

const MINUTE = 60000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export const RANGE_PRESETS: readonly RangePresetDef[] = [
  { id: "all", label: "All time", ms: null },
  { id: "15m", label: "Last 15 min", ms: 15 * MINUTE },
  { id: "1h", label: "Last hour", ms: HOUR },
  { id: "24h", label: "Last 24 h", ms: DAY },
  { id: "7d", label: "Last 7 days", ms: 7 * DAY },
  { id: "30d", label: "Last 30 days", ms: 30 * DAY },
  { id: "custom", label: "Custom range", ms: null },
];

export function presetWindow(
  preset: RangePreset,
  now: number = Date.now(),
): { fromTs: number | null; toTs: number | null } {
  const def = RANGE_PRESETS.find((candidate) => candidate.id === preset);
  if (!def || def.ms === null) return { fromTs: null, toTs: null };
  return { fromTs: now - def.ms, toTs: null };
}

export function parseDateTimeInput(value: string): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}
