export type Mode = "beginner" | "analyst";

export const MODE_STORAGE_KEY = "nullplinth.mode";

export const MODE_OPTIONS: ReadonlyArray<{ value: Mode; label: string; hint: string }> = [
  { value: "beginner", label: "Beginner", hint: "Friendly labels, fewer columns, plain-language explanations" },
  { value: "analyst", label: "Analyst", hint: "Dense columns, raw records, precise timestamps and rule detail" },
];

export function isMode(value: unknown): value is Mode {
  return value === "beginner" || value === "analyst";
}
