import { formatNumber } from "./format";

/** Accurate, correctly pluralized import notification for event imports. */
export function importSuccessMessage(imported: number, skipped: number): string {
  const eventWord = imported === 1 ? "event" : "events";
  const base = "Successfully imported " + formatNumber(imported) + " " + eventWord + " into NULLPLINTH.";
  if (skipped <= 0) return base;
  return base + " Skipped " + formatNumber(skipped) + " " + (skipped === 1 ? "record" : "records") + ".";
}

export function captureSuccessMessage(captureName: string, packetCount: number): string {
  const packetWord = packetCount === 1 ? "packet" : "packets";
  return (
    "Imported " + formatNumber(packetCount) + " " + packetWord + " from " + captureName + " into NULLPLINTH."
  );
}

export function demoSuccessMessage(imported: number): string {
  const eventWord = imported === 1 ? "event" : "events";
  return "Imported " + formatNumber(imported) + " demo " + eventWord + " into NULLPLINTH.";
}

export function clearedWorkspaceMessage(datasets: number, events: number): string {
  return (
    "Workspace cleared: removed " +
    formatNumber(datasets) +
    " " +
    (datasets === 1 ? "dataset" : "datasets") +
    " and " +
    formatNumber(events) +
    " " +
    (events === 1 ? "event" : "events") +
    "."
  );
}
