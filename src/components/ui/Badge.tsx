import type { ReactNode } from "react";

import { cx } from "../../lib/cx";

export type Tone = "critical" | "high" | "medium" | "low" | "info" | "neutral" | "signal" | "ok";

export function Badge({ tone = "neutral", children }: { tone?: Tone; children: ReactNode }) {
  return <span className={cx("badge", "badge--" + tone, "mono")}>{children}</span>;
}

export function severityTone(severity: string): Tone {
  switch (severity.toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    case "info":
      return "info";
    default:
      return "neutral";
  }
}

export function SeverityBadge({ severity }: { severity: string }) {
  return <Badge tone={severityTone(severity)}>{severity.toUpperCase()}</Badge>;
}

export function statusTone(status: string): Tone {
  switch (status.toLowerCase()) {
    case "resolved":
    case "closed":
      return "ok";
    case "investigating":
      return "signal";
    case "new":
    case "open":
      return "medium";
    default:
      return "neutral";
  }
}

export function StatusBadge({ status }: { status: string }) {
  return <Badge tone={statusTone(status)}>{status.toUpperCase()}</Badge>;
}
