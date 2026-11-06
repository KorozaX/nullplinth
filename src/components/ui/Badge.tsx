import type { ReactNode } from "react";

import { cx } from "../../lib/cx";
import {
  confidenceClass,
  frameKindClass,
  protocolClass,
  protocolLabel,
  severityClass,
  severityLabel,
  statusClass,
} from "../../lib/semantic";

export type Tone = "critical" | "high" | "medium" | "low" | "info" | "neutral" | "signal" | "ok";

export function Badge({ tone = "neutral", children }: { tone?: Tone; children: ReactNode }) {
  return <span className={cx("badge", "badge--" + tone, "mono")}>{children}</span>;
}

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={cx("chip", severityClass(severity))} data-tone={severityLabel(severity).toLowerCase()}>
      <span className="chip__dot" aria-hidden="true" />
      {severityLabel(severity)}
    </span>
  );
}

export function ProtocolChip({ protocol, label }: { protocol: string | null | undefined; label?: string }) {
  return (
    <span className={cx("chip", protocolClass(protocol))} data-protocol={protocol ?? "none"}>
      {label ?? protocolLabel(protocol)}
    </span>
  );
}

export function FrameKindChip({ frameKind }: { frameKind: string | null | undefined }) {
  if (!frameKind) return null;
  return <span className={cx("chip", frameKindClass(frameKind))}>{frameKind}</span>;
}

export function EncryptedChip({ encrypted }: { encrypted: boolean }) {
  if (!encrypted) return null;
  return (
    <span className="chip chip--encrypted" title="Wireless frame is protected; payload is not decoded">
      Encrypted
    </span>
  );
}

export function StatusChip({ status }: { status: string }) {
  return <span className={cx("chip", statusClass(status))}>{status}</span>;
}

export function ConfidenceChip({ confidence }: { confidence: string }) {
  return <span className={cx("chip", confidenceClass(confidence))}>{confidence}</span>;
}

/** Back-compat alias kept for the alert and investigation screens. */
export function StatusBadge({ status }: { status: string }) {
  return <StatusChip status={status} />;
}

export function severityTone(severity: string): Tone {
  switch (severity.toLowerCase()) {
    case "critical":
    case "high":
    case "medium":
    case "low":
    case "info":
      return severity.toLowerCase() as Tone;
    default:
      return "neutral";
  }
}

export function statusTone(status: string): Tone {
  switch (status.toLowerCase()) {
    case "resolved":
    case "closed":
      return "ok";
    case "investigating":
    case "open":
      return "signal";
    case "new":
      return "medium";
    default:
      return "neutral";
  }
}
