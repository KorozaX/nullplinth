import type { ReactNode } from "react";

import { cx } from "../lib/cx";

export type MetricTone = "default" | "accent" | "critical" | "ok";

export interface MetricPanelProps {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: MetricTone;
  /** Optional sparkline values rendered as tiny bars. */
  spark?: readonly number[];
}

/** One cell of the overview metric strip: label, large value, mono sub-line. */
export function MetricPanel({ label, value, hint, tone = "default", spark }: MetricPanelProps) {
  const peak = spark && spark.length > 0 ? Math.max(...spark, 1) : 1;
  return (
    <div className={cx("metric-cell", tone !== "default" && "metric-cell--" + tone)}>
      <span className="metric-cell__label">{label}</span>
      <span className="metric-cell__value">{value}</span>
      {spark && spark.length > 0 ? (
        <span className="metric-cell__spark" aria-hidden="true">
          {spark.slice(-18).map((point, index) => (
            <span key={index} style={{ height: String(Math.max(2, Math.round((point / peak) * 18))) + "px" }} />
          ))}
        </span>
      ) : null}
      {hint !== undefined ? <span className="metric-cell__delta">{hint}</span> : null}
    </div>
  );
}

export function MetricsStrip({ children }: { children: ReactNode }) {
  return <div className="metric-strip">{children}</div>;
}
