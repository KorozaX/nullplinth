import type { ReactNode } from "react";

import { cx } from "../lib/cx";

export type MetricTone = "default" | "accent" | "critical" | "success";

export interface MetricCardProps {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: MetricTone;
}

export function MetricCard({ label, value, hint, tone = "default" }: MetricCardProps) {
  return (
    <div className="metric">
      <span className="metric__label">{label}</span>
      <span className={cx("metric__value", tone !== "default" && "metric__value--" + tone)}>{value}</span>
      {hint !== undefined ? <span className="metric__hint">{hint}</span> : null}
    </div>
  );
}
