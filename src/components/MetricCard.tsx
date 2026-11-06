import type { ReactNode } from "react";

import { cx } from "../lib/cx";

export interface MetricCardProps {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  signal?: boolean;
}

export function MetricCard({ label, value, hint, signal }: MetricCardProps) {
  return (
    <div className="metric">
      <span className="metric__label">{label}</span>
      <span className={cx("metric__value", signal && "metric__value--signal")}>{value}</span>
      {hint !== undefined ? <span className="metric__hint">{hint}</span> : null}
    </div>
  );
}
