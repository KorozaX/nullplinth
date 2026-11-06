import type { Count, TimeBucket } from "../types/contracts";
import type { Mode } from "../lib/mode";
import { axisTickIndices, niceScale } from "../lib/chart";
import { formatAxisTimestamp, formatNumber, formatRangeLabel, formatTimestamp } from "../lib/format";

export function VolumeChart({ series, mode }: { series: readonly TimeBucket[]; mode: Mode }) {
  if (series.length === 0) {
    return <p className="muted">No volume recorded for this range.</p>;
  }

  const width = 960;
  const height = 220;
  const padLeft = 44;
  const padRight = 12;
  const padTop = 12;
  const padBottom = 24;
  const innerWidth = width - padLeft - padRight;
  const innerHeight = height - padTop - padBottom;
  const peak = series.reduce((max, bucket) => Math.max(max, bucket.count), 0);
  const scale = niceScale(peak, 4);
  const slot = innerWidth / series.length;
  const barWidth = Math.max(1, Math.min(28, slot - 2));
  const first = series[0];
  const last = series[series.length - 1];
  const span = Math.max(0, last.ts - first.ts);
  const tickIndices = axisTickIndices(series.length, 6);

  return (
    <div>
      <svg
        viewBox={"0 0 " + String(width) + " " + String(height)}
        className="chart"
        role="img"
        aria-label={"Event volume over time: " + String(series.length) + " buckets, peak " + String(peak) + " events"}
      >
        {scale.ticks.map((tick) => {
          const y = padTop + innerHeight - (tick / scale.max) * innerHeight;
          return <line key={"grid-" + tick} className="chart__grid" x1={padLeft} x2={width - padRight} y1={y} y2={y} />;
        })}
        {scale.ticks.map((tick) => {
          const y = padTop + innerHeight - (tick / scale.max) * innerHeight;
          return (
            <text key={"ylabel-" + tick} className="chart__label chart__ylabel" x={padLeft - 8} y={y + 3} textAnchor="end">
              {formatNumber(tick)}
            </text>
          );
        })}
        {series.map((bucket, index) => {
          const barHeight = Math.max(1, (bucket.count / scale.max) * innerHeight);
          const x = padLeft + index * slot + (slot - barWidth) / 2;
          const y = padTop + innerHeight - barHeight;
          return (
            <rect key={bucket.ts} className="chart__bar" x={x} y={y} width={barWidth} height={barHeight}>
              <title>{formatTimestamp(bucket.ts, mode) + " \u2014 " + String(bucket.count) + " events"}</title>
            </rect>
          );
        })}
        {tickIndices.map((index) => {
          const bucket = series[index];
          if (!bucket) return null;
          const x = padLeft + index * slot + barWidth / 2;
          const anchor = index === 0 ? "start" : index === series.length - 1 ? "end" : "middle";
          return (
            <text
              key={"xlabel-" + bucket.ts}
              className="chart__label chart__xlabel"
              x={index === 0 ? padLeft : x}
              y={height - 6}
              textAnchor={anchor}
            >
              {formatAxisTimestamp(bucket.ts, span)}
            </text>
          );
        })}
      </svg>
      <div className="chart-legend">
        <span className="legend">
          <span className="legend__swatch" style={{ background: "var(--accent)" }} aria-hidden="true" />
          {formatNumber(peak)} peak events in {String(series.length)} buckets
        </span>
        <span className="legend">
          <span className="legend__swatch" style={{ background: "var(--line-strong)" }} aria-hidden="true" />
          {formatRangeLabel(first.ts, last.ts)}
        </span>
      </div>
    </div>
  );
}

export interface DistributionListProps {
  items: readonly Count[];
  colorFor: (key: string) => string;
  labelFor?: (key: string) => string;
  limit?: number;
  unit?: string;
  emptyLabel?: string;
}

export function DistributionList({
  items,
  colorFor,
  labelFor,
  limit = 6,
  unit = "events",
  emptyLabel = "No data for this range.",
}: DistributionListProps) {
  if (items.length === 0) return <p className="muted">{emptyLabel}</p>;
  const peak = items.reduce((max, item) => Math.max(max, item.count), 1);
  return (
    <ul className="dist">
      {items.slice(0, limit).map((item) => {
        const color = colorFor(item.key);
        return (
          <li className="dist__row" key={item.key}>
            <span className="dist__label">
              <span className="legend__swatch" style={{ background: color }} aria-hidden="true" />
              <span className="dist__name mono">{labelFor ? labelFor(item.key) : item.key.length > 0 ? item.key : "(empty)"}</span>
            </span>
            <span className="dist__track" aria-hidden="true">
              <span
                className="dist__fill"
                style={{ width: String(Math.max(2, (item.count / peak) * 100)) + "%", background: color }}
              />
            </span>
            <span className="dist__value">
              {formatNumber(item.count)}
              <span className="sr-only"> {unit}</span>
            </span>
          </li>
        );
      })}
    </ul>
  );
}

export function DistributionLegend({
  entries,
  colorFor,
}: {
  entries: ReadonlyArray<{ key: string; label: string; color: string }>;
  colorFor?: (key: string) => string;
}) {
  return (
    <div className="dist__legend">
      {entries.map((entry) => (
        <span className="legend" key={entry.key}>
          <span
            className="legend__swatch"
            style={{ background: colorFor ? colorFor(entry.key) : entry.color }}
            aria-hidden="true"
          />
          {entry.label}
        </span>
      ))}
    </div>
  );
}
