import type { Mode } from "../lib/mode";
import type { TimeBucket } from "../types/contracts";
import { formatTimestamp } from "../lib/format";

export function VolumeChart({ series, mode }: { series: readonly TimeBucket[]; mode: Mode }) {
  if (series.length === 0) {
    return <p className="muted">No volume recorded for this range.</p>;
  }

  const width = 900;
  const height = 180;
  const padLeft = 8;
  const padTop = 8;
  const padBottom = 18;
  const innerWidth = width - padLeft * 2;
  const innerHeight = height - padTop - padBottom;
  const peak = Math.max(...series.map((bucket) => bucket.count), 1);
  const slot = innerWidth / series.length;
  const barWidth = Math.max(1, Math.min(24, slot - 2));
  const first = series[0];
  const last = series[series.length - 1];

  return (
    <svg
      viewBox={"0 0 " + String(width) + " " + String(height)}
      className="chart"
      role="img"
      aria-label={"Event volume: " + String(series.length) + " buckets, peak " + String(peak) + " events"}
    >
      {[0.25, 0.5, 0.75, 1].map((tick) => {
        const y = padTop + innerHeight - innerHeight * tick;
        return <line key={tick} className="chart__grid" x1={padLeft} x2={width - padLeft} y1={y} y2={y} />;
      })}
      {series.map((bucket, index) => {
        const barHeight = Math.max(1, (bucket.count / peak) * innerHeight);
        const x = padLeft + index * slot + (slot - barWidth) / 2;
        const y = padTop + innerHeight - barHeight;
        return (
          <rect key={bucket.ts} className="chart__bar" x={x} y={y} width={barWidth} height={barHeight}>
            <title>
              {formatTimestamp(bucket.ts, mode) + " \u2014 " + String(bucket.count) + " events"}
            </title>
          </rect>
        );
      })}
      <text className="chart__axis" x={padLeft} y={height - 4}>
        {formatTimestamp(first.ts, mode)}
      </text>
      <text className="chart__axis" x={width - padLeft} y={height - 4} textAnchor="end">
        {formatTimestamp(last.ts, mode)}
      </text>
    </svg>
  );
}
