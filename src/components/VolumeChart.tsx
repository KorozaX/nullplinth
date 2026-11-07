import { useState } from "react";

import type { Alert, Count, TimeBucket } from "../types/contracts";
import type { Mode } from "../lib/mode";
import { axisTickIndices, niceScale } from "../lib/chart";
import {
  formatAxisTimestamp,
  formatNumber,
  formatRangeLabel,
  formatRelativeTime,
  formatTimestamp,
} from "../lib/format";
import {
  normalizeSeverity,
  protocolColor,
  protocolLabel,
  severityColor,
  SEVERITY_ORDER,
  severityLabel,
} from "../lib/semantic";

/* ============================== VOLUME ============================== */
export function VolumeChart({ series, mode }: { series: readonly TimeBucket[]; mode: Mode }) {
  const [hovered, setHovered] = useState<number | null>(null);
  if (series.length === 0) {
    return <p className="muted">No volume recorded for this range.</p>;
  }

  const width = 960;
  const height = 232;
  const padLeft = 44;
  const padRight = 12;
  const padTop = 14;
  const padBottom = 26;
  const innerWidth = width - padLeft - padRight;
  const innerHeight = height - padTop - padBottom;
  const peak = series.reduce((max, bucket) => Math.max(max, bucket.count), 0);
  const scale = niceScale(peak, 4);
  const slot = innerWidth / series.length;
  const barWidth = Math.max(1, Math.min(26, slot - 2));
  const first = series[0];
  const last = series[series.length - 1];
  const span = Math.max(0, last.ts - first.ts);
  const tickIndices = axisTickIndices(series.length, 6);
  const hoveredBucket = hovered === null ? null : series[hovered] ?? null;

  return (
    <div>
      <div className="chart-hover" aria-live="off">
        {hoveredBucket ? (
          <>
            <span>{formatTimestamp(hoveredBucket.ts, mode)}</span>
            <span className="dot" aria-hidden="true">·</span>
            <strong>{formatNumber(hoveredBucket.count)} events</strong>
          </>
        ) : (
          <span className="dim">Hover a column for the exact bucket count</span>
        )}
      </div>
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
          const active = hovered === index;
          return (
            <rect
              key={bucket.ts}
              className={active ? "chart__bar is-hovered" : "chart__bar"}
              x={x}
              y={y}
              width={barWidth}
              height={barHeight}
              onMouseEnter={() => setHovered(index)}
              onMouseLeave={() => setHovered(null)}
            >
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
              y={height - 8}
              textAnchor={anchor}
            >
              {formatAxisTimestamp(bucket.ts, span)}
            </text>
          );
        })}
      </svg>
      <div className="chart-legend">
        <span className="legend">
          <span className="legend__swatch" style={{ background: "var(--teal)" }} aria-hidden="true" />
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

/* ============================== SEVERITY MIX ============================== */
export function SeverityDistribution({
  items,
  label = "Severity mix",
  unit = "alerts",
}: {
  items: readonly Count[];
  label?: string;
  unit?: string;
}) {
  const ordered = SEVERITY_ORDER.map((severity) => ({
    severity,
    label: severityLabel(severity),
    count: items.find((item) => normalizeSeverity(item.key) === severity)?.count ?? 0,
  })).filter((entry) => entry.count > 0);
  const total = ordered.reduce((sum, entry) => sum + entry.count, 0);

  if (total === 0) {
    return <p className="muted">No alerts recorded yet. Run detection to populate the severity mix.</p>;
  }

  return (
    <div>
      <div className="severity-bar" role="img" aria-label={label + " across " + String(total) + " " + unit}>
        {ordered.map((entry) => (
          <span
            key={entry.severity}
            className="severity-bar__seg"
            style={{ width: (entry.count / total) * 100 + "%", background: severityColor(entry.severity) }}
          />
        ))}
      </div>
      <div className="legend-list">
        {ordered.map((entry) => (
          <div className="legend-row" key={entry.severity}>
            <span className="legend-row__swatch" style={{ background: severityColor(entry.severity) }} aria-hidden="true" />
            <span className="legend-row__label">{entry.label}</span>
            <span className="legend-row__value">
              {formatNumber(entry.count)} <span className="dim">· {Math.round((entry.count / total) * 100)}%</span>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ============================== PROTOCOL MIX ============================== */
export function ProtocolMix({ items }: { items: readonly Count[] }) {
  const slices = items.filter((item) => item.count > 0).slice(0, 7);
  const total = slices.reduce((sum, item) => sum + item.count, 0);
  if (total === 0) {
    return <p className="muted">No protocol telemetry stored yet.</p>;
  }

  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;

  return (
    <div className="donut">
      <div className="donut__figure">
        <svg viewBox="0 0 132 132" role="img" aria-label={"Protocol mix across " + String(total) + " records"}>
          <circle cx="66" cy="66" r={radius} fill="none" stroke="var(--surface-2)" strokeWidth="14" />
          {slices.map((item) => {
            const length = (item.count / total) * circumference;
            const dash = String(length) + " " + String(circumference - length);
            const dashOffset = String(-offset);
            offset += length;
            return (
              <circle
                key={item.key}
                className="donut__slice"
                cx="66"
                cy="66"
                r={radius}
                fill="none"
                stroke={protocolColor(item.key)}
                strokeWidth="14"
                strokeDasharray={dash}
                strokeDashoffset={dashOffset}
              />
            );
          })}
        </svg>
        <div className="donut__center">
          <span className="donut__total">{formatNumber(total)}</span>
          <span className="donut__caption">records</span>
        </div>
      </div>
      <div className="donut__legend">
        {slices.map((item) => (
          <div className="legend-row" key={item.key}>
            <span className="legend-row__swatch" style={{ background: protocolColor(item.key) }} aria-hidden="true" />
            <span className="legend-row__label mono">{protocolLabel(item.key)}</span>
            <span className="legend-row__value">{formatNumber(item.count)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ============================== BAR + RANK LISTS ============================== */
export function BarList({
  items,
  colorFor,
  labelFor,
  emptyLabel = "No data for this range.",
}: {
  items: readonly Count[];
  colorFor: (key: string) => string;
  labelFor?: (key: string) => string;
  emptyLabel?: string;
}) {
  if (items.length === 0) return <p className="muted">{emptyLabel}</p>;
  const peak = items.reduce((max, item) => Math.max(max, item.count), 1);
  return (
    <div className="bar-list">
      {items.slice(0, 6).map((item) => (
        <div className="bar-row" key={item.key}>
          <span className="bar-row__label">{labelFor ? labelFor(item.key) : item.key}</span>
          <span className="bar-row__track" aria-hidden="true">
            <span
              className="bar-row__fill"
              style={{ width: Math.max(2, (item.count / peak) * 100) + "%", background: colorFor(item.key) }}
            />
          </span>
          <span className="bar-row__value">{formatNumber(item.count)}</span>
        </div>
      ))}
    </div>
  );
}

export function RankList({ items, emptyLabel = "Nothing observed yet." }: { items: readonly Count[]; emptyLabel?: string }) {
  if (items.length === 0) return <p className="muted">{emptyLabel}</p>;
  return (
    <div className="rank-list">
      {items.slice(0, 6).map((item, index) => (
        <div className="rank-row" key={item.key}>
          <span className="rank-row__index">{String(index + 1).padStart(2, "0")}</span>
          <span className="rank-row__label">{item.key.length > 0 ? item.key : "(empty)"}</span>
          <span className="rank-row__count">{formatNumber(item.count)}</span>
        </div>
      ))}
    </div>
  );
}

/* ============================== RECENT ALERTS ============================== */
export function AlertList({ alerts, onOpen }: { alerts: readonly Alert[]; onOpen: () => void }) {
  if (alerts.length === 0) {
    return <p className="muted">No alerts yet. Run detection to evaluate the stored events.</p>;
  }
  return (
    <div className="alert-list">
      {alerts.slice(0, 6).map((alert) => (
        <button type="button" className="alert-row" key={alert.id} onClick={onOpen}>
          <span
            className="alert-row__dot"
            style={{ background: severityColor(alert.severity) }}
            aria-hidden="true"
          />
          <span className="alert-row__body">
            <span className="alert-row__title">{alert.title}</span>
            <span className="alert-row__meta">
              {severityLabel(alert.severity)} · {alert.rule} · {formatNumber(alert.eventCount)} events
            </span>
          </span>
          <span className="alert-row__time">{formatRelativeTime(alert.createdAt)}</span>
        </button>
      ))}
    </div>
  );
}
