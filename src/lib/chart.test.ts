import { describe, expect, it } from "vitest";

import { axisTickIndices, niceScale } from "./chart";
import { formatAxisTimestamp, formatRangeLabel } from "./format";

const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;
const BASE = 1767225600000; // a fixed local instant, avoids locale drift

describe("formatAxisTimestamp", () => {
  it("prints a short clock for intraday ranges", () => {
    const label = formatAxisTimestamp(BASE, 6 * HOUR);
    expect(label).toMatch(/^\d{2}:\d{2}$/);
    expect(label).not.toMatch(/\d{13}/);
  });

  it("adds the day when the range crosses days", () => {
    const label = formatAxisTimestamp(BASE, 3 * DAY);
    expect(label).toMatch(/^\d{2} [A-Z][a-z]{2} \d{2}:\d{2}$/);
    expect(label.length).toBeLessThanOrEqual(16);
  });

  it("drops the clock for long ranges", () => {
    const label = formatAxisTimestamp(BASE, 120 * DAY);
    expect(label).toMatch(/^\d{2} [A-Z][a-z]{2}$/);
  });

  it("never emits 13-digit epoch milliseconds", () => {
    for (const span of [0, HOUR, DAY * 2, DAY * 120, DAY * 800]) {
      expect(formatAxisTimestamp(BASE, span)).not.toMatch(/\d{13}/);
    }
  });
});

describe("formatRangeLabel", () => {
  it("shortens a same-day range", () => {
    const label = formatRangeLabel(BASE, BASE + 5 * HOUR);
    expect(label).toMatch(/^\d{2} [A-Z][a-z]{2}, \d{2}:\d{2} - \d{2}:\d{2}$/);
    expect(label).not.toMatch(/\d{13}/);
    expect(label).not.toContain(":00.000");
  });

  it("includes both days for a cross-day range", () => {
    const label = formatRangeLabel(BASE, BASE + 2 * DAY);
    expect(label).toMatch(/^\d{2} [A-Z][a-z]{2} \d{2}:\d{2} - \d{2} [A-Z][a-z]{2} \d{2}:\d{2}$/);
    expect(label).not.toMatch(/\d{13}/);
  });
});

describe("chart scale helpers", () => {
  it("rounds the axis instead of using the raw maximum", () => {
    const scale = niceScale(75, 4);
    expect(scale.max).toBe(80);
    expect(scale.ticks).toEqual([0, 20, 40, 60, 80]);
    for (const tick of scale.ticks) expect(Number.isInteger(tick)).toBe(true);
  });

  it("keeps a sensible scale for tiny and empty data", () => {
    expect(niceScale(0).ticks).toEqual([0, 1]);
    expect(niceScale(1).max).toBeGreaterThanOrEqual(1);
  });

  it("thins buckets to at most six evenly spaced ticks", () => {
    expect(axisTickIndices(4)).toEqual([0, 1, 2, 3]);
    const many = axisTickIndices(100);
    expect(many.length).toBeLessThanOrEqual(6);
    expect(many[0]).toBe(0);
    expect(many[many.length - 1]).toBe(99);
    for (let index = 1; index < many.length; index += 1) {
      expect(many[index]).toBeGreaterThan(many[index - 1]);
    }
  });
});
