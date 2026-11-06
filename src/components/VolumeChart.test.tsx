import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { VolumeChart } from "./VolumeChart";
import type { TimeBucket } from "../types/contracts";

const HOUR = 3600 * 1000;
const BASE = 1767225600000;

function series(count: number, stepMs: number): TimeBucket[] {
  return Array.from({ length: count }, (_value, index) => ({
    ts: BASE + index * stepMs,
    count: 5 + ((index * 7) % 70),
  }));
}

describe("VolumeChart", () => {
  it("renders at most six short x-axis labels and never an epoch millisecond", () => {
    const { container } = render(<VolumeChart series={series(6, HOUR)} mode="analyst" />);

    const xLabels = Array.from(container.querySelectorAll(".chart__xlabel"));
    expect(xLabels.length).toBeGreaterThan(0);
    expect(xLabels.length).toBeLessThanOrEqual(6);
    for (const label of xLabels) {
      const text = label.textContent ?? "";
      expect(text).not.toMatch(/\d{13}/);
      expect(text).toMatch(/^\d{2}:\d{2}$/);
      expect(text.length).toBeLessThanOrEqual(16);
    }
    expect(screen.getByRole("img", { name: /Event volume over time/ })).toBeInTheDocument();
  });

  it("renders rounded y-axis ticks and six x ticks for a long series", () => {
    const { container } = render(<VolumeChart series={series(100, HOUR)} mode="beginner" />);

    const xLabels = Array.from(container.querySelectorAll(".chart__xlabel"));
    expect(xLabels.length).toBeLessThanOrEqual(6);
    for (const label of xLabels) {
      expect(label.textContent ?? "").not.toMatch(/\d{13}/);
    }

    const yLabels = Array.from(container.querySelectorAll(".chart__ylabel")).map(
      (label) => label.textContent ?? "",
    );
    expect(yLabels).toContain("0");
    for (const label of yLabels) {
      expect(label).toMatch(/^[0-9,]+$/);
    }
    const values = yLabels.map((label) => Number(label.replace(/,/g, "")));
    expect(Math.max(...values)).toBeGreaterThanOrEqual(70);
    expect(Math.max(...values)).toBeLessThanOrEqual(100);
  });

  it("shortens the legend range text", () => {
    const { container } = render(<VolumeChart series={series(6, HOUR)} mode="analyst" />);
    const legendText = container.querySelector(".chart-legend")?.textContent ?? "";
    expect(legendText).not.toMatch(/\d{13}/);
    expect(legendText).not.toContain(".000");
    expect(legendText).toContain("peak events");
    expect(legendText).toMatch(/\d{2} [A-Z][a-z]{2}, \d{2}:\d{2} - \d{2}:\d{2}/);
  });
});
