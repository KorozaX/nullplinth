export interface ChartScale {
  max: number;
  step: number;
  ticks: number[];
}

/**
 * Rounded axis scale: picks a 1/2/5 x 10^n step so tick labels stay readable
 * instead of the raw data maximum (for example 75 becomes 0/20/40/60/80).
 */
export function niceScale(peak: number, targetIntervals = 4): ChartScale {
  const safePeak = Number.isFinite(peak) && peak > 0 ? peak : 1;
  const rawStep = safePeak / Math.max(1, targetIntervals);
  const magnitude = Math.pow(10, Math.floor(Math.log10(rawStep)));
  const normalized = rawStep / magnitude;
  let niceStep = 10;
  if (normalized <= 1) niceStep = 1;
  else if (normalized <= 2) niceStep = 2;
  else if (normalized <= 5) niceStep = 5;
  let step = Math.round(niceStep * magnitude);
  if (!Number.isFinite(step) || step < 1) step = 1;
  const max = Math.max(step, Math.ceil(safePeak / step) * step);
  const ticks: number[] = [];
  for (let value = 0; value <= max; value += step) ticks.push(value);
  return { max, step, ticks };
}

/** At most maxTicks evenly spaced indices, always including the first and last. */
export function axisTickIndices(count: number, maxTicks = 6): number[] {
  if (count <= 0) return [];
  if (count <= maxTicks) return Array.from({ length: count }, (_value, index) => index);
  const stride = (count - 1) / (maxTicks - 1);
  const indices: number[] = [];
  for (let index = 0; index < maxTicks; index += 1) indices.push(Math.round(index * stride));
  return Array.from(new Set(indices)).sort((left, right) => left - right);
}
