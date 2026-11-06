export interface HexRow {
  offset: string;
  bytes: string;
  ascii: string;
}

const BYTES_PER_ROW = 16;
const BLANK = "\u2007";

/**
 * Normalise backend hex + ASCII into aligned rows. Accepts either a
 * pre-formatted multi-line dump or one continuous hex string.
 */
export function buildHexRows(rawHex: string, rawAscii: string): HexRow[] {
  const hexLines = rawHex.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const asciiLines = rawAscii.split(/\r?\n/).filter((line) => line.length > 0);

  if (hexLines.length > 1) {
    return hexLines.map((line, index) => ({
      offset: "",
      bytes: line,
      ascii: asciiLines[index] ?? "",
    }));
  }

  const clean = rawHex.replace(/[^0-9a-fA-F]/g, "");
  const rows: HexRow[] = [];
  for (let offset = 0; offset < clean.length; offset += BYTES_PER_ROW * 2) {
    const chunk = clean.slice(offset, offset + BYTES_PER_ROW * 2);
    const pairs = chunk.match(/..?/g) ?? [];
    const byteOffset = offset / 2;
    const asciiSlice =
      asciiLines.length > 1
        ? asciiLines[offset / (BYTES_PER_ROW * 2)] ?? ""
        : rawAscii.slice(byteOffset, byteOffset + BYTES_PER_ROW);
    rows.push({
      offset: byteOffset.toString(16).padStart(8, "0"),
      bytes: pairs.join(" ").padEnd(BYTES_PER_ROW * 3 - 1, " "),
      ascii: asciiSlice.length > 0 ? asciiSlice : BLANK,
    });
  }
  return rows;
}
