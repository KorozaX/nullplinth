import { buildHexRows } from "../lib/hex";

export function HexView({ hex, ascii }: { hex: string; ascii: string }) {
  const rows = buildHexRows(hex, ascii);
  if (rows.length === 0) return <p className="muted">No packet bytes available.</p>;
  return (
    <div className="hex">
      <div className="hex__col">
        {rows.map((row, index) => (
          <div className="hex__line" key={index}>
            {row.offset ? <span className="hex__offset">{row.offset}</span> : <span />}
            <span className="hex__bytes">{row.bytes}</span>
          </div>
        ))}
      </div>
      <pre className="hex__ascii">{rows.map((row) => row.ascii).join("\n")}</pre>
    </div>
  );
}
