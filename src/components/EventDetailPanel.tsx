import type { Mode } from "../lib/mode";
import type { EventDetail } from "../types/contracts";
import {
  formatEndpoint,
  formatFieldLabel,
  formatJson,
  formatTimestamp,
  formatValue,
} from "../lib/format";
import { protocolKind, protocolLabel, protocolColor } from "../lib/semantic";
import { ProtocolChip, SeverityBadge } from "./ui/Badge";
import { ErrorState, LoadingState } from "./ui/Feedback";

function severityMeaning(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "this was rated an immediate risk and should be reviewed first";
    case "high":
      return "this looks like a serious event that deserves attention";
    case "medium":
      return "this is unusual but might be normal activity";
    case "low":
      return "this is low risk and probably routine";
    default:
      return "this carries no known risk and is recorded for completeness";
  }
}

export function EventDetailPanel({
  detail,
  loading,
  error,
  mode,
}: {
  detail: EventDetail | null;
  loading: boolean;
  error: string | null;
  mode: Mode;
}) {
  if (loading) return <LoadingState label="Loading event" />;
  if (error) return <ErrorState title="Could not load event" message={error} />;
  if (!detail) return null;

  const event = detail.event;
  const rows: Array<{ key: string; value: string }> = [
    { key: "Timestamp", value: formatTimestamp(event.ts, mode) },
    { key: "Severity", value: event.severity },
    { key: "Source format", value: formatValue(event.sourceType) },
    { key: "Category", value: formatValue(event.category) },
    { key: "Event type", value: formatValue(event.eventType) },
    { key: "Action", value: formatValue(event.action) },
    { key: "Source IP", value: formatEndpoint(event.srcIp, event.srcPort) },
    { key: "Destination IP", value: formatEndpoint(event.dstIp, event.dstPort) },
    { key: "Transport", value: formatValue(event.transport) },
    { key: "App protocol", value: formatValue(event.appProto) },
    { key: "User", value: formatValue(event.username) },
    { key: "Host", value: formatValue(event.hostname) },
    { key: "Process", value: formatValue(event.processName) },
    { key: "Dataset", value: formatValue(detail.datasetName) },
    { key: "Event ID", value: String(event.id) },
  ];
  const visibleRows =
    mode === "beginner"
      ? rows.filter((row) => row.key !== "Event ID" && row.key !== "Transport" && row.key !== "Process")
      : rows;

  const related = [
    event.srcIp ? { label: "source", value: formatEndpoint(event.srcIp, event.srcPort) } : null,
    event.dstIp ? { label: "destination", value: formatEndpoint(event.dstIp, event.dstPort) } : null,
    event.transport ? { label: "transport", value: formatValue(event.transport) } : null,
    event.hostname ? { label: "host", value: formatValue(event.hostname) } : null,
    event.username ? { label: "user", value: formatValue(event.username) } : null,
  ].filter((entry): entry is { label: string; value: string } => entry !== null);

  return (
    <div className="detail-grid">
      <div className="detail-head">
        <SeverityBadge severity={event.severity} />
        {event.appProto ? <ProtocolChip protocol={event.appProto} /> : null}
        <span className="chip chip--other">{formatValue(event.sourceType)}</span>
        {event.transport ? <span className="chip chip--other">{protocolLabel(event.transport)}</span> : null}
      </div>

      <div className="inspector-summary">{formatValue(event.message)}</div>

      {related.length > 0 ? (
        <div className="inspector-section">
          <h3 className="subhead">Related values</h3>
          <div className="related-list">
            {related.map((entry) => (
              <span className="chip chip--other" key={entry.label + entry.value}>
                <span
                  className="chip__dot"
                  style={{
                    background:
                      entry.label === "transport" || entry.label === "destination"
                        ? protocolColor(protocolKind(event.appProto))
                        : "var(--fg-dim)",
                  }}
                  aria-hidden="true"
                />
                {entry.label}: {entry.value}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      <div className="inspector-section">
        <h3 className="subhead">Normalized fields</h3>
        <dl className="kv">
          {visibleRows.map((row) => (
            <div key={row.key} style={{ display: "contents" }}>
              <dt className="kv__key">{formatFieldLabel(row.key)}</dt>
              <dd className="kv__val">{row.value}</dd>
            </div>
          ))}
        </dl>
      </div>

      {mode === "beginner" ? (
        <details className="disclosure">
          <summary>Why this matters</summary>
          <div className="disclosure__body">
            <p>
              This record came from a {formatValue(event.sourceType)} file. The importer rated it{" "}
              {formatValue(event.severity)}, which means {severityMeaning(event.severity)}.
            </p>
            <p>Imported data is stored exactly as received and only ever displayed as text. Nothing here is executed.</p>
          </div>
        </details>
      ) : (
        <>
          <div className="inspector-section">
            <h3 className="subhead">Unmapped attributes</h3>
            <pre className="codeblock">{formatJson(detail.attrs)}</pre>
          </div>
          <div className="inspector-section">
            <h3 className="subhead">Original record</h3>
            <pre className="codeblock">{formatJson(detail.raw)}</pre>
          </div>
        </>
      )}
    </div>
  );
}
