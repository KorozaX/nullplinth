import type { Mode } from "../lib/mode";
import type { EventDetail } from "../types/contracts";
import { formatEndpoint, formatJson, formatTimestamp, formatValue } from "../lib/format";
import { SeverityBadge } from "./ui/Badge";
import { ErrorState, LoadingState } from "./ui/Feedback";

function severityMeaning(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "this was flagged as an immediate risk and should be reviewed first";
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
    { key: "Source", value: formatEndpoint(event.srcIp, event.srcPort) },
    { key: "Destination", value: formatEndpoint(event.dstIp, event.dstPort) },
    { key: "Category", value: formatValue(event.category) },
    { key: "Event type", value: formatValue(event.eventType) },
    { key: "Action", value: formatValue(event.action) },
    { key: "User", value: formatValue(event.username) },
    { key: "Host", value: formatValue(event.hostname) },
    { key: "Process", value: formatValue(event.processName) },
    { key: "Transport", value: formatValue(event.transport) },
    { key: "Application protocol", value: formatValue(event.appProto) },
    { key: "Source format", value: formatValue(event.sourceType) },
    { key: "Dataset", value: formatValue(detail.datasetName) },
    { key: "Event ID", value: String(event.id) },
  ];
  const visibleRows = mode === "beginner" ? rows.filter((row) => row.key !== "Event ID" && row.key !== "Transport") : rows;

  return (
    <div className="detail-grid">
      <div className="detail-section">
        <div className="row">
          <SeverityBadge severity={event.severity} />
          <span className="badge badge--neutral mono">{event.sourceType}</span>
        </div>
        <p className="why-matters">{formatValue(event.message)}</p>
      </div>

      <div className="detail-section">
        <h3 className="subhead">Normalized fields</h3>
        <dl className="kv">
          {visibleRows.map((row) => (
            <div key={row.key} style={{ display: "contents" }}>
              <dt className="kv__key">{row.key}</dt>
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
            <p>
              Log data is stored exactly as it was imported and is only displayed as text. Nothing here is executed.
            </p>
          </div>
        </details>
      ) : (
        <>
          <div className="detail-section">
            <h3 className="subhead">Unmapped attributes</h3>
            <pre className="codeblock">{formatJson(detail.attrs)}</pre>
          </div>
          <div className="detail-section">
            <h3 className="subhead">Original record</h3>
            <pre className="codeblock">{formatJson(detail.raw)}</pre>
          </div>
        </>
      )}
    </div>
  );
}
