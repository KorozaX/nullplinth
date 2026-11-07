import { useMemo, useState } from "react";
import {
  Activity,
  Database,
  FileJson,
  FileSpreadsheet,
  FileText,
  Network,
  ShieldAlert,
  Terminal,
  Trash2,
  Upload,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

import { api } from "../services/api";
import type { Capture, Dataset } from "../types/contracts";
import { useMode } from "../context/ModeContext";
import { useWorkspace } from "../context/WorkspaceContext";
import { useImport } from "../components/ImportWorkflow";
import { errorMessage, useLoad } from "../lib/async";
import { fileName, formatBytes, formatNumber, formatTimestamp, shortHash } from "../lib/format";
import { Button, IconButton } from "../components/ui/Button";
import { EmptyState, ErrorState, LoadingState, Notice } from "../components/ui/Feedback";
import { Panel } from "../components/ui/Panel";
import { ConfirmDialog } from "../components/ui/ConfirmDialog";
import { StatusBadge } from "../components/ui/Badge";
import { DataTable } from "../components/ui/Table";
import type { Column } from "../components/ui/Table";
import { MetricPanel, MetricsStrip } from "../components/MetricPanel";
import "../styles/screen-data-sources.css";

type PendingDelete =
  | { kind: "dataset"; id: number; name: string }
  | { kind: "capture"; id: number; name: string }
  | null;

const SOURCE_TYPE_ICONS: Record<string, LucideIcon> = {
  json: FileJson,
  ndjson: FileJson,
  suricata: ShieldAlert,
  zeek: Terminal,
  csv: FileSpreadsheet,
  linux_auth: ShieldAlert,
  syslog: FileText,
  web_access: Network,
  firewall: ShieldAlert,
  generic_text: FileText,
};

function SourceType({ sourceType }: { sourceType: string }) {
  const Icon = SOURCE_TYPE_ICONS[sourceType] ?? FileText;
  return (
    <span className="chip chip--other sources-type">
      <Icon size={11} aria-hidden="true" />
      {sourceType}
    </span>
  );
}

export function DataSourcesScreen() {
  const { mode, isAnalyst } = useMode();
  const { version, refresh } = useWorkspace();
  const { beginImport } = useImport();
  const datasets = useLoad(() => api.listDatasets(), [version]);
  const captures = useLoad(() => api.listCaptures(), [version]);

  const [pending, setPending] = useState<PendingDelete>(null);
  const [deleting, setDeleting] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  async function confirmDelete() {
    if (!pending) return;
    setDeleting(true);
    setActionError(null);
    setNotice(null);
    try {
      if (pending.kind === "dataset") {
        await api.deleteDataset(pending.id);
        setNotice("Deleted dataset " + pending.name + ".");
      } else {
        await api.deleteCapture(pending.id);
        setNotice("Deleted capture " + pending.name + ".");
      }
      setPending(null);
      refresh();
    } catch (cause) {
      setActionError(errorMessage(cause));
    } finally {
      setDeleting(false);
    }
  }

  const datasetList = datasets.data ?? [];
  const captureList = captures.data ?? [];

  const stats = useMemo(() => {
    let events = 0;
    let skipped = 0;
    let importedBytes = 0;
    for (const dataset of datasetList) {
      events += dataset.recordCount;
      skipped += dataset.skippedCount;
      importedBytes += dataset.fileSize ?? 0;
    }
    let packets = 0;
    for (const capture of captureList) {
      packets += capture.packetCount;
      importedBytes += capture.fileSize ?? 0;
    }
    return { events, skipped, packets, importedBytes };
  }, [datasetList, captureList]);

  const recentImports = useMemo(
    () => datasetList.slice(0, 4),
    [datasetList],
  );

  const datasetColumns: ReadonlyArray<Column<Dataset>> = [
    {
      key: "name",
      header: "Dataset",
      render: (dataset: Dataset) => (
        <span className="alerts-cell">
          <span className="alerts-cell__title">{dataset.name}</span>
          <span className="alerts-cell__rule mono">{fileName(dataset.fileName)}</span>
        </span>
      ),
    },
    {
      key: "sourceType",
      header: "Type",
      render: (dataset: Dataset) => <SourceType sourceType={dataset.sourceType} />,
    },
    {
      key: "status",
      header: "Status",
      render: (dataset: Dataset) => <StatusBadge status={dataset.status} />,
    },
    {
      key: "recordCount",
      header: "Records",
      mono: true,
      align: "right",
      render: (dataset: Dataset) => formatNumber(dataset.recordCount),
    },
    {
      key: "skippedCount",
      header: "Skipped",
      mono: true,
      align: "right",
      render: (dataset: Dataset) =>
        dataset.skippedCount > 0 ? (
          <span className="sources-skipped">{formatNumber(dataset.skippedCount)}</span>
        ) : (
          <span className="dim">0</span>
        ),
    },
    {
      key: "warnings",
      header: "Warnings",
      align: "right",
      render: (dataset: Dataset) =>
        dataset.warnings.length === 0 ? (
          <span className="dim">0</span>
        ) : (
          <span title={dataset.warnings.join("\n")}>
            <span className="chip chip--medium">{formatNumber(dataset.warnings.length)}</span>
          </span>
        ),
    },
    {
      key: "fileSize",
      header: "Size",
      mono: true,
      align: "right",
      render: (dataset: Dataset) => formatBytes(dataset.fileSize),
    },
    {
      key: "importedAt",
      header: "Last import",
      mono: true,
      render: (dataset: Dataset) => formatTimestamp(dataset.importedAt, mode),
    },
    ...(isAnalyst
      ? ([
          {
            key: "fileHash",
            header: "Hash",
            mono: true,
            render: (dataset: Dataset) => shortHash(dataset.fileHash),
          },
        ] as const)
      : []),
    {
      key: "actions",
      header: "",
      align: "right",
      render: (dataset: Dataset) => (
        <IconButton
          icon={Trash2}
          label={"Delete dataset " + dataset.name}
          className="btn--sm"
          onClick={() => setPending({ kind: "dataset", id: dataset.id, name: dataset.name })}
        />
      ),
    },
  ];

  const captureColumns: ReadonlyArray<Column<Capture>> = [
    {
      key: "name",
      header: "Capture",
      render: (capture: Capture) => (
        <span className="alerts-cell">
          <span className="alerts-cell__title">{capture.name}</span>
          <span className="alerts-cell__rule mono">{fileName(capture.fileName)}</span>
        </span>
      ),
    },
    {
      key: "linkType",
      header: "Link type",
      render: (capture: Capture) => <span className="chip chip--eth">{capture.linkType ?? "unknown"}</span>,
    },
    {
      key: "packetCount",
      header: "Packets",
      mono: true,
      align: "right",
      render: (capture: Capture) => formatNumber(capture.packetCount),
    },
    {
      key: "fileSize",
      header: "Size",
      mono: true,
      align: "right",
      render: (capture: Capture) => formatBytes(capture.fileSize),
    },
    {
      key: "importedAt",
      header: "Last import",
      mono: true,
      render: (capture: Capture) => formatTimestamp(capture.importedAt, mode),
    },
    {
      key: "actions",
      header: "",
      align: "right",
      render: (capture: Capture) => (
        <IconButton
          icon={Trash2}
          label={"Delete capture " + capture.name}
          className="btn--sm"
          onClick={() => setPending({ kind: "capture", id: capture.id, name: capture.name })}
        />
      ),
    },
  ];

  const importButtons = (
    <>
      <Button icon={Upload} variant="primary" onClick={() => void beginImport()}>
        Import data
      </Button>
      <Button icon={FileSpreadsheet} variant="secondary" onClick={() => void beginImport()}>
        Import CSV
      </Button>
    </>
  );

  return (
    <div className="page sources-page">
      <div className="page__head">
        <div className="page__titles">
          <h2 className="page__title">Data sources</h2>
          <p className="page__lede">
            Every imported file is hashed on import and stored in a local SQLite database. Drag files anywhere onto the
            window, or use one button for every supported format. Source files are never modified.
          </p>
        </div>
        <div className="page__actions">{importButtons}</div>
      </div>

      {notice ? <Notice tone="ok">{notice}</Notice> : null}
      {actionError ? <Notice tone="error">{actionError}</Notice> : null}

      <MetricsStrip>
        <MetricPanel
          label="Datasets"
          value={formatNumber(datasetList.length)}
          hint={formatNumber(stats.events) + " log records"}
          tone="accent"
        />
        <MetricPanel label="Captures" value={formatNumber(captureList.length)} hint={formatNumber(stats.packets) + " packets"} />
        <MetricPanel label="Skipped records" value={formatNumber(stats.skipped)} hint="malformed rows kept out of the timeline" />
        <MetricPanel label="Imported bytes" value={formatBytes(stats.importedBytes)} hint="source file size, hashed locally" />
      </MetricsStrip>

      <div className="sources-drop">
        <span className="sources-drop__icon" aria-hidden="true">
          <Upload size={22} />
        </span>
        <div className="sources-drop__body">
          <p className="sources-drop__title">Drop log or capture files here</p>
          <p className="sources-drop__hint">
            Drop one or several files anywhere on the window. Logs are parsed, normalized and stored as events; captures
            are decoded into packets and conversations. A file that was already imported is rejected by its SHA-256 hash
            instead of being duplicated.
          </p>
          <div className="sources-drop__types">
            {["JSON", "NDJSON", "Suricata EVE", "Zeek TSV", "CSV", "TSV", "PCAP", "PCAPNG"].map((type) => (
              <span className="chip chip--other" key={type}>
                {type}
              </span>
            ))}
          </div>
        </div>
        <div className="sources-drop__actions">
          <Button icon={Upload} variant="primary" onClick={() => void beginImport()}>
            Choose files
          </Button>
        </div>
      </div>

      <Panel title="Import status" meta={formatNumber(recentImports.length) + " recent"}>
        {datasets.loading && !datasets.data ? (
          <LoadingState label="Reading import history" />
        ) : datasets.error ? (
          <ErrorState message={datasets.error} onRetry={datasets.reload} />
        ) : recentImports.length === 0 ? (
          <p className="muted">No imports yet. Recent imports, their status and skipped-record counts appear here.</p>
        ) : (
          <div className="sources-status">
            {recentImports.map((dataset) => (
              <div className="sources-status__row" key={dataset.id}>
                <StatusBadge status={dataset.status} />
                <span className="sources-status__name" title={dataset.name}>
                  {dataset.fileName ? fileName(dataset.fileName) : dataset.sourceType}
                </span>
                <span className="sources-status__facts">
                  <span className="mono">{formatNumber(dataset.recordCount) + " records"}</span>
                  <span className="sources-status__sep" aria-hidden="true">{"\u00B7"}</span>
                  <span>
                    {dataset.skippedCount > 0 ? formatNumber(dataset.skippedCount) + " skipped" : "no skipped records"}
                  </span>
                  <span className="sources-status__sep" aria-hidden="true">{"\u00B7"}</span>
                  <span>
                    {dataset.warnings.length > 0
                      ? formatNumber(dataset.warnings.length) + (dataset.warnings.length === 1 ? " warning" : " warnings")
                      : "no warnings"}
                  </span>
                  <span className="sources-status__sep" aria-hidden="true">{"\u00B7"}</span>
                  <span className="sources-status__when">{formatTimestamp(dataset.importedAt, mode)}</span>
                </span>
              </div>
            ))}
          </div>
        )}
      </Panel>

      <Panel title="Supported formats">
        <div className="sources-formats">
          <div className="sources-format">
            <span className="sources-format__head">
              <FileJson size={14} aria-hidden="true" /> Structured logs
            </span>
            <ul className="sources-format__list">
              <li><span className="mono">JSON array</span> one document with an array of records</li>
              <li><span className="mono">NDJSON</span> one JSON object per line</li>
              <li><span className="mono">Suricata EVE</span> alerts, dns, http, tls, flow, anomaly</li>
            </ul>
          </div>
          <div className="sources-format">
            <span className="sources-format__head">
              <Activity size={14} aria-hidden="true" /> Network and text logs
            </span>
            <ul className="sources-format__list">
              <li><span className="mono">Zeek TSV</span> conn, dns, http, ssl, ssh</li>
              <li><span className="mono">Firewall</span> key=value lines with allow / deny / failed</li>
              <li><span className="mono">Syslog</span> RFC3164 and RFC5424, Linux auth, Apache and Nginx access logs</li>
              <li><span className="mono">Generic text</span> one event per line, timestamps only when present</li>
            </ul>
          </div>
          <div className="sources-format">
            <span className="sources-format__head">
              <Database size={14} aria-hidden="true" /> CSV and captures
            </span>
            <ul className="sources-format__list">
              <li><span className="mono">CSV / TSV</span> preview, delimiter detection and explicit column mapping</li>
              <li><span className="mono">PCAP / PCAPNG</span> packet decoding, protocol layers and conversations</li>
              <li>Import status is written per file; one malformed row never aborts a log import.</li>
            </ul>
          </div>
        </div>
      </Panel>

      <Panel title="Datasets" meta={formatNumber(datasetList.length)} flush>
        {datasets.loading && !datasets.data ? (
          <LoadingState label="Loading datasets" />
        ) : datasets.error ? (
          <ErrorState message={datasets.error} onRetry={datasets.reload} />
        ) : datasetList.length === 0 ? (
          <EmptyState
            icon={Database}
            title="No datasets imported"
            description="Import a JSON, NDJSON, Suricata EVE, Zeek TSV, syslog, firewall, web access or CSV log file to create a dataset."
            action={
              <Button icon={Upload} variant="primary" onClick={() => void beginImport()}>
                Import data
              </Button>
            }
          />
        ) : (
          <DataTable
            label="Datasets"
            columns={datasetColumns}
            rows={datasetList}
            rowKey={(dataset: Dataset) => dataset.id}
            dense
          />
        )}
      </Panel>

      <Panel title="Packet captures" meta={formatNumber(captureList.length)} flush>
        {captures.loading && !captures.data ? (
          <LoadingState label="Loading captures" />
        ) : captures.error ? (
          <ErrorState message={captures.error} onRetry={captures.reload} />
        ) : captureList.length === 0 ? (
          <EmptyState
            icon={FileText}
            title="No captures imported"
            description="Import a .pcap or .pcapng file to decode packets and group conversations."
            action={
              <Button icon={Upload} variant="primary" onClick={() => void beginImport()}>
                Import data
              </Button>
            }
          />
        ) : (
          <DataTable
            label="Packet captures"
            columns={captureColumns}
            rows={captureList}
            rowKey={(capture: Capture) => capture.id}
            dense
          />
        )}
      </Panel>

      <ConfirmDialog
        open={pending !== null}
        title={pending && pending.kind === "dataset" ? "Delete dataset" : "Delete capture"}
        message={
          pending
            ? "Delete " + pending.name + "? The stored records are removed from this machine. This cannot be undone."
            : ""
        }
        confirmLabel="Delete"
        busy={deleting}
        onCancel={() => setPending(null)}
        onConfirm={() => void confirmDelete()}
      />
    </div>
  );
}
