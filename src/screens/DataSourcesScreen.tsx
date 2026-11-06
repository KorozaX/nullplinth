import { useState } from "react";
import { Database, FileSpreadsheet, FileText, Trash2, Upload } from "lucide-react";

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
import { DataTable } from "../components/ui/Table";
import type { Column } from "../components/ui/Table";

type PendingDelete =
  | { kind: "dataset"; id: number; name: string }
  | { kind: "capture"; id: number; name: string }
  | null;

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

  const datasetColumns: ReadonlyArray<Column<Dataset>> = [
    { key: "name", header: "Dataset", render: (dataset: Dataset) => dataset.name },
    {
      key: "sourceType",
      header: "Type",
      render: (dataset: Dataset) => <span className="chip chip--other">{dataset.sourceType}</span>,
    },
    {
      key: "file",
      header: "File",
      render: (dataset: Dataset) => (
        <span className="mono" title={dataset.fileName ?? undefined}>
          {fileName(dataset.fileName)}
        </span>
      ),
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
          <span style={{ color: "var(--sev-medium)" }}>{formatNumber(dataset.skippedCount)}</span>
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
      header: "Imported",
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
    { key: "name", header: "Capture", render: (capture: Capture) => capture.name },
    { key: "file", header: "File", mono: true, render: (capture: Capture) => fileName(capture.fileName) },
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
      header: "Imported",
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

  const datasetList = datasets.data ?? [];
  const captureList = captures.data ?? [];

  return (
    <div className="page">
      <div className="page__bar">
        <p className="page__lede">
          Every imported file is hashed on import and stored in a local SQLite database. Drag files anywhere onto the
          window, or use one button for every supported format. Source files are never modified.
        </p>
        <div className="toolbar">
          <Button icon={Upload} variant="primary" onClick={() => void beginImport()}>
            Import data
          </Button>
          <Button icon={FileSpreadsheet} onClick={() => void beginImport()}>
            Import CSV
          </Button>
        </div>
      </div>

      {notice ? <Notice tone="ok">{notice}</Notice> : null}
      {actionError ? <Notice tone="error">{actionError}</Notice> : null}

      <Panel title="Datasets" meta={formatNumber(datasetList.length)} flush>
        {datasets.loading && !datasets.data ? (
          <LoadingState label="Loading datasets" />
        ) : datasets.error ? (
          <ErrorState message={datasets.error} onRetry={datasets.reload} />
        ) : datasetList.length === 0 ? (
          <EmptyState
            icon={Database}
            title="No datasets imported"
            description="Import a JSON, NDJSON, Suricata EVE, Zeek TSV or CSV log file to create a dataset."
            action={
              <Button icon={Upload} variant="primary" onClick={() => void beginImport()}>
                Import data
              </Button>
            }
          />
        ) : (
          <DataTable label="Datasets" columns={datasetColumns} rows={datasetList} rowKey={(dataset: Dataset) => dataset.id} dense />
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
          <DataTable label="Packet captures" columns={captureColumns} rows={captureList} rowKey={(capture: Capture) => capture.id} dense />
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
