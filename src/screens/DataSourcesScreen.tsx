import { useState } from "react";
import { Database, FileSpreadsheet, FileText, Trash2, Upload } from "lucide-react";

import { api } from "../services/api";
import type { Capture, Dataset } from "../types/contracts";
import { useMode } from "../context/ModeContext";
import { errorMessage, useLoad } from "../lib/async";
import { pickFile } from "../lib/dialog";
import { fileName, formatBytes, formatNumber, formatTimestamp, shortHash } from "../lib/format";
import { Button, IconButton } from "../components/ui/Button";
import { EmptyState, ErrorState, LoadingState, Notice } from "../components/ui/Feedback";
import { Panel } from "../components/ui/Panel";
import { Badge } from "../components/ui/Badge";
import { ConfirmDialog } from "../components/ui/ConfirmDialog";
import { DataTable } from "../components/ui/Table";
import type { Column } from "../components/ui/Table";
import { CsvWizard } from "../components/CsvWizard";

type PendingDelete =
  | { kind: "dataset"; id: number; name: string }
  | { kind: "capture"; id: number; name: string }
  | null;

export function DataSourcesScreen() {
  const { mode, isAnalyst } = useMode();
  const datasets = useLoad(() => api.listDatasets(), []);
  const captures = useLoad(() => api.listCaptures(), []);

  const [busy, setBusy] = useState<"log" | "pcap" | null>(null);
  const [pending, setPending] = useState<PendingDelete>(null);
  const [deleting, setDeleting] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [wizardOpen, setWizardOpen] = useState(false);

  async function importLog() {
    const path = await pickFile("Import log file", [
      { name: "Log files", extensions: ["json", "jsonl", "ndjson", "log", "tsv", "csv"] },
    ]);
    if (!path) return;
    setBusy("log");
    setNotice(null);
    setActionError(null);
    try {
      const result = await api.importFile({ path });
      setNotice(
        "Imported " + formatNumber(result.imported) + " events, skipped " + formatNumber(result.skipped) + ".",
      );
      datasets.reload();
    } catch (cause) {
      setActionError(errorMessage(cause));
    } finally {
      setBusy(null);
    }
  }

  async function importPcap() {
    const path = await pickFile("Import packet capture", [
      { name: "Packet captures", extensions: ["pcap", "pcapng", "cap"] },
    ]);
    if (!path) return;
    setBusy("pcap");
    setNotice(null);
    setActionError(null);
    try {
      const capture = await api.importPcap(path);
      setNotice("Imported " + formatNumber(capture.packetCount) + " packets from " + capture.name + ".");
      captures.reload();
    } catch (cause) {
      setActionError(errorMessage(cause));
    } finally {
      setBusy(null);
    }
  }

  async function confirmDelete() {
    if (!pending) return;
    setDeleting(true);
    setActionError(null);
    setNotice(null);
    try {
      if (pending.kind === "dataset") {
        await api.deleteDataset(pending.id);
        setNotice("Deleted dataset " + pending.name + ".");
        datasets.reload();
      } else {
        await api.deleteCapture(pending.id);
        setNotice("Deleted capture " + pending.name + ".");
        captures.reload();
      }
      setPending(null);
    } catch (cause) {
      setActionError(errorMessage(cause));
    } finally {
      setDeleting(false);
    }
  }

  const datasetColumns: ReadonlyArray<Column<Dataset>> = [
    { key: "name", header: "Dataset", render: (dataset: Dataset) => dataset.name },
    { key: "sourceType", header: "Type", render: (dataset: Dataset) => <Badge>{dataset.sourceType.toUpperCase()}</Badge> },
    {
      key: "file",
      header: "File",
      render: (dataset: Dataset) => (
        <span className="mono" title={dataset.fileName ?? undefined}>
          {fileName(dataset.fileName)} {isAnalyst ? formatBytes(dataset.fileSize) : ""}
        </span>
      ),
    },
    {
      key: "importedAt",
      header: "Imported",
      mono: true,
      render: (dataset: Dataset) => formatTimestamp(dataset.importedAt, mode),
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
      render: (dataset: Dataset) => formatNumber(dataset.skippedCount),
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
            <Badge tone="critical">{formatNumber(dataset.warnings.length)}</Badge>
          </span>
        ),
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
    { key: "linkType", header: "Link type", render: (capture: Capture) => capture.linkType ?? "\u2014" },
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
          Every imported file is hashed on import and stored in a local SQLite database. Source files are never modified.
        </p>
        <div className="toolbar">
          <Button icon={Upload} variant="primary" onClick={importLog} disabled={busy !== null}>
            {busy === "log" ? "Importing" : "Import log file"}
          </Button>
          <Button icon={FileSpreadsheet} onClick={() => setWizardOpen(true)} disabled={busy !== null}>
            CSV wizard
          </Button>
          <Button icon={Upload} onClick={importPcap} disabled={busy !== null}>
            {busy === "pcap" ? "Importing" : "Import PCAP"}
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
              <Button icon={Upload} variant="primary" onClick={importLog} disabled={busy !== null}>
                Import log file
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
              <Button icon={Upload} variant="primary" onClick={importPcap} disabled={busy !== null}>
                Import PCAP
              </Button>
            }
          />
        ) : (
          <DataTable label="Packet captures" columns={captureColumns} rows={captureList} rowKey={(capture: Capture) => capture.id} dense />
        )}
      </Panel>

      <CsvWizard
        open={wizardOpen}
        onClose={() => setWizardOpen(false)}
        onImported={(result) => {
          setWizardOpen(false);
          setNotice("Imported " + formatNumber(result.imported) + " events from a CSV file.");
          datasets.reload();
        }}
      />

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
