import { useState } from "react";
import { Download, FileSpreadsheet, Inbox, Play, RefreshCw, ShieldAlert } from "lucide-react";

import { api } from "../services/api";
import type { Alert, Count, Overview } from "../types/contracts";
import { useMode } from "../context/ModeContext";
import { errorMessage, useLoad } from "../lib/async";
import { pickFile } from "../lib/dialog";
import { formatBytes, formatDuration, formatNumber, formatTimestamp } from "../lib/format";
import { Button } from "../components/ui/Button";
import { EmptyState, ErrorState, LoadingState, Notice } from "../components/ui/Feedback";
import { Panel } from "../components/ui/Panel";
import { SeverityBadge } from "../components/ui/Badge";
import { DataTable } from "../components/ui/Table";
import type { Column } from "../components/ui/Table";
import { MetricCard } from "../components/MetricCard";
import { VolumeChart } from "../components/VolumeChart";
import { CsvWizard } from "../components/CsvWizard";
import type { SectionId } from "../shell/sections";

function CountList({ counts }: { counts: readonly Count[] }) {
  if (counts.length === 0) return <p className="muted">No data for this range.</p>;
  const peak = counts.reduce((max, item) => Math.max(max, item.count), 1);
  return (
    <ul className="count-list">
      {counts.slice(0, 6).map((item) => (
        <li className="count-list__item" key={item.key}>
          <span className="count-list__label mono">{item.key.length > 0 ? item.key : "(empty)"}</span>
          <span className="count-list__bar" aria-hidden="true">
            <span
              className="count-list__fill"
              style={{ width: String(Math.max(2, (item.count / peak) * 100)) + "%" }}
            />
          </span>
          <span className="count-list__value mono">{formatNumber(item.count)}</span>
        </li>
      ))}
    </ul>
  );
}

function alertBreakdown(data: Overview): string {
  if (data.alertsBySeverity.length === 0) return "No alerts";
  return data.alertsBySeverity.map((item) => formatNumber(item.count) + " " + item.key).join(" / ");
}

export function OverviewScreen({ onNavigate }: { onNavigate: (section: SectionId) => void }) {
  const { mode, isAnalyst } = useMode();
  const overview = useLoad(() => api.getOverview(), []);
  const [busy, setBusy] = useState<"import" | "demo" | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [wizardOpen, setWizardOpen] = useState(false);

  async function handleImport() {
    const path = await pickFile("Import log file", [
      { name: "Log files", extensions: ["json", "jsonl", "ndjson", "log", "tsv", "csv"] },
    ]);
    if (!path) return;
    setBusy("import");
    setActionError(null);
    setNotice(null);
    try {
      const result = await api.importFile({ path });
      const skipped = result.skipped > 0 ? " Skipped " + formatNumber(result.skipped) + " malformed records." : "";
      setNotice(
        "Imported " + formatNumber(result.imported) + " events in " + formatDuration(result.durationMs) + "." + skipped,
      );
      overview.reload();
    } catch (cause) {
      setActionError(errorMessage(cause));
    } finally {
      setBusy(null);
    }
  }

  async function handleDemo() {
    setBusy("demo");
    setActionError(null);
    setNotice(null);
    try {
      const imported = await api.loadDemoData();
      setNotice("Loaded the synthetic demo dataset with " + formatNumber(imported) + " events.");
      overview.reload();
    } catch (cause) {
      setActionError(errorMessage(cause));
    } finally {
      setBusy(null);
    }
  }

  const actions = (
    <div className="toolbar">
      <Button icon={Download} variant="primary" onClick={handleImport} disabled={busy !== null}>
        {busy === "import" ? "Importing" : "Import data"}
      </Button>
      <Button icon={FileSpreadsheet} onClick={() => setWizardOpen(true)} disabled={busy !== null}>
        CSV wizard
      </Button>
      <Button icon={Play} onClick={handleDemo} disabled={busy !== null}>
        {busy === "demo" ? "Loading demo" : "Load demo dataset"}
      </Button>
      <Button icon={RefreshCw} variant="ghost" onClick={overview.reload} aria-label="Refresh overview" />
    </div>
  );

  if (overview.loading && !overview.data) return <LoadingState label="Loading overview" />;
  if (overview.error) return <ErrorState message={overview.error} onRetry={overview.reload} />;
  const data = overview.data;
  if (!data) return <LoadingState label="Loading overview" />;

  const hasData = data.totalEvents > 0 || data.datasetCount > 0 || data.captureCount > 0 || data.alertTotal > 0;
  const alertColumns: ReadonlyArray<Column<Alert>> = isAnalyst
    ? [
        { key: "severity", header: "Severity", render: (alert: Alert) => <SeverityBadge severity={alert.severity} /> },
        { key: "title", header: "Alert", render: (alert: Alert) => alert.title },
        { key: "rule", header: "Rule", mono: true, render: (alert: Alert) => alert.rule },
        { key: "status", header: "Status", render: (alert: Alert) => alert.status },
        { key: "createdAt", header: "Created", mono: true, render: (alert: Alert) => formatTimestamp(alert.createdAt, mode) },
      ]
    : [
        { key: "severity", header: "Severity", render: (alert: Alert) => <SeverityBadge severity={alert.severity} /> },
        { key: "title", header: "Alert", render: (alert: Alert) => alert.title },
        { key: "status", header: "Status", render: (alert: Alert) => alert.status },
      ];

  return (
    <div className="page">
      <div className="page__bar">
        <p className="page__lede">
          NULLPLINTH works entirely on this machine. Import logs or packet captures, search normalized events, and let
          the detection rules surface what deserves a second look.
        </p>
        {actions}
      </div>

      {notice ? <Notice tone="ok">{notice}</Notice> : null}
      {actionError ? <Notice tone="error">{actionError}</Notice> : null}

      <div className="metrics">
        <MetricCard label="Events" value={formatNumber(data.totalEvents)} hint={formatNumber(data.datasetCount) + " datasets"} />
        <MetricCard label="Datasets" value={formatNumber(data.datasetCount)} hint="Imported files" />
        <MetricCard label="Alerts" value={formatNumber(data.alertTotal)} signal hint={alertBreakdown(data)} />
        <MetricCard label="Packets" value={formatNumber(data.packetCount)} hint={formatNumber(data.captureCount) + " captures"} />
        <MetricCard label="Investigations" value={formatNumber(data.investigationCount)} hint="Case files" />
        <MetricCard label="Conversations" value={formatNumber(data.flowSummary.flowCount)} hint={formatBytes(data.flowSummary.totalBytes)} />
      </div>

      {hasData ? (
        <>
          <Panel title="Event volume" meta={isAnalyst ? formatNumber(data.volumeSeries.length) + " buckets" : undefined}>
            <VolumeChart series={data.volumeSeries} mode={mode} />
          </Panel>

          <div className="grid-2">
            <Panel title="Top source IPs">{<CountList counts={data.topSrcIps} />}</Panel>
            <Panel title="Top destination IPs">{<CountList counts={data.topDstIps} />}</Panel>
          </div>

          <div className="grid-2">
            <Panel
              title="Protocol distribution"
              meta={isAnalyst ? formatNumber(data.flowSummary.tcpFlows) + " TCP flows" : undefined}
            >
              <CountList counts={data.protocolDistribution} />
            </Panel>
            <Panel
              title="Recent alerts"
              actions={
                <Button size="sm" variant="ghost" onClick={() => onNavigate("alerts")}>
                  View all
                </Button>
              }
            >
              {data.recentAlerts.length === 0 ? (
                <EmptyState
                  compact
                  icon={ShieldAlert}
                  title="No alerts yet"
                  description="Run detection from the Alerts screen to evaluate the stored events against the built-in rules."
                />
              ) : (
                <DataTable
                  label="Recent alerts"
                  columns={alertColumns}
                  rows={data.recentAlerts}
                  rowKey={(alert: Alert) => alert.id}
                  onRowClick={() => onNavigate("alerts")}
                  dense
                />
              )}
            </Panel>
          </div>
        </>
      ) : (
        <Panel flush>
          <EmptyState
            icon={Inbox}
            title="No data imported yet"
            description="Import a Suricata, Zeek, JSON or CSV log file, or load the deterministic demo dataset to explore the workbench. The demo dataset is synthetic and stays on this machine."
            action={
              <div className="toolbar">
                <Button icon={Download} variant="primary" onClick={handleImport} disabled={busy !== null}>
                  Import data
                </Button>
                <Button icon={Play} onClick={handleDemo} disabled={busy !== null}>
                  Load demo dataset
                </Button>
              </div>
            }
          />
        </Panel>
      )}

      <p className="dim">
        All data stays on this machine. Nothing is uploaded, and imported content is only ever rendered as text.
      </p>

      <CsvWizard
        open={wizardOpen}
        onClose={() => setWizardOpen(false)}
        onImported={(result) => {
          setWizardOpen(false);
          setNotice("Imported " + formatNumber(result.imported) + " events from a CSV file.");
          overview.reload();
        }}
      />
    </div>
  );
}
