import { useState } from "react";
import { Download, FileSpreadsheet, Inbox, Play, RefreshCw } from "lucide-react";

import { api } from "../services/api";
import type { Alert, Dataset, EventQuery, EventRow } from "../types/contracts";
import { useMode } from "../context/ModeContext";
import { useWorkspace } from "../context/WorkspaceContext";
import { useImport } from "../components/ImportWorkflow";
import { useLoad } from "../lib/async";
import { formatBytes, formatEndpoint, formatNumber, formatTimestamp } from "../lib/format";
import { protocolColor, protocolLabel, severityColor, severityLabel } from "../lib/semantic";
import { Button } from "../components/ui/Button";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/Feedback";
import { Panel } from "../components/ui/Panel";
import { SeverityBadge, StatusChip } from "../components/ui/Badge";
import { DataTable } from "../components/ui/Table";
import type { Column } from "../components/ui/Table";
import { MetricCard } from "../components/MetricCard";
import { DistributionList, VolumeChart } from "../components/VolumeChart";
import type { SectionId } from "../shell/sections";

const RECENT_QUERY: EventQuery = {
  datasetIds: [],
  sourceTypes: [],
  fromTs: null,
  toTs: null,
  filters: [],
  text: null,
  sort: "ts",
  sortDir: "desc",
  page: 1,
  pageSize: 5,
};

export function OverviewScreen({ onNavigate }: { onNavigate: (section: SectionId) => void }) {
  const { mode, isAnalyst } = useMode();
  const { version, refresh } = useWorkspace();
  const { beginImport, importDemo } = useImport();
  const overview = useLoad(() => api.getOverview(), [version]);
  const datasets = useLoad(() => api.listDatasets(), [version]);
  const recentEvents = useLoad(() => api.searchEvents(RECENT_QUERY), [version]);
  const [busy, setBusy] = useState<"demo" | null>(null);

  async function handleDemo() {
    setBusy("demo");
    await importDemo();
    setBusy(null);
  }

  const actions = (
    <div className="toolbar">
      <Button icon={Download} variant="primary" onClick={() => void beginImport()} disabled={busy !== null}>
        Import data
      </Button>
      <Button icon={FileSpreadsheet} onClick={() => void beginImport()} disabled={busy !== null}>
        Import CSV
      </Button>
      <Button icon={Play} onClick={handleDemo} disabled={busy !== null}>
        {busy === "demo" ? "Loading demo" : "Load demo dataset"}
      </Button>
      <Button icon={RefreshCw} variant="ghost" onClick={refresh} aria-label="Refresh overview" />
    </div>
  );

  if (overview.loading && !overview.data) return <LoadingState label="Loading overview" />;
  if (overview.error) return <ErrorState message={overview.error} onRetry={overview.reload} />;
  const data = overview.data;
  if (!data) return <LoadingState label="Loading overview" />;

  const hasData = data.totalEvents > 0 || data.datasetCount > 0 || data.captureCount > 0 || data.alertTotal > 0;
  const severityItems = data.alertsBySeverity.slice().sort((a, b) => b.count - a.count);
  const datasetRows: readonly Dataset[] = datasets.data ?? [];

  const alertColumns: ReadonlyArray<Column<Alert>> = isAnalyst
    ? [
        { key: "severity", header: "Severity", width: "96px", render: (alert: Alert) => <SeverityBadge severity={alert.severity} /> },
        { key: "title", header: "Alert", render: (alert: Alert) => alert.title },
        { key: "rule", header: "Rule", mono: true, render: (alert: Alert) => alert.rule },
        { key: "status", header: "Status", render: (alert: Alert) => <StatusChip status={alert.status} /> },
        { key: "createdAt", header: "Created", mono: true, render: (alert: Alert) => formatTimestamp(alert.createdAt, mode) },
      ]
    : [
        { key: "severity", header: "Severity", width: "96px", render: (alert: Alert) => <SeverityBadge severity={alert.severity} /> },
        { key: "title", header: "Alert", render: (alert: Alert) => alert.title },
        { key: "status", header: "Status", render: (alert: Alert) => <StatusChip status={alert.status} /> },
        { key: "createdAt", header: "Created", mono: true, render: (alert: Alert) => formatTimestamp(alert.createdAt, mode) },
      ];

  const datasetColumns: ReadonlyArray<Column<Dataset>> = [
    { key: "name", header: "Dataset", render: (dataset: Dataset) => dataset.name },
    { key: "sourceType", header: "Type", render: (dataset: Dataset) => <span className="chip chip--other">{dataset.sourceType}</span> },
    {
      key: "recordCount",
      header: "Records",
      mono: true,
      align: "right",
      render: (dataset: Dataset) => formatNumber(dataset.recordCount),
    },
    {
      key: "importedAt",
      header: "Imported",
      mono: true,
      render: (dataset: Dataset) => formatTimestamp(dataset.importedAt, mode),
    },
  ];

  const activityColumns: ReadonlyArray<Column<EventRow>> = isAnalyst
    ? [
        {
          key: "ts",
          header: "Time",
          mono: true,
          width: "150px",
          render: (event: EventRow) => formatTimestamp(event.ts, mode),
        },
        { key: "severity", header: "Severity", width: "96px", render: (event: EventRow) => <SeverityBadge severity={event.severity} /> },
        {
          key: "srcIp",
          header: "Source",
          mono: true,
          render: (event: EventRow) => formatEndpoint(event.srcIp, event.srcPort),
        },
        { key: "message", header: "Event", render: (event: EventRow) => event.message ?? "\u2014" },
      ]
    : [
        {
          key: "ts",
          header: "Time",
          mono: true,
          width: "150px",
          render: (event: EventRow) => formatTimestamp(event.ts, mode),
        },
        { key: "severity", header: "Severity", width: "96px", render: (event: EventRow) => <SeverityBadge severity={event.severity} /> },
        { key: "message", header: "What happened", render: (event: EventRow) => event.message ?? "\u2014" },
      ];

  const recentRows = recentEvents.data ? recentEvents.data.events : [];

  return (
    <div className="page">
      <div className="page__bar">
        <p className="page__lede">
          Everything runs on this machine. Import logs, drop files anywhere in the window, or load the deterministic demo
          dataset to explore the workbench.
        </p>
        {actions}
      </div>

      <div className="metrics">
        <MetricCard label="Events" value={formatNumber(data.totalEvents)} tone="accent" hint={formatNumber(data.datasetCount) + " datasets"} />
        <MetricCard label="Datasets" value={formatNumber(data.datasetCount)} hint={formatNumber(data.captureCount) + " captures"} />
        <MetricCard
          label="Alerts"
          value={formatNumber(data.alertTotal)}
          tone={data.alertTotal > 0 ? "critical" : "default"}
          hint={
            severityItems.length > 0
              ? severityItems.map((item) => severityLabel(item.key) + ": " + formatNumber(item.count)).join("  ")
              : "No alerts"
          }
        />
        <MetricCard label="Packets" value={formatNumber(data.packetCount)} hint={formatNumber(data.flowSummary.flowCount) + " conversations"} />
        <MetricCard label="Cases" value={formatNumber(data.investigationCount)} hint="Investigations" />
        <MetricCard label="Traffic" value={formatBytes(data.flowSummary.totalBytes)} hint={formatNumber(data.flowSummary.tcpFlows) + " TCP / " + formatNumber(data.flowSummary.udpFlows) + " UDP flows"} />
      </div>

      {hasData ? (
        <>
          <Panel title="Event volume" meta={formatNumber(data.volumeSeries.length) + " buckets"}>
            <VolumeChart series={data.volumeSeries} mode={mode} />
          </Panel>

          <div className="grid-2">
            <Panel title="Severity distribution" meta={formatNumber(data.alertTotal) + " alerts"}>
              <DistributionList
                items={severityItems}
                colorFor={severityColor}
                labelFor={severityLabel}
                unit="alerts"
                emptyLabel="No alerts recorded yet."
              />
            </Panel>
            <Panel
              title="Protocol distribution"
              meta={formatNumber(data.flowSummary.flowCount) + " flows / " + formatBytes(data.flowSummary.totalBytes)}
            >
              <DistributionList
                items={data.protocolDistribution}
                colorFor={protocolColor}
                labelFor={protocolLabel}
                emptyLabel="No protocol telemetry stored."
              />
            </Panel>
          </div>

          <div className="grid-2">
            <Panel title="Top source IPs">
              <DistributionList items={data.topSrcIps} colorFor={protocolColor} labelFor={protocolLabel} />
            </Panel>
            <Panel title="Top destination IPs">
              <DistributionList items={data.topDstIps} colorFor={protocolColor} labelFor={protocolLabel} />
            </Panel>
          </div>

          <Panel title="Recent activity" meta={formatNumber(recentEvents.data ? recentEvents.data.total : 0) + " events"} flush>
            {recentEvents.loading ? (
              <LoadingState label="Loading activity" />
            ) : recentEvents.error ? (
              <ErrorState message={recentEvents.error} onRetry={recentEvents.reload} />
            ) : recentRows.length === 0 ? (
              <EmptyState compact title="No recent activity" description="Imported events appear here newest first." />
            ) : (
              <DataTable
                label="Recent activity"
                columns={activityColumns}
                rows={recentRows}
                rowKey={(event: EventRow) => event.id}
                dense
              />
            )}
          </Panel>

          <div className="grid-2">
            <Panel
              title="Recent alerts"
              actions={
                <Button size="sm" variant="ghost" onClick={() => onNavigate("alerts")}>
                  View all
                </Button>
              }
              flush
            >
              {data.recentAlerts.length === 0 ? (
                <EmptyState
                  compact
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

            <Panel
              title="Datasets"
              meta={formatNumber(data.datasetCount)}
              actions={
                <Button size="sm" variant="ghost" onClick={() => onNavigate("sources")}>
                  Manage
                </Button>
              }
              flush
            >
              {datasetRows.length === 0 ? (
                <EmptyState compact title="No datasets" description="Imported log files appear here with their record counts." />
              ) : (
                <DataTable
                  label="Datasets"
                  columns={datasetColumns}
                  rows={datasetRows.slice(0, 5)}
                  rowKey={(dataset: Dataset) => dataset.id}
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
            description="Import a Suricata, Zeek, JSON or CSV log file, or load the deterministic demo dataset. You can also drag files from your file manager straight onto this window. The demo dataset is synthetic and stays on this machine."
            action={
              <div className="toolbar">
                <Button icon={Download} variant="primary" onClick={() => void beginImport()}>
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
        {isAnalyst ? " Detection and parsing run in the local Rust backend." : ""}
      </p>
    </div>
  );
}
