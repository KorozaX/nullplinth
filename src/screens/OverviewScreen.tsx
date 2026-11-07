import { useState } from "react";
import { Download, FileSpreadsheet, Inbox, Play, RefreshCw, Share2 } from "lucide-react";

import { api } from "../services/api";
import type { TopologyNode } from "../types/contracts";
import { useMode } from "../context/ModeContext";
import { useWorkspace } from "../context/WorkspaceContext";
import { useImport } from "../components/ImportWorkflow";
import { useLoad } from "../lib/async";
import { formatBytes, formatNumber } from "../lib/format";
import { severityColor, severityLabel } from "../lib/semantic";
import { Button } from "../components/ui/Button";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/Feedback";
import { Panel } from "../components/ui/Panel";
import { MetricPanel, MetricsStrip } from "../components/MetricPanel";
import {
  AlertList,
  BarList,
  ProtocolMix,
  RankList,
  SeverityDistribution,
  VolumeChart,
} from "../components/VolumeChart";
import { TopologyGraph } from "../components/TopologyGraph";
import type { SectionId } from "../shell/sections";

export interface OverviewScreenProps {
  onNavigate: (section: SectionId) => void;
  onSearch?: (text: string) => void;
}

export function OverviewScreen({ onNavigate, onSearch }: OverviewScreenProps) {
  const { mode, isAnalyst } = useMode();
  const { version, refresh } = useWorkspace();
  const { beginImport, importDemo } = useImport();
  const overview = useLoad(() => api.getOverview(), [version]);
  const topology = useLoad(() => api.networkTopology(120), [version]);
  const [busy, setBusy] = useState(false);
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null);

  async function handleDemo() {
    setBusy(true);
    await importDemo();
    setBusy(false);
  }

  if (overview.loading && !overview.data) return <LoadingState label="Loading overview" />;
  if (overview.error) return <ErrorState message={overview.error} onRetry={overview.reload} />;
  const data = overview.data;
  if (!data) return <LoadingState label="Loading overview" />;

  const hasData = data.totalEvents > 0 || data.datasetCount > 0 || data.captureCount > 0 || data.alertTotal > 0;
  const criticalAlerts = data.alertsBySeverity.find((item) => item.key === "critical")?.count ?? 0;
  const severityHint =
    data.alertsBySeverity.length > 0
      ? data.alertsBySeverity.map((item) => formatNumber(item.count) + " " + item.key).join(" · ")
      : "No alerts";
  const topologyNodes = topology.data ? topology.data.nodes.length : 0;
  const topologyEdges = topology.data ? topology.data.edges.length : 0;

  const actions = (
    <div className="page__actions">
      <Button icon={Download} variant="primary" onClick={() => void beginImport()} disabled={busy}>
        Import data
      </Button>
      <Button icon={FileSpreadsheet} variant="secondary" onClick={() => void beginImport()} disabled={busy}>
        Import CSV
      </Button>
      <Button icon={Play} variant="ghost" onClick={handleDemo} disabled={busy}>
        {busy ? "Loading demo" : "Load demo dataset"}
      </Button>
      <Button icon={RefreshCw} variant="ghost" onClick={refresh} aria-label="Refresh overview" />
    </div>
  );

  return (
    <div className="page">
      <div className="page__head">
        <div className="page__titles">
          <h2 className="page__title">Workbench overview</h2>
          <p className="page__lede">
            Everything runs on this machine. Import logs, drop files anywhere in the window, or load the deterministic
            demo dataset to explore the workbench.
          </p>
        </div>
        {actions}
      </div>

      <MetricsStrip>
        <MetricPanel
          label="Events"
          value={formatNumber(data.totalEvents)}
          tone="accent"
          hint={formatNumber(data.datasetCount) + " datasets"}
          spark={data.volumeSeries.map((bucket) => bucket.count)}
        />
        <MetricPanel label="Datasets" value={formatNumber(data.datasetCount)} hint={formatNumber(data.captureCount) + " captures"} />
        <MetricPanel label="Alerts" value={formatNumber(data.alertTotal)} tone={data.alertTotal > 0 ? "critical" : "default"} hint={severityHint} />
        <MetricPanel label="Critical" value={formatNumber(criticalAlerts)} tone={criticalAlerts > 0 ? "critical" : "default"} hint="unresolved alerts" />
        <MetricPanel label="Packets" value={formatNumber(data.packetCount)} hint={formatNumber(data.captureCount) + " captures"} />
        <MetricPanel
          label="Conversations"
          value={formatNumber(data.flowSummary.flowCount)}
          hint={formatBytes(data.flowSummary.totalBytes)}
        />
      </MetricsStrip>

      {hasData ? (
        <>
          <div className="overview-main">
            <Panel
              title="Event volume"
              meta={isAnalyst ? formatNumber(data.volumeSeries.length) + " buckets" : undefined}
            >
              <VolumeChart series={data.volumeSeries} mode={mode} />
            </Panel>

            <div className="overview-side">
              <Panel title="Severity mix" meta={formatNumber(data.alertTotal) + " alerts"}>
                <SeverityDistribution items={data.alertsBySeverity} label="Alert severity" />
              </Panel>
              <Panel
                title="Protocol mix"
                meta={formatNumber(data.flowSummary.flowCount) + " flows / " + formatBytes(data.flowSummary.totalBytes)}
              >
                <ProtocolMix items={data.protocolDistribution} />
              </Panel>
            </div>
          </div>

          <div className="overview-split">
            <Panel title="Top sources">
              <BarList items={data.topSrcIps} colorFor={() => "var(--teal)"} />
            </Panel>
            <Panel title="Top destinations">
              <BarList items={data.topDstIps} colorFor={() => "var(--cyan)"} />
            </Panel>
            <Panel title="Event severity" meta={formatNumber(data.totalEvents) + " events"}>
              <SeverityDistribution items={data.eventSeverityDistribution} label="Event severity" unit="events" />
            </Panel>
          </div>

          <div className="grid-2">
            <Panel title="Top hosts">
              <RankList items={data.topHosts} emptyLabel="No host values stored in the events yet." />
            </Panel>
            <Panel title="Top ports">
              <RankList items={data.topPorts} emptyLabel="No destination ports stored in the events yet." />
            </Panel>
          </div>

          <div className="overview-main">
            <Panel
              title="Relationship graph"
              meta={
                topology.data
                  ? formatNumber(topologyNodes) + " hosts · " + formatNumber(topologyEdges) + " conversations"
                  : undefined
              }
              actions={
                <span className="badge">
                  <Share2 size={11} aria-hidden="true" /> derived from records
                </span>
              }
            >
              <div className="topology-frame">
                {topology.loading && !topology.data ? (
                  <LoadingState label="Building topology" />
                ) : topology.error ? (
                  <ErrorState message={topology.error} onRetry={topology.reload} />
                ) : (
                  <TopologyGraph
                    data={topology.data}
                    selectedNodeId={selectedNode ? selectedNode.id : null}
                    onSelectNode={setSelectedNode}
                  />
                )}
              </div>
              {selectedNode ? (
                <div className="topology-meta" style={{ marginTop: "var(--s-4)" }}>
                  <span className="chip chip--other">
                    <span
                      className="chip__dot"
                      style={{ background: severityColor(selectedNode.severity) }}
                      aria-hidden="true"
                    />
                    {severityLabel(selectedNode.severity)}
                  </span>
                  <span className="mono" style={{ color: "var(--fg)" }}>{selectedNode.id}</span>
                  <span className="dim">{selectedNode.kind}</span>
                  <span className="dim">{formatNumber(selectedNode.events)} events</span>
                  <span className="dim">{formatNumber(selectedNode.alerts)} alerts</span>
                  {onSearch ? (
                    <Button size="sm" variant="ghost" onClick={() => onSearch(selectedNode.id)}>
                      Investigate in Event Explorer
                    </Button>
                  ) : null}
                </div>
              ) : null}
            </Panel>

            <Panel
              title="Recent alerts"
              meta={formatNumber(data.recentAlerts.length) + " shown"}
              actions={
                <Button size="sm" variant="ghost" onClick={() => onNavigate("alerts")}>
                  View all
                </Button>
              }
              flush
            >
              <AlertList alerts={data.recentAlerts} onOpen={() => onNavigate("alerts")} />
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
                <Button icon={Play} variant="secondary" onClick={handleDemo} disabled={busy}>
                  Load demo dataset
                </Button>
              </div>
            }
          />
        </Panel>
      )}

      <p className="page-footnote">
        All data stays on this machine. Nothing is uploaded, and imported content is only ever rendered as text.
      </p>
    </div>
  );
}
