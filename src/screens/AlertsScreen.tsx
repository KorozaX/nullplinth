import { useCallback, useMemo, useState } from "react";
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  Inbox,
  Info,
  Play,
  RefreshCw,
  ShieldAlert,
  ShieldPlus,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

import { api } from "../services/api";
import type { Alert, AlertDetail, DetectionRun, EventDetail } from "../types/contracts";
import { useMode } from "../context/ModeContext";
import { errorMessage, useLoad } from "../lib/async";
import { formatDuration, formatFieldLabel, formatJson, formatNumber, formatTimestamp, formatValue } from "../lib/format";
import { normalizeSeverity, severityClass, severityLabel } from "../lib/semantic";
import { Button } from "../components/ui/Button";
import { EmptyState, ErrorState, LoadingState, Notice } from "../components/ui/Feedback";
import { Panel } from "../components/ui/Panel";
import { Field, Select, TextArea, TextInput } from "../components/ui/Field";
import { StatusBadge } from "../components/ui/Badge";
import { DataTable } from "../components/ui/Table";
import type { Column } from "../components/ui/Table";
import { Drawer } from "../components/ui/Drawer";
import { MetricPanel, MetricsStrip } from "../components/MetricPanel";
import { EventDetailPanel } from "../components/EventDetailPanel";
import "../styles/screen-alerts.css";

const SEVERITIES = ["all", "critical", "high", "medium", "low", "info"] as const;
const STATUSES = ["all", "new", "investigating", "resolved"] as const;
const TIME_RANGES = ["all", "15m", "1h", "24h", "7d"] as const;

type TimeRange = (typeof TIME_RANGES)[number];

const TIME_RANGE_LABELS: Record<TimeRange, string> = {
  all: "Any time",
  "15m": "Last 15 minutes",
  "1h": "Last hour",
  "24h": "Last 24 hours",
  "7d": "Last 7 days",
};

const TIME_RANGE_MS: Record<TimeRange, number | null> = {
  all: null,
  "15m": 15 * 60 * 1000,
  "1h": 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
};

const SEVERITY_ICONS: Record<string, LucideIcon> = {
  critical: AlertOctagon,
  high: AlertTriangle,
  medium: ShieldAlert,
  low: Info,
  info: Info,
};

/** Severity is carried by colour, an icon and a text label at the same time. */
function SeverityMark({ severity }: { severity: string }) {
  const key = normalizeSeverity(severity);
  const Icon = SEVERITY_ICONS[key] ?? Info;
  return (
    <span className={"chip " + severityClass(severity)} data-severity={key}>
      <Icon size={11} aria-hidden="true" />
      {severityLabel(severity)}
    </span>
  );
}

function thresholdRows(threshold: unknown): Array<{ key: string; value: string }> {
  if (threshold && typeof threshold === "object" && !Array.isArray(threshold)) {
    return Object.entries(threshold as Record<string, unknown>).map(([key, value]) => ({
      key: formatFieldLabel(key),
      value: formatValue(value),
    }));
  }
  return [{ key: "Threshold", value: formatValue(threshold) }];
}

function severityFromCounts(counts: Record<string, number>, severity: string): number {
  return counts[severity] ?? 0;
}

/** Render only the endpoints that exist; never an orphan arrow or placeholder dash. */
function Endpoints({ alert }: { alert: Alert }) {
  const source = alert.srcIp && alert.srcIp.trim().length > 0 ? alert.srcIp : null;
  const destination = alert.dstIp && alert.dstIp.trim().length > 0 ? alert.dstIp : null;
  if (!source && !destination) {
    return <span className="dim">no endpoint recorded</span>;
  }
  return (
    <span className="alerts-entities">
      {source ? <span className="mono">{source}</span> : null}
      {source && destination ? (
        <ArrowRight className="alerts-entities__arrow" size={11} aria-hidden="true" />
      ) : null}
      {destination ? <span className="mono">{destination}</span> : null}
    </span>
  );
}

export function AlertsScreen({ onOpenInvestigation }: { onOpenInvestigation: (investigationId: number) => void }) {
  const { mode, isAnalyst } = useMode();
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [ruleFilter, setRuleFilter] = useState<string>("all");
  const [ipFilter, setIpFilter] = useState<string>("");
  const [timeRange, setTimeRange] = useState<TimeRange>("all");

  const alerts = useLoad(
    () =>
      api.listAlerts(
        severityFilter === "all" ? null : severityFilter,
        statusFilter === "all" ? null : statusFilter,
      ),
    [severityFilter, statusFilter],
  );

  const [running, setRunning] = useState(false);
  const [runResult, setRunResult] = useState<DetectionRun | null>(null);
  const [runError, setRunError] = useState<string | null>(null);

  const [selectedAlertId, setSelectedAlertId] = useState<number | null>(null);
  const [alertDetail, setAlertDetail] = useState<AlertDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [statusDraft, setStatusDraft] = useState("new");
  const [noteDraft, setNoteDraft] = useState("");
  const [saving, setSaving] = useState(false);
  const [creating, setCreating] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const [evidenceEvent, setEvidenceEvent] = useState<EventDetail | null>(null);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [evidenceOpen, setEvidenceOpen] = useState(false);

  const openAlert = useCallback(async (alertId: number) => {
    setSelectedAlertId(alertId);
    setAlertDetail(null);
    setDetailError(null);
    setActionError(null);
    setDetailLoading(true);
    try {
      const loaded = await api.getAlert(alertId);
      setAlertDetail(loaded);
      setStatusDraft(loaded.alert.status);
      setNoteDraft(loaded.alert.note ?? "");
    } catch (cause) {
      setDetailError(errorMessage(cause));
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const closeAlert = useCallback(() => {
    setSelectedAlertId(null);
    setAlertDetail(null);
    setDetailError(null);
    setActionError(null);
  }, []);

  const closeEvidence = useCallback(() => {
    setEvidenceOpen(false);
    setEvidenceEvent(null);
    setEvidenceError(null);
  }, []);

  async function handleRun() {
    setRunning(true);
    setRunError(null);
    setRunResult(null);
    try {
      const result = await api.runDetection();
      setRunResult(result);
      alerts.reload();
      if (selectedAlertId !== null) {
        await openAlert(selectedAlertId);
      }
    } catch (cause) {
      setRunError(errorMessage(cause));
    } finally {
      setRunning(false);
    }
  }

  async function openEvidenceEvent(eventId: number) {
    setEvidenceOpen(true);
    setEvidenceEvent(null);
    setEvidenceError(null);
    setEvidenceLoading(true);
    try {
      const loaded = await api.getEvent(eventId);
      setEvidenceEvent(loaded);
    } catch (cause) {
      setEvidenceError(errorMessage(cause));
    } finally {
      setEvidenceLoading(false);
    }
  }

  async function saveAlert() {
    if (selectedAlertId === null) return;
    setSaving(true);
    setActionError(null);
    try {
      await api.updateAlertStatus(selectedAlertId, statusDraft, noteDraft.trim().length > 0 ? noteDraft.trim() : null);
      const refreshed = await api.getAlert(selectedAlertId);
      setAlertDetail(refreshed);
      alerts.reload();
    } catch (cause) {
      setActionError(errorMessage(cause));
    } finally {
      setSaving(false);
    }
  }

  async function createInvestigation() {
    if (!alertDetail) return;
    setCreating(true);
    setActionError(null);
    try {
      const detail = await api.createInvestigation({
        title: alertDetail.alert.title,
        description: alertDetail.alert.explanation,
        alertIds: [alertDetail.alert.id],
      });
      onOpenInvestigation(detail.investigation.id);
    } catch (cause) {
      setActionError(errorMessage(cause));
    } finally {
      setCreating(false);
    }
  }

  const alertList = alerts.data ?? [];

  const rules = useMemo(() => {
    const unique = new Set<string>();
    for (const alert of alertList) unique.add(alert.rule);
    return Array.from(unique).sort();
  }, [alertList]);

  const visibleAlerts = useMemo(() => {
    const cutoffMs = TIME_RANGE_MS[timeRange];
    const cutoff = cutoffMs === null ? null : Date.now() - cutoffMs;
    const needle = ipFilter.trim().toLowerCase();
    return alertList.filter((alert) => {
      if (ruleFilter !== "all" && alert.rule !== ruleFilter) return false;
      if (cutoff !== null && alert.createdAt < cutoff) return false;
      if (needle.length > 0) {
        const haystack = [alert.title, alert.srcIp, alert.dstIp, alert.rule, alert.id]
          .filter((value) => value !== null && value !== undefined)
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(needle)) return false;
      }
      return true;
    });
  }, [alertList, ruleFilter, ipFilter, timeRange]);

  const counts = useMemo(() => {
    const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    let open = 0;
    let investigating = 0;
    let linkedEvents = 0;
    for (const alert of alertList) {
      bySeverity[normalizeSeverity(alert.severity)] += 1;
      if (alert.status === "new") open += 1;
      if (alert.status === "investigating") investigating += 1;
      linkedEvents += alert.eventCount;
    }
    return { bySeverity, open, investigating, linkedEvents };
  }, [alertList]);

  const filtersActive =
    severityFilter !== "all" ||
    statusFilter !== "all" ||
    ruleFilter !== "all" ||
    ipFilter.trim().length > 0 ||
    timeRange !== "all";

  function clearFilters() {
    setSeverityFilter("all");
    setStatusFilter("all");
    setRuleFilter("all");
    setIpFilter("");
    setTimeRange("all");
  }

  const columns: ReadonlyArray<Column<Alert>> = [
    {
      key: "severity",
      header: "Severity",
      width: "110px",
      render: (alert: Alert) => <SeverityMark severity={alert.severity} />,
    },
    {
      key: "title",
      header: "Alert",
      render: (alert: Alert) => (
        <span className="alerts-cell">
          <span className="alerts-cell__title">{alert.title}</span>
          <span className="alerts-cell__rule mono">{alert.rule}</span>
        </span>
      ),
    },
    {
      key: "entity",
      header: "Source / destination",
      render: (alert: Alert) => <Endpoints alert={alert} />,
    },
    ...(isAnalyst
      ? ([
          {
            key: "confidence",
            header: "Conf.",
            mono: true,
            align: "right",
            render: (alert: Alert) => alert.confidence.toFixed(2),
          },
        ] as const)
      : []),
    {
      key: "eventCount",
      header: "Events",
      mono: true,
      align: "right",
      render: (alert: Alert) => formatNumber(alert.eventCount),
    },
    { key: "status", header: "Status", render: (alert: Alert) => <StatusBadge status={alert.status} /> },
    {
      key: "createdAt",
      header: "Created",
      mono: true,
      render: (alert: Alert) => formatTimestamp(alert.createdAt, mode),
    },
  ];

  const headActions = (
    <div className="page__actions">
      <Button icon={Play} variant="primary" onClick={handleRun} disabled={running}>
        {running ? "Running detection" : "Run detection"}
      </Button>
      <Button icon={RefreshCw} variant="ghost" onClick={alerts.reload} aria-label="Refresh alerts" />
    </div>
  );

  return (
    <div className="page alerts-page">
      <div className="page__head">
        <div className="page__titles">
          <h2 className="page__title">Alerts</h2>
          <p className="page__lede">
            Detection runs locally over the stored events. Every alert links back to the real events that triggered it,
            with the threshold that fired and the steps worth taking next.
          </p>
        </div>
        {headActions}
      </div>

      {runResult ? (
        <Notice tone="ok">
          Detection run complete: {formatNumber(runResult.alertsCreated)} new alerts in{" "}
          {formatDuration(runResult.durationMs)}.{" "}
          {runResult.rules.map((rule) => (
            <span key={rule.rule}>
              {rule.rule}: {formatNumber(rule.alertsCreated)}
              {rule.skipped ? " (skipped: " + rule.skipped + ")" : ""}.{" "}
            </span>
          ))}
        </Notice>
      ) : null}
      {runError ? <Notice tone="error">{runError}</Notice> : null}

      <MetricsStrip>
        <MetricPanel
          label="Shown"
          value={formatNumber(visibleAlerts.length)}
          hint={formatNumber(alertList.length) + " " + (alertList.length === 1 ? "alert" : "alerts")}
          tone="accent"
        />
        <MetricPanel
          label="Critical"
          value={formatNumber(severityFromCounts(counts.bySeverity, "critical"))}
          hint="needs immediate triage"
          tone={severityFromCounts(counts.bySeverity, "critical") > 0 ? "critical" : "default"}
        />
        <MetricPanel
          label="High"
          value={formatNumber(severityFromCounts(counts.bySeverity, "high"))}
          hint={formatNumber(severityFromCounts(counts.bySeverity, "medium")) + " medium"}
        />
        <MetricPanel
          label="Open"
          value={formatNumber(counts.open)}
          hint={formatNumber(counts.investigating) + " investigating"}
        />
        <MetricPanel label="Linked events" value={formatNumber(counts.linkedEvents)} hint="evidence rows behind these alerts" />
      </MetricsStrip>

      <div className="alerts-legend" aria-label="Severity legend">
        {(["critical", "high", "medium", "low", "info"] as const).map((severity) => (
          <span className="alerts-legend__item" key={severity}>
            <SeverityMark severity={severity} />
          </span>
        ))}
      </div>

      <div className="alerts-filterbar">
        <Field label="Severity">
          <Select
            aria-label="Filter by severity"
            value={severityFilter}
            onChange={(event) => setSeverityFilter(event.target.value)}
          >
            {SEVERITIES.map((severity) => (
              <option key={severity} value={severity}>
                {severity === "all" ? "All severities" : severityLabel(severity)}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Status">
          <Select
            aria-label="Filter by status"
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
          >
            {STATUSES.map((status) => (
              <option key={status} value={status}>
                {status === "all" ? "All statuses" : status}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Rule">
          <Select
            aria-label="Filter by rule"
            value={ruleFilter}
            onChange={(event) => setRuleFilter(event.target.value)}
          >
            <option value="all">All rules</option>
            {rules.map((rule) => (
              <option key={rule} value={rule}>
                {rule}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="IP or title">
          <TextInput
            aria-label="Filter by IP address"
            placeholder="203.0.113.44"
            value={ipFilter}
            onChange={(event) => setIpFilter(event.target.value)}
          />
        </Field>
        <Field label="Time">
          <Select
            aria-label="Filter by time"
            value={timeRange}
            onChange={(event) => setTimeRange(event.target.value as TimeRange)}
          >
            {TIME_RANGES.map((range) => (
              <option key={range} value={range}>
                {TIME_RANGE_LABELS[range]}
              </option>
            ))}
          </Select>
        </Field>
        <div className="alerts-filterbar__reset">
          <Button variant="ghost" size="sm" onClick={clearFilters} disabled={!filtersActive}>
            Clear filters
          </Button>
        </div>
      </div>

      <Panel title="Alert queue" meta={formatNumber(visibleAlerts.length) + " shown"} flush>
        {alerts.loading ? (
          <LoadingState label="Loading alerts" />
        ) : alerts.error ? (
          <ErrorState message={alerts.error} onRetry={alerts.reload} />
        ) : alertList.length === 0 ? (
          <EmptyState
            icon={Inbox}
            title="No alerts yet"
            description="Run detection to evaluate the stored events against the four built-in rules: repeated authentication failures, port scanning, DNS NXDOMAIN bursts and repeated blocked connections."
            action={
              <Button icon={Play} variant="primary" onClick={handleRun} disabled={running}>
                {running ? "Running detection" : "Run detection"}
              </Button>
            }
          />
        ) : visibleAlerts.length === 0 ? (
          <EmptyState
            icon={Inbox}
            title="No alerts match these filters"
            description="Loosen the severity, rule, IP or time filter to see the rest of the queue."
            action={
              <Button variant="ghost" onClick={clearFilters}>
                Clear filters
              </Button>
            }
          />
        ) : (
          <DataTable
            label="Alerts"
            columns={columns}
            rows={visibleAlerts}
            rowKey={(alert: Alert) => alert.id}
            onRowClick={(alert: Alert) => void openAlert(alert.id)}
            selectedKey={selectedAlertId}
            dense
          />
        )}
      </Panel>

      <Drawer
        open={selectedAlertId !== null}
        title={alertDetail ? alertDetail.alert.title : "Alert"}
        subtitle={alertDetail ? formatTimestamp(alertDetail.alert.createdAt, mode) : undefined}
        onClose={closeAlert}
        testId="alert-detail"
      >
        {detailLoading ? (
          <LoadingState label="Loading alert" />
        ) : detailError ? (
          <ErrorState message={detailError} />
        ) : alertDetail ? (
          <div className="detail-grid">
            <div className="alerts-detail-head">
              <SeverityMark severity={alertDetail.alert.severity} />
              <StatusBadge status={alertDetail.alert.status} />
              <span className="badge badge--neutral mono">{alertDetail.alert.rule}</span>
            </div>

            <p className="why-matters">{alertDetail.alert.explanation}</p>

            <div className="alerts-facts">
              <span className="alerts-fact">
                <span className="alerts-fact__label">Confidence</span>
                <span className="alerts-fact__value">{alertDetail.alert.confidence.toFixed(2)}</span>
              </span>
              <span className="alerts-fact">
                <span className="alerts-fact__label">Linked events</span>
                <span className="alerts-fact__value">{formatNumber(alertDetail.alert.eventCount)}</span>
              </span>
              {alertDetail.alert.srcIp ? (
                <span className="alerts-fact">
                  <span className="alerts-fact__label">Source</span>
                  <span className="alerts-fact__value">{alertDetail.alert.srcIp}</span>
                </span>
              ) : null}
              {alertDetail.alert.dstIp ? (
                <span className="alerts-fact">
                  <span className="alerts-fact__label">Destination</span>
                  <span className="alerts-fact__value">{alertDetail.alert.dstIp}</span>
                </span>
              ) : null}
              <span className="alerts-fact alerts-facts__wide">
                <span className="alerts-fact__label">Created</span>
                <span className="alerts-fact__value">{formatTimestamp(alertDetail.alert.createdAt, mode)}</span>
              </span>
            </div>

            {isAnalyst ? (
              <div className="detail-section">
                <h3 className="subhead">Rule detail</h3>
                <dl className="kv">
                  <div style={{ display: "contents" }}>
                    <dt className="kv__key">Rule</dt>
                    <dd className="kv__val mono">{alertDetail.alert.rule}</dd>
                  </div>
                  <div style={{ display: "contents" }}>
                    <dt className="kv__key">Rule ID</dt>
                    <dd className="kv__val mono">{String(alertDetail.alert.id)}</dd>
                  </div>
                </dl>
              </div>
            ) : null}

            <div className="detail-section">
              <h3 className="subhead">Threshold</h3>
              {isAnalyst ? (
                <pre className="codeblock">{formatJson(alertDetail.alert.threshold)}</pre>
              ) : (
                <dl className="kv">
                  {thresholdRows(alertDetail.alert.threshold).map((row) => (
                    <div key={row.key} style={{ display: "contents" }}>
                      <dt className="kv__key">{row.key}</dt>
                      <dd className="kv__val mono">{row.value}</dd>
                    </div>
                  ))}
                </dl>
              )}
            </div>

            <div className="detail-section">
              <h3 className="subhead">Recommended steps</h3>
              <ol className="steps">
                {alertDetail.alert.recommendedSteps.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ol>
            </div>

            <div className="detail-section">
              <h3 className="subhead">Evidence ({formatNumber(alertDetail.evidence.length)})</h3>
              {alertDetail.evidence.length === 0 ? (
                <p className="muted">This alert has no linked evidence rows.</p>
              ) : (
                <ul className="evidence-list">
                  {alertDetail.evidence.map((item) => (
                    <li key={item.kind + "-" + String(item.refId)}>
                      <button type="button" className="evidence" onClick={() => void openEvidenceEvent(item.refId)}>
                        <span className="alerts-evidence-row">
                          <span className="alerts-evidence-row__time mono">{formatTimestamp(item.ts, mode)}</span>
                          <span className="alerts-evidence-row__summary evidence__summary">{item.summary}</span>
                          <span className="badge badge--neutral mono">{item.kind}</span>
                          <ArrowRight size={11} aria-hidden="true" className="alerts-entities__arrow" />
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div className="detail-section">
              <h3 className="subhead">Status and note</h3>
              <Field label="Status">
                <Select value={statusDraft} onChange={(event) => setStatusDraft(event.target.value)}>
                  <option value="new">new</option>
                  <option value="investigating">investigating</option>
                  <option value="resolved">resolved</option>
                </Select>
              </Field>
              <Field label="Analyst note">
                <TextArea
                  value={noteDraft}
                  placeholder="What did you check? What was the outcome?"
                  onChange={(event) => setNoteDraft(event.target.value)}
                />
              </Field>
              {actionError ? <Notice tone="error">{actionError}</Notice> : null}
              <div className="toolbar">
                <Button onClick={saveAlert} disabled={saving}>
                  {saving ? "Saving" : "Save status"}
                </Button>
                <Button icon={ShieldPlus} variant="ghost" onClick={createInvestigation} disabled={creating}>
                  {creating ? "Creating case" : "Create investigation"}
                </Button>
              </div>
            </div>
          </div>
        ) : null}
      </Drawer>

      <Drawer
        open={evidenceOpen}
        title="Evidence event"
        subtitle={evidenceEvent ? formatTimestamp(evidenceEvent.event.ts, mode) : undefined}
        onClose={closeEvidence}
        testId="evidence-event"
      >
        <EventDetailPanel detail={evidenceEvent} loading={evidenceLoading} error={evidenceError} mode={mode} />
      </Drawer>

      {alerts.error ? null : (
        <span className="sr-only" aria-live="polite">
          {visibleAlerts.length + " alerts shown"}
        </span>
      )}
    </div>
  );
}
