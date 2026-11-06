import { useCallback, useState } from "react";
import { Inbox, Play, RefreshCw, ShieldPlus } from "lucide-react";

import { api } from "../services/api";
import type { Alert, AlertDetail, DetectionRun, EventDetail } from "../types/contracts";
import { useMode } from "../context/ModeContext";
import { errorMessage, useLoad } from "../lib/async";
import { formatDuration, formatFieldLabel, formatJson, formatNumber, formatTimestamp, formatValue } from "../lib/format";
import { Button } from "../components/ui/Button";
import { EmptyState, ErrorState, LoadingState, Notice } from "../components/ui/Feedback";
import { Panel } from "../components/ui/Panel";
import { Field, Select, TextArea } from "../components/ui/Field";
import { SeverityBadge, StatusBadge } from "../components/ui/Badge";
import { DataTable } from "../components/ui/Table";
import type { Column } from "../components/ui/Table";
import { Drawer } from "../components/ui/Drawer";
import { EventDetailPanel } from "../components/EventDetailPanel";

const SEVERITIES = ["all", "critical", "high", "medium", "low", "info"] as const;
const STATUSES = ["all", "new", "investigating", "resolved"] as const;

function thresholdRows(threshold: unknown): Array<{ key: string; value: string }> {
  if (threshold && typeof threshold === "object" && !Array.isArray(threshold)) {
    return Object.entries(threshold as Record<string, unknown>).map(([key, value]) => ({
      key: formatFieldLabel(key),
      value: formatValue(value),
    }));
  }
  return [{ key: "Threshold", value: formatValue(threshold) }];
}

export function AlertsScreen({ onOpenInvestigation }: { onOpenInvestigation: (investigationId: number) => void }) {
  const { mode, isAnalyst } = useMode();
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");

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

  const columns: ReadonlyArray<Column<Alert>> = [
    {
      key: "severity",
      header: "Severity",
      width: "96px",
      render: (alert: Alert) => <SeverityBadge severity={alert.severity} />,
    },
    { key: "title", header: "Alert", render: (alert: Alert) => alert.title },
    ...(isAnalyst
      ? ([
          { key: "rule", header: "Rule", mono: true, render: (alert: Alert) => alert.rule },
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

  const alertList = alerts.data ?? [];

  return (
    <div className="page">
      <div className="page__bar">
        <p className="page__lede">
          Detection runs locally over the stored events. Every alert links back to the real events that triggered it, with
          the threshold that fired and the steps worth taking next.
        </p>
        <div className="toolbar">
          <Button icon={Play} variant="primary" onClick={handleRun} disabled={running}>
            {running ? "Running detection" : "Run detection"}
          </Button>
          <Button icon={RefreshCw} variant="ghost" onClick={alerts.reload} aria-label="Refresh alerts" />
        </div>
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

      <Panel
        title="Alerts"
        meta={formatNumber(alertList.length) + " shown"}
        actions={
          <div className="toolbar">
            <Select
              aria-label="Filter by severity"
              className="select--compact"
              value={severityFilter}
              onChange={(event) => setSeverityFilter(event.target.value)}
            >
              {SEVERITIES.map((severity) => (
                <option key={severity} value={severity}>
                  {severity === "all" ? "All severities" : severity}
                </option>
              ))}
            </Select>
            <Select
              aria-label="Filter by status"
              className="select--compact"
              value={statusFilter}
              onChange={(event) => setStatusFilter(event.target.value)}
            >
              {STATUSES.map((status) => (
                <option key={status} value={status}>
                  {status === "all" ? "All statuses" : status}
                </option>
              ))}
            </Select>
          </div>
        }
        flush
      >
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
        ) : (
          <DataTable
            label="Alerts"
            columns={columns}
            rows={alertList}
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
            <div className="row">
              <SeverityBadge severity={alertDetail.alert.severity} />
              <StatusBadge status={alertDetail.alert.status} />
              {isAnalyst ? <span className="badge badge--neutral mono">{alertDetail.alert.rule}</span> : null}
            </div>

            <p className="why-matters">{alertDetail.alert.explanation}</p>

            {isAnalyst ? (
              <div className="detail-section">
                <h3 className="subhead">Rule detail</h3>
                <dl className="kv">
                  <div style={{ display: "contents" }}>
                    <dt className="kv__key">Rule</dt>
                    <dd className="kv__val mono">{alertDetail.alert.rule}</dd>
                  </div>
                  <div style={{ display: "contents" }}>
                    <dt className="kv__key">Confidence</dt>
                    <dd className="kv__val mono">{alertDetail.alert.confidence.toFixed(2)}</dd>
                  </div>
                  <div style={{ display: "contents" }}>
                    <dt className="kv__key">Source IP</dt>
                    <dd className="kv__val mono">{formatValue(alertDetail.alert.srcIp)}</dd>
                  </div>
                  <div style={{ display: "contents" }}>
                    <dt className="kv__key">Destination IP</dt>
                    <dd className="kv__val mono">{formatValue(alertDetail.alert.dstIp)}</dd>
                  </div>
                  <div style={{ display: "contents" }}>
                    <dt className="kv__key">Events</dt>
                    <dd className="kv__val mono">{formatNumber(alertDetail.alert.eventCount)}</dd>
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
                        <span className="mono">{formatTimestamp(item.ts, mode)}</span>
                        <span className="evidence__summary">{item.summary}</span>
                        <span className="badge badge--neutral mono">{item.kind}</span>
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
          {alertList.length + " alerts shown"}
        </span>
      )}
    </div>
  );
}
