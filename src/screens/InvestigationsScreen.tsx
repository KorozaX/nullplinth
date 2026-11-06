import { useCallback, useEffect, useState } from "react";
import { Download, Inbox, Plus, ShieldQuestion, X } from "lucide-react";

import { api } from "../services/api";
import type { Alert, AlertDetail, Investigation, InvestigationDetail } from "../types/contracts";
import { useMode } from "../context/ModeContext";
import { errorMessage, useLoad } from "../lib/async";
import { pickSavePath } from "../lib/dialog";
import { formatNumber, formatTimestamp, formatValue } from "../lib/format";
import { Button, IconButton } from "../components/ui/Button";
import { EmptyState, ErrorState, LoadingState, Notice } from "../components/ui/Feedback";
import { Panel } from "../components/ui/Panel";
import { Field, Select, TextArea, TextInput } from "../components/ui/Field";
import { SeverityBadge, StatusBadge } from "../components/ui/Badge";
import { Drawer } from "../components/ui/Drawer";
import { EventDetailPanel } from "../components/EventDetailPanel";
import type { EventDetail } from "../types/contracts";

const STATUSES = ["open", "investigating", "resolved", "closed"] as const;

export function InvestigationsScreen({ focusId }: { focusId: number | null }) {
  const { mode, isAnalyst } = useMode();
  const list = useLoad(() => api.listInvestigations(), []);

  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [createTitle, setCreateTitle] = useState("");
  const [createDescription, setCreateDescription] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const [titleDraft, setTitleDraft] = useState("");
  const [descriptionDraft, setDescriptionDraft] = useState("");
  const [statusDraft, setStatusDraft] = useState("open");
  const [noteDraft, setNoteDraft] = useState("");

  const [alertDrawerOpen, setAlertDrawerOpen] = useState(false);
  const [alertDetail, setAlertDetail] = useState<AlertDetail | null>(null);
  const [alertLoading, setAlertLoading] = useState(false);
  const [alertError, setAlertError] = useState<string | null>(null);

  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const [evidenceEvent, setEvidenceEvent] = useState<EventDetail | null>(null);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);

  useEffect(() => {
    if (focusId !== null) setSelectedId(focusId);
  }, [focusId]);

  const detail = useLoad<InvestigationDetail | null>(
    () => (selectedId === null ? Promise.resolve<InvestigationDetail | null>(null) : api.getInvestigation(selectedId)),
    [selectedId],
  );

  useEffect(() => {
    const investigation = detail.data ? detail.data.investigation : null;
    if (!investigation) return;
    setTitleDraft(investigation.title);
    setDescriptionDraft(investigation.description);
    setStatusDraft(investigation.status);
  }, [detail.data]);

  const closeAlert = useCallback(() => {
    setAlertDrawerOpen(false);
    setAlertDetail(null);
    setAlertError(null);
  }, []);

  const closeEvidence = useCallback(() => {
    setEvidenceOpen(false);
    setEvidenceEvent(null);
    setEvidenceError(null);
  }, []);

  async function createInvestigation() {
    if (createTitle.trim().length === 0) {
      setCreateError("Give the investigation a title");
      return;
    }
    setCreateError(null);
    setBusy(true);
    setActionError(null);
    try {
      const created = await api.createInvestigation({
        title: createTitle.trim(),
        description: createDescription.trim(),
      });
      setSelectedId(created.investigation.id);
      setShowCreate(false);
      setCreateTitle("");
      setCreateDescription("");
      list.reload();
    } catch (cause) {
      setActionError(errorMessage(cause));
    } finally {
      setBusy(false);
    }
  }

  async function saveInvestigation() {
    if (selectedId === null) return;
    setBusy(true);
    setActionError(null);
    setNotice(null);
    try {
      const updated = await api.updateInvestigation(selectedId, {
        title: titleDraft.trim(),
        description: descriptionDraft,
        status: statusDraft,
      });
      detail.setData(updated);
      setNotice("Investigation saved.");
      list.reload();
    } catch (cause) {
      setActionError(errorMessage(cause));
    } finally {
      setBusy(false);
    }
  }

  async function addNote() {
    if (selectedId === null) return;
    const body = noteDraft.trim();
    if (body.length === 0) return;
    setBusy(true);
    setActionError(null);
    try {
      const updated = await api.addInvestigationNote(selectedId, body);
      detail.setData(updated);
      setNoteDraft("");
      list.reload();
    } catch (cause) {
      setActionError(errorMessage(cause));
    } finally {
      setBusy(false);
    }
  }

  async function exportInvestigation() {
    if (selectedId === null || !detail.data) return;
    const target = await pickSavePath(
      detail.data.investigation.title.replace(/[^a-zA-Z0-9-_]+/g, "-") + "-investigation.json",
      [{ name: "JSON report", extensions: ["json"] }],
    );
    if (!target) return;
    setBusy(true);
    setActionError(null);
    setNotice(null);
    try {
      const written = await api.exportInvestigation(selectedId, target);
      setNotice("Exported investigation to " + written + ".");
    } catch (cause) {
      setActionError(errorMessage(cause));
    } finally {
      setBusy(false);
    }
  }

  async function openAlert(alert: Alert) {
    setAlertDrawerOpen(true);
    setAlertDetail(null);
    setAlertError(null);
    setAlertLoading(true);
    try {
      const loaded = await api.getAlert(alert.id);
      setAlertDetail(loaded);
    } catch (cause) {
      setAlertError(errorMessage(cause));
    } finally {
      setAlertLoading(false);
    }
  }

  async function openEvidence(eventRefId: number) {
    setEvidenceOpen(true);
    setEvidenceEvent(null);
    setEvidenceError(null);
    setEvidenceLoading(true);
    try {
      const loaded = await api.getEvent(eventRefId);
      setEvidenceEvent(loaded);
    } catch (cause) {
      setEvidenceError(errorMessage(cause));
    } finally {
      setEvidenceLoading(false);
    }
  }

  const investigations: readonly Investigation[] = list.data ?? [];
  const active: InvestigationDetail | null = detail.data;
  const investigation = active ? active.investigation : null;

  if (list.loading && !list.data) return <LoadingState label="Loading investigations" />;
  if (list.error) return <ErrorState message={list.error} onRetry={list.reload} />;

  return (
    <div className="page">
      <div className="page__bar">
        <p className="page__lede">
          Keep a written record of what you checked. Investigations collect notes and attached alerts, and export as a
          single JSON report.
        </p>
        <div className="toolbar">
          <Button icon={Plus} variant="primary" onClick={() => setShowCreate((current) => !current)}>
            {showCreate ? "Cancel new investigation" : "New investigation"}
          </Button>
        </div>
      </div>

      {notice ? <Notice tone="ok">{notice}</Notice> : null}
      {actionError ? <Notice tone="error">{actionError}</Notice> : null}

      {showCreate ? (
        <Panel title="New investigation" actions={<IconButton icon={X} label="Close new investigation form" onClick={() => setShowCreate(false)} />}>
          <div className="form-grid">
            <Field label="Title" error={createError}>
              <TextInput
                value={createTitle}
                placeholder="Suspicious outbound connections from 10.0.0.5"
                onChange={(event) => setCreateTitle(event.target.value)}
              />
            </Field>
            <Field label="Description" className="form-grid__wide">
              <TextArea
                value={createDescription}
                placeholder="What do you know so far?"
                onChange={(event) => setCreateDescription(event.target.value)}
              />
            </Field>
          </div>
          <div className="form-actions">
            <Button variant="primary" onClick={createInvestigation} disabled={busy}>
              {busy ? "Creating" : "Create investigation"}
            </Button>
          </div>
        </Panel>
      ) : null}

      {investigations.length === 0 ? (
        <Panel flush>
          <EmptyState
            icon={ShieldQuestion}
            title="No investigations yet"
            description="Open a case when an alert needs follow-up. You can also create one directly from an alert's detail panel."
            action={
              <Button icon={Plus} variant="primary" onClick={() => setShowCreate(true)}>
                New investigation
              </Button>
            }
          />
        </Panel>
      ) : (
        <div className="split split--side">
          <Panel title="Cases" meta={formatNumber(investigations.length)} flush>
            <div className="record-list">
              {investigations.map((entry) => (
                <button
                  key={entry.id}
                  type="button"
                  className={"record" + (entry.id === selectedId ? " is-active" : "")}
                  onClick={() => setSelectedId(entry.id)}
                >
                  <span className="record__title">{entry.title}</span>
                  <span className="record__meta">
                    <StatusBadge status={entry.status} />
                    <span>{formatTimestamp(entry.updatedAt, mode)}</span>
                    {isAnalyst ? <span className="mono">{"#" + String(entry.id)}</span> : null}
                    <span>{formatNumber(entry.noteCount) + (entry.noteCount === 1 ? " note" : " notes")}</span>
                  </span>
                </button>
              ))}
            </div>
          </Panel>

          <Panel
            title={investigation ? investigation.title : "Investigation"}
            meta={investigation ? formatTimestamp(investigation.updatedAt, mode) : undefined}
            actions={
              investigation ? (
                <Button size="sm" variant="ghost" icon={Download} onClick={exportInvestigation} disabled={busy}>
                  Export report
                </Button>
              ) : undefined
            }
          >
            {selectedId === null ? (
              <EmptyState icon={Inbox} title="Select an investigation" description="Choose a case from the list to read its notes and attached alerts." />
            ) : detail.loading && !detail.data ? (
              <LoadingState label="Loading investigation" />
            ) : detail.error ? (
              <ErrorState message={detail.error} onRetry={detail.reload} />
            ) : active && investigation ? (
              <div className="stack">
                <div className="form-grid">
                  <Field label="Title">
                    <TextInput value={titleDraft} onChange={(event) => setTitleDraft(event.target.value)} />
                  </Field>
                  <Field label="Status">
                    <Select value={statusDraft} onChange={(event) => setStatusDraft(event.target.value)}>
                      {STATUSES.map((status) => (
                        <option key={status} value={status}>
                          {status}
                        </option>
                      ))}
                    </Select>
                  </Field>
                </div>
                <Field label="Description">
                  <TextArea value={descriptionDraft} onChange={(event) => setDescriptionDraft(event.target.value)} />
                </Field>
                <div className="toolbar">
                  <Button onClick={saveInvestigation} disabled={busy}>
                    {busy ? "Saving" : "Save changes"}
                  </Button>
                  {isAnalyst ? (
                    <span className="dim mono">
                      created {formatTimestamp(investigation.createdAt, mode)} | id {String(investigation.id)} | alerts{" "}
                      {formatNumber(investigation.alertIds.length)}
                    </span>
                  ) : null}
                </div>

                <div className="detail-section">
                  <h3 className="subhead">Attached alerts ({formatNumber(active.alerts.length)})</h3>
                  {active.alerts.length === 0 ? (
                    <p className="muted">No alerts attached to this case.</p>
                  ) : (
                    <ul className="evidence-list">
                      {active.alerts.map((alert) => (
                        <li key={alert.id}>
                          <button type="button" className="evidence" onClick={() => void openAlert(alert)}>
                            <SeverityBadge severity={alert.severity} />
                            <span className="evidence__summary">{alert.title}</span>
                            <StatusBadge status={alert.status} />
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>

                <div className="detail-section">
                  <h3 className="subhead">Notes ({formatNumber(active.notes.length)})</h3>
                  {active.notes.length === 0 ? (
                    <p className="muted">No notes yet. The first note starts the timeline.</p>
                  ) : (
                    <ul className="record-list">
                      {active.notes.map((note) => (
                        <li key={note.id} className="record">
                          <span className="record__meta">{formatTimestamp(note.createdAt, mode)}</span>
                          <span className="record__title" style={{ whiteSpace: "pre-wrap" }}>
                            {note.body}
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}
                  <Field label="Add note">
                    <TextArea
                      value={noteDraft}
                      placeholder="Record what you checked and what you found"
                      onChange={(event) => setNoteDraft(event.target.value)}
                    />
                  </Field>
                  <div className="toolbar">
                    <Button onClick={addNote} disabled={busy || noteDraft.trim().length === 0}>
                      Add note
                    </Button>
                  </div>
                </div>

                <p className="dim">Imported values are shown as text only. Nothing in this case is executed.</p>
              </div>
            ) : (
              <EmptyState icon={Inbox} title="Investigation not found" description={formatValue(detail.error)} />
            )}
          </Panel>
        </div>
      )}

      <Drawer
        open={alertDrawerOpen}
        title={alertDetail ? alertDetail.alert.title : "Attached alert"}
        onClose={closeAlert}
        testId="investigation-alert"
      >
        {alertLoading ? (
          <LoadingState label="Loading alert" />
        ) : alertError ? (
          <ErrorState message={alertError} />
        ) : alertDetail ? (
          <div className="detail-grid">
            <div className="row">
              <SeverityBadge severity={alertDetail.alert.severity} />
              <StatusBadge status={alertDetail.alert.status} />
            </div>
            <p className="why-matters">{alertDetail.alert.explanation}</p>
            <div className="detail-section">
              <h3 className="subhead">Evidence</h3>
              {alertDetail.evidence.length === 0 ? (
                <p className="muted">No evidence rows.</p>
              ) : (
                <ul className="evidence-list">
                  {alertDetail.evidence.map((item) => (
                    <li key={item.kind + "-" + String(item.refId)}>
                      <button type="button" className="evidence" onClick={() => void openEvidence(item.refId)}>
                        <span className="mono">{formatTimestamp(item.ts, mode)}</span>
                        <span className="evidence__summary">{item.summary}</span>
                        <span className="badge badge--neutral mono">{item.kind}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        ) : null}
      </Drawer>

      <Drawer
        open={evidenceOpen}
        title="Evidence event"
        subtitle={evidenceEvent ? formatTimestamp(evidenceEvent.event.ts, mode) : undefined}
        onClose={closeEvidence}
        testId="investigation-evidence"
      >
        <EventDetailPanel detail={evidenceEvent} loading={evidenceLoading} error={evidenceError} mode={mode} />
      </Drawer>
    </div>
  );
}
