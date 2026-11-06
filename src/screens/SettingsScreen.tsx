import { useEffect, useState } from "react";
import { Database, Save, ShieldCheck, Trash2 } from "lucide-react";

import { api } from "../services/api";
import type { DetectionSettings } from "../types/contracts";
import { useWorkspace } from "../context/WorkspaceContext";
import { errorMessage, useLoad } from "../lib/async";
import { pickSavePath } from "../lib/dialog";
import { formatNumber } from "../lib/format";
import { clearedWorkspaceMessage } from "../lib/importResults";
import { Button } from "../components/ui/Button";
import { ConfirmDialog } from "../components/ui/ConfirmDialog";
import { ErrorState, LoadingState, Notice } from "../components/ui/Feedback";
import { Panel } from "../components/ui/Panel";
import { Field, Select, TextInput } from "../components/ui/Field";

interface SettingField {
  key: keyof DetectionSettings;
  label: string;
  hint: string;
}

const FIELDS: readonly SettingField[] = [
  { key: "bruteForceThreshold", label: "Brute force threshold", hint: "Failed authentication attempts from one source IP" },
  { key: "bruteForceWindowSecs", label: "Brute force window (s)", hint: "Window in seconds for the brute force rule" },
  { key: "portScanThreshold", label: "Port scan threshold", hint: "Distinct destination ports from one source IP" },
  { key: "portScanWindowSecs", label: "Port scan window (s)", hint: "Window in seconds for the port scan rule" },
  { key: "dnsNxdomainThreshold", label: "DNS NXDOMAIN threshold", hint: "NXDOMAIN answers from one source IP" },
  { key: "dnsWindowSecs", label: "DNS window (s)", hint: "Window in seconds for the DNS anomaly rule" },
  { key: "failedConnThreshold", label: "Blocked connection threshold", hint: "Blocked or failed connections from one source IP" },
  { key: "failedConnWindowSecs", label: "Connection window (s)", hint: "Window in seconds for the suspicious connection rule" },
];

function validate(settings: DetectionSettings): Partial<Record<keyof DetectionSettings, string>> {
  const errors: Partial<Record<keyof DetectionSettings, string>> = {};
  for (const field of FIELDS) {
    const value = settings[field.key];
    if (!Number.isInteger(value) || value < 1) {
      errors[field.key] = "Enter a whole number of at least 1";
    }
  }
  return errors;
}

export function SettingsScreen() {
  const { version, refresh } = useWorkspace();
  const settings = useLoad(() => api.getSettings(), []);
  const preferences = useLoad(() => api.getPreferences(), []);
  const workspace = useLoad(() => api.workspaceState(), [version]);

  const [draft, setDraft] = useState<DetectionSettings | null>(null);
  const [errors, setErrors] = useState<Partial<Record<keyof DetectionSettings, string>>>({});
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const [startup, setStartup] = useState<"ask" | "resume">("ask");
  const [startupNotice, setStartupNotice] = useState<string | null>(null);

  const [confirmOpen, setConfirmOpen] = useState(false);
  const [backup, setBackup] = useState(true);
  const [clearing, setClearing] = useState(false);
  const [clearNotice, setClearNotice] = useState<string | null>(null);
  const [clearError, setClearError] = useState<string | null>(null);

  useEffect(() => {
    if (settings.data) setDraft(settings.data);
  }, [settings.data]);

  useEffect(() => {
    if (preferences.data) {
      setStartup(preferences.data.startupBehavior === "resume" ? "resume" : "ask");
    }
  }, [preferences.data]);

  function updateValue(key: keyof DetectionSettings, raw: string) {
    const parsed = raw.trim().length === 0 ? Number.NaN : Number(raw);
    setDraft((current) => (current ? { ...current, [key]: Number.isFinite(parsed) ? parsed : 0 } : current));
    setErrors((current) => {
      const next = { ...current };
      delete next[key];
      return next;
    });
  }

  async function save() {
    if (!draft) return;
    const found = validate(draft);
    if (Object.keys(found).length > 0) {
      setErrors(found);
      setActionError("Fix the highlighted thresholds before saving.");
      return;
    }
    setSaving(true);
    setActionError(null);
    setNotice(null);
    try {
      const saved = await api.saveSettings(draft);
      setDraft(saved);
      setNotice("Detection thresholds saved.");
    } catch (cause) {
      setActionError(errorMessage(cause));
    } finally {
      setSaving(false);
    }
  }

  async function changeStartup(value: "ask" | "resume") {
    setStartup(value);
    setStartupNotice(null);
    try {
      await api.savePreferences({ startupBehavior: value });
      preferences.setData({ startupBehavior: value });
      setStartupNotice(
        value === "resume"
          ? "Saved. NULLPLINTH will resume automatically on launch."
          : "Saved. NULLPLINTH will ask how to start each session.",
      );
    } catch (cause) {
      setStartupNotice(errorMessage(cause));
    }
  }

  async function clearWorkspace() {
    setClearing(true);
    setClearError(null);
    setClearNotice(null);
    try {
      let backupPath: string | null = null;
      if (backup) {
        backupPath = await pickSavePath("nullplinth-backup.db", [{ name: "Database backup", extensions: ["db"] }]);
        if (!backupPath) {
          setClearError("Backup cancelled, so the workspace was not cleared.");
          setClearing(false);
          return;
        }
      }
      const result = await api.clearWorkspace(backupPath);
      setClearNotice(clearedWorkspaceMessage(result.datasets, result.events));
      setConfirmOpen(false);
      refresh();
    } catch (cause) {
      setClearError(errorMessage(cause));
    } finally {
      setClearing(false);
    }
  }

  if (settings.loading && !settings.data) return <LoadingState label="Loading settings" />;
  if (settings.error) return <ErrorState message={settings.error} onRetry={settings.reload} />;

  const workspaceCounts = workspace.data;

  return (
    <div className="page">
      <div className="page__bar">
        <p className="page__lede">
          Detection thresholds control how much evidence is required before a rule raises an alert. Workspace controls live
          in the local SQLite database on this machine.
        </p>
      </div>

      {notice ? <Notice tone="ok">{notice}</Notice> : null}
      {actionError ? <Notice tone="error">{actionError}</Notice> : null}

      <Panel title="Detection thresholds">
        {draft ? (
          <>
            <div className="form-grid">
              {FIELDS.map((field) => (
                <Field key={field.key} label={field.label} hint={field.hint} error={errors[field.key] ?? null}>
                  <TextInput
                    type="number"
                    min={1}
                    step={1}
                    className="input--mono"
                    value={String(draft[field.key])}
                    onChange={(event) => updateValue(field.key, event.target.value)}
                  />
                </Field>
              ))}
            </div>
            <div className="form-actions">
              <Button icon={Save} variant="primary" onClick={save} disabled={saving}>
                {saving ? "Saving" : "Save settings"}
              </Button>
              <Button variant="ghost" onClick={settings.reload} disabled={saving}>
                Reload
              </Button>
            </div>
          </>
        ) : (
          <LoadingState label="Loading thresholds" />
        )}
      </Panel>

      <Panel title="Startup behaviour">
        <div className="grid-2">
          <Field
            label="When NULLPLINTH starts with existing data"
            hint="Asking is the default. Resume opens the workbench immediately."
          >
            <Select
              value={startup}
              disabled={preferences.loading}
              onChange={(event) => void changeStartup(event.target.value === "resume" ? "resume" : "ask")}
            >
              <option value="ask">Ask how to start</option>
              <option value="resume">Resume automatically</option>
            </Select>
          </Field>
          <div>
            {startupNotice ? <Notice tone="ok">{startupNotice}</Notice> : null}
            {preferences.error ? <Notice tone="error">{preferences.error}</Notice> : null}
          </div>
        </div>
      </Panel>

      <Panel title="Workspace">
        <div className="stack">
          {workspaceCounts ? (
            <div className="workspace-stats">
              <span className="ws-stat">
                <span className="ws-stat__value">{formatNumber(workspaceCounts.datasets)}</span>
                <span className="ws-stat__label">Datasets</span>
              </span>
              <span className="ws-stat">
                <span className="ws-stat__value">{formatNumber(workspaceCounts.events)}</span>
                <span className="ws-stat__label">Events</span>
              </span>
              <span className="ws-stat">
                <span className="ws-stat__value">{formatNumber(workspaceCounts.captures)}</span>
                <span className="ws-stat__label">Captures</span>
              </span>
              <span className="ws-stat">
                <span className="ws-stat__value">{formatNumber(workspaceCounts.packets)}</span>
                <span className="ws-stat__label">Packets</span>
              </span>
              <span className="ws-stat">
                <span className="ws-stat__value">{formatNumber(workspaceCounts.alerts)}</span>
                <span className="ws-stat__label">Alerts</span>
              </span>
              <span className="ws-stat">
                <span className="ws-stat__value">{formatNumber(workspaceCounts.investigations)}</span>
                <span className="ws-stat__label">Cases</span>
              </span>
            </div>
          ) : (
            <LoadingState label="Reading workspace" />
          )}
          <label className="checkbox">
            <input type="checkbox" checked={backup} onChange={(event) => setBackup(event.target.checked)} />
            Save a database backup before clearing
          </label>
          <div className="toolbar">
            <Button icon={Trash2} variant="danger" onClick={() => setConfirmOpen(true)}>
              Clear workspace
            </Button>
          </div>
          {clearNotice ? <Notice tone="ok">{clearNotice}</Notice> : null}
          {clearError ? <Notice tone="error">{clearError}</Notice> : null}
          <p className="settings-note">
            Clearing removes datasets, captures, alerts and investigations from the local database. Original imported files
            remain untouched on disk.
          </p>
        </div>
      </Panel>

      <Panel title="About NULLPLINTH">
        <div className="stack">
          <div className="row">
            <ShieldCheck size={16} aria-hidden="true" className="dim" />
            <p className="settings-note">
              NULLPLINTH is a local-first security analysis workbench. Every imported record stays in a SQLite database in
              this user's application data directory. The application makes no network requests, and imported content is
              stored and rendered as text only, never executed.
            </p>
          </div>
          <dl className="about-list">
            <div>
              <dt>Version</dt>
              <dd className="mono">0.2.0</dd>
            </div>
            <div>
              <dt>Storage</dt>
              <dd>Per-user application data directory (SQLite, WAL mode)</dd>
            </div>
            <div>
              <dt>Network access</dt>
              <dd>None. No telemetry, no remote sync, no cloud features.</dd>
            </div>
            <div>
              <dt>Parsers</dt>
              <dd>JSON, NDJSON, Suricata EVE, Zeek TSV, CSV, PCAP and PCAPNG</dd>
            </div>
            <div>
              <dt>Detection rules</dt>
              <dd>Auth brute force, port scan, DNS NXDOMAIN burst, repeated blocked connections</dd>
            </div>
            <div>
              <dt>Workspace storage</dt>
              <dd className="mono">
                <Database size={12} aria-hidden="true" /> local only
              </dd>
            </div>
          </dl>
        </div>
      </Panel>

      <ConfirmDialog
        open={confirmOpen}
        title="Clear workspace"
        message="Remove every dataset, capture, alert and investigation from the local database? Original imported files are not touched, and a backup can be written first. This cannot be undone."
        confirmLabel="Clear workspace"
        busy={clearing}
        onCancel={() => setConfirmOpen(false)}
        onConfirm={() => void clearWorkspace()}
      />
    </div>
  );
}