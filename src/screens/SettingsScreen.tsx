import { useEffect, useState } from "react";
import { Save, ShieldCheck } from "lucide-react";

import { api } from "../services/api";
import type { DetectionSettings } from "../types/contracts";
import { errorMessage, useLoad } from "../lib/async";
import { formatNumber } from "../lib/format";
import { Button } from "../components/ui/Button";
import { ErrorState, LoadingState, Notice } from "../components/ui/Feedback";
import { Panel } from "../components/ui/Panel";
import { Field, TextInput } from "../components/ui/Field";

interface SettingField {
  key: keyof DetectionSettings;
  label: string;
  hint: string;
}

const FIELDS: readonly SettingField[] = [
  {
    key: "bruteForceThreshold",
    label: "Brute force threshold",
    hint: "Failed authentication attempts from one source IP",
  },
  {
    key: "bruteForceWindowSecs",
    label: "Brute force window (s)",
    hint: "Window in seconds for the brute force rule",
  },
  { key: "portScanThreshold", label: "Port scan threshold", hint: "Distinct destination ports from one source IP" },
  { key: "portScanWindowSecs", label: "Port scan window (s)", hint: "Window in seconds for the port scan rule" },
  { key: "dnsNxdomainThreshold", label: "DNS NXDOMAIN threshold", hint: "NXDOMAIN answers from one source IP" },
  { key: "dnsWindowSecs", label: "DNS window (s)", hint: "Window in seconds for the DNS anomaly rule" },
  {
    key: "failedConnThreshold",
    label: "Blocked connection threshold",
    hint: "Blocked or failed connections from one source IP",
  },
  {
    key: "failedConnWindowSecs",
    label: "Connection window (s)",
    hint: "Window in seconds for the suspicious connection rule",
  },
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
  const settings = useLoad(() => api.getSettings(), []);
  const [draft, setDraft] = useState<DetectionSettings | null>(null);
  const [errors, setErrors] = useState<Partial<Record<keyof DetectionSettings, string>>>({});
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  useEffect(() => {
    if (settings.data) setDraft(settings.data);
  }, [settings.data]);

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

  if (settings.loading && !settings.data) return <LoadingState label="Loading settings" />;
  if (settings.error) return <ErrorState message={settings.error} onRetry={settings.reload} />;

  return (
    <div className="page">
      <div className="page__bar">
        <p className="page__lede">
          Detection thresholds control how much evidence is required before a rule raises an alert. All values are counts
          and windows in seconds.
        </p>
      </div>

      {notice ? <Notice tone="ok">{notice}</Notice> : null}
      {actionError ? <Notice tone="error">{actionError}</Notice> : null}

      <Panel title="Detection thresholds" className="settings-form">
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
              <dd className="mono">0.1.0</dd>
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
              <dt>Imported event count threshold</dt>
              <dd className="mono">{draft ? formatNumber(draft.bruteForceThreshold) : "\u2014"}</dd>
            </div>
          </dl>
        </div>
      </Panel>
    </div>
  );
}
