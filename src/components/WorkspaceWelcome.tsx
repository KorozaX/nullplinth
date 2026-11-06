import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { createPortal } from "react-dom";
import { ArchiveRestore, ShieldCheck } from "lucide-react";

import { api } from "../services/api";
import type { WorkspaceClearResult, WorkspaceState } from "../types/contracts";
import { errorMessage } from "../lib/async";
import { pickSavePath } from "../lib/dialog";
import { formatNumber } from "../lib/format";
import { clearedWorkspaceMessage } from "../lib/importResults";
import { useWorkspace } from "../context/WorkspaceContext";
import { Button } from "./ui/Button";
import { Notice } from "./ui/Feedback";

type Phase = "hidden" | "welcome" | "confirm" | "clearing" | "cleared";

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <span className="ws-stat">
      <span className="ws-stat__value">{formatNumber(value)}</span>
      <span className="ws-stat__label">{label}</span>
    </span>
  );
}

export function WorkspaceGate({ children }: { children: ReactNode }) {
  const { refresh } = useWorkspace();
  const [workspace, setWorkspace] = useState<WorkspaceState | null>(null);
  const [phase, setPhase] = useState<Phase>("hidden");
  const [dontAsk, setDontAsk] = useState(false);
  const [backup, setBackup] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cleared, setCleared] = useState<WorkspaceClearResult | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.workspaceState(), api.getPreferences()])
      .then(([workspaceState, appPreferences]) => {
        if (cancelled) return;
        setWorkspace(workspaceState);
        if (workspaceState.hasData && appPreferences.startupBehavior !== "resume") {
          setPhase("welcome");
        }
      })
      .catch(() => {
        // A missing workspace command must not block the app.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function rememberPreference() {
    if (!dontAsk) return;
    try {
      await api.savePreferences({ startupBehavior: "resume" });
    } catch {
      // The choice still applies for this session.
    }
  }

  async function resume() {
    setBusy(true);
    await rememberPreference();
    setBusy(false);
    setPhase("hidden");
  }

  async function clearWorkspace() {
    setBusy(true);
    setError(null);
    setPhase("clearing");
    try {
      let backupPath: string | null = null;
      if (backup) {
        backupPath = await pickSavePath("nullplinth-backup.db", [{ name: "Database backup", extensions: ["db"] }]);
        if (!backupPath) {
          setError("Backup cancelled, so the workspace was not cleared.");
          setPhase("confirm");
          return;
        }
      }
      const result = await api.clearWorkspace(backupPath);
      setCleared(result);
      setPhase("cleared");
      refresh();
      await rememberPreference();
    } catch (cause) {
      setError(errorMessage(cause));
      setPhase("confirm");
    } finally {
      setBusy(false);
    }
  }

  const modal =
    phase === "hidden"
      ? null
      : createPortal(
          <div className="overlay overlay--center">
            <div
              className="workspace-modal"
              role="dialog"
              aria-modal="true"
              aria-labelledby="workspace-welcome-title"
              data-testid="workspace-welcome"
            >
              {phase === "cleared" && cleared ? (
                <>
                  <header className="workspace-modal__head">
                    <h2 className="workspace-modal__title" id="workspace-welcome-title">
                      Workspace cleared
                    </h2>
                    <p className="workspace-modal__lede">{clearedWorkspaceMessage(cleared.datasets, cleared.events)}</p>
                  </header>
                  <div className="workspace-modal__body">
                    <p className="wizard__help">
                      {cleared.backupPath
                        ? "A backup of the database was written to " + cleared.backupPath + "."
                        : "No backup was written."}
                    </p>
                    <p className="wizard__help">Your original imported files were never modified.</p>
                  </div>
                  <div className="workspace-modal__foot">
                    <Button variant="primary" onClick={() => setPhase("hidden")}>
                      Close
                    </Button>
                  </div>
                </>
              ) : phase === "confirm" || phase === "clearing" ? (
                <>
                  <header className="workspace-modal__head">
                    <h2 className="workspace-modal__title" id="workspace-welcome-title">
                      Start a fresh workspace?
                    </h2>
                    <p className="workspace-modal__lede">
                      This removes every imported dataset, capture, alert and investigation from the local database.
                      Your original imported files remain untouched on disk.
                    </p>
                  </header>
                  <div className="workspace-modal__body">
                    {workspace ? (
                      <div className="workspace-stats">
                        <Stat label="Datasets" value={workspace.datasets} />
                        <Stat label="Events" value={workspace.events} />
                        <Stat label="Captures" value={workspace.captures} />
                        <Stat label="Alerts" value={workspace.alerts} />
                        <Stat label="Cases" value={workspace.investigations} />
                      </div>
                    ) : null}
                    <label className="checkbox">
                      <input
                        type="checkbox"
                        checked={backup}
                        disabled={busy}
                        onChange={(event) => setBackup(event.target.checked)}
                      />
                      Save a backup of the local database before clearing
                    </label>
                    {error ? <Notice tone="error">{error}</Notice> : null}
                  </div>
                  <div className="workspace-modal__foot">
                    <Button variant="ghost" onClick={() => setPhase("welcome")} disabled={busy}>
                      Cancel
                    </Button>
                    <Button variant="danger" onClick={() => void clearWorkspace()} disabled={busy}>
                      {phase === "clearing" ? "Clearing" : "Clear workspace"}
                    </Button>
                  </div>
                </>
              ) : (
                <>
                  <header className="workspace-modal__head">
                    <h2 className="workspace-modal__title" id="workspace-welcome-title">
                      Welcome back to NULLPLINTH.
                    </h2>
                    <p className="workspace-modal__lede">How would you like to start your next session?</p>
                  </header>
                  <div className="workspace-modal__body">
                    {workspace ? (
                      <div className="workspace-stats">
                        <Stat label="Datasets" value={workspace.datasets} />
                        <Stat label="Events" value={workspace.events} />
                        <Stat label="Packets" value={workspace.packets} />
                        <Stat label="Alerts" value={workspace.alerts} />
                        <Stat label="Cases" value={workspace.investigations} />
                      </div>
                    ) : null}
                    <p className="wizard__help">
                      Resume continues with everything already stored on this machine. Start Fresh clears the local
                      workspace first.
                    </p>
                    <label className="checkbox">
                      <input
                        type="checkbox"
                        checked={dontAsk}
                        onChange={(event) => setDontAsk(event.target.checked)}
                      />
                      Do not ask again, resume automatically
                    </label>
                  </div>
                  <div className="workspace-modal__foot">
                    <Button variant="ghost" icon={ArchiveRestore} onClick={() => setPhase("confirm")}>
                      Start Fresh
                    </Button>
                    <Button variant="primary" icon={ShieldCheck} onClick={() => void resume()} disabled={busy}>
                      Resume
                    </Button>
                  </div>
                </>
              )}
            </div>
          </div>,
          document.body,
        );

  return (
    <>
      {children}
      {modal}
    </>
  );
}
