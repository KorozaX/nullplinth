import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Upload } from "lucide-react";

import { api } from "../services/api";
import { useWorkspace } from "../context/WorkspaceContext";
import { errorMessage } from "../lib/async";
import { pickFile } from "../lib/dialog";
import { fileName } from "../lib/format";
import { demoSuccessMessage, importSuccessMessage } from "../lib/importResults";
import { ACCEPTED_LABEL, classifyFile, fileExtension, LOG_FILE_FILTERS } from "../lib/importRouting";
import { Toast } from "./ui/Toast";
import { CsvWizard } from "./CsvWizard";
import { ImportPreviewDialog } from "./ImportPreviewDialog";
import type { ImportOutcome } from "./ImportPreviewDialog";

interface ImportContextValue {
  beginImport: (path?: string | null) => void;
  importDemo: () => Promise<void>;
}

const ImportContext = createContext<ImportContextValue | null>(null);

export function useImport(): ImportContextValue {
  const context = useContext(ImportContext);
  if (!context) throw new Error("useImport must be used inside ImportProvider");
  return context;
}

interface Toast {
  tone: "ok" | "error";
  message: string;
}

const DROP_TYPES = ["CSV", "TSV", "JSON", "NDJSON", "LOG", "PCAP", "PCAPNG"];

export function ImportProvider({ children }: { children: ReactNode }) {
  const { refresh } = useWorkspace();
  const [csvPath, setCsvPath] = useState<string | null>(null);
  const [previewPath, setPreviewPath] = useState<string | null>(null);
  const [toast, setToast] = useState<Toast | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [dragPaths, setDragPaths] = useState<string[]>([]);
  const queueRef = useRef<string[]>([]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 9000);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const route = useCallback((path: string) => {
    const kind = classifyFile(path);
    if (kind === "csv") {
      setCsvPath(path);
      return;
    }
    if (kind === "log" || kind === "pcap") {
      setPreviewPath(path);
      return;
    }
    const extension = fileExtension(path);
    setToast({
      tone: "error",
      message:
        "Unsupported file type" +
        (extension.length > 0 ? " \u201C." + extension + "\u201D" : "") +
        ". Accepted: " +
        ACCEPTED_LABEL +
        ".",
    });
  }, []);

  const beginImport = useCallback(
    async (path?: string | null) => {
      if (path) {
        route(path);
        return;
      }
      const selected = await pickFile("Import data", LOG_FILE_FILTERS);
      if (selected) route(selected);
    },
    [route],
  );

  const importDemo = useCallback(async () => {
    try {
      const result = await api.loadDemoData();
      setToast({ tone: "ok", message: demoSuccessMessage(result.imported) });
      refresh();
    } catch (cause) {
      setToast({ tone: "error", message: errorMessage(cause) });
    }
  }, [refresh]);

  const startNext = useCallback(() => {
    const next = queueRef.current.shift();
    if (next) route(next);
  }, [route]);

  const finish = useCallback(
    (outcome: ImportOutcome) => {
      setToast({ tone: "ok", message: outcome.message });
      refresh();
      setCsvPath(null);
      setPreviewPath(null);
      startNext();
    },
    [refresh, startNext],
  );

  const closeCsv = useCallback(() => {
    setCsvPath(null);
    startNext();
  }, [startNext]);

  const closePreview = useCallback(() => {
    setPreviewPath(null);
    startNext();
  }, [startNext]);

  useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | null = null;
    void (async () => {
      try {
        const { getCurrentWebview } = await import("@tauri-apps/api/webview");
        const stop = await getCurrentWebview().onDragDropEvent((event: { payload: unknown }) => {
          if (cancelled) return;
          const payload = event.payload as { type?: string; paths?: string[] } | null;
          if (!payload || typeof payload.type !== "string") return;
          if (payload.type === "enter" || payload.type === "over") {
            setDragActive(true);
            setDragPaths(payload.paths ?? []);
            return;
          }
          if (payload.type === "leave") {
            setDragActive(false);
            setDragPaths([]);
            return;
          }
          if (payload.type !== "drop") return;
          setDragActive(false);
          setDragPaths([]);
          const droppedPaths = payload.paths ?? [];
          const supported = droppedPaths.filter((candidate) => classifyFile(candidate) !== "unsupported");
          const rejected = droppedPaths.filter((candidate) => classifyFile(candidate) === "unsupported");
          if (rejected.length > 0) {
            setToast({
              tone: "error",
              message:
                "Ignored " +
                (rejected.length === 1 ? "an unsupported file: " : "unsupported files: ") +
                rejected.map((candidate) => fileName(candidate)).join(", ") +
                ". Accepted: " +
                ACCEPTED_LABEL +
                ".",
            });
          }
          if (supported.length === 0) return;
          if (supported.length > 1) {
            setToast({
              tone: "ok",
              message: supported.length + " files dropped; importing them one at a time.",
            });
          }
          queueRef.current = supported.slice(1);
          route(supported[0]);
        });
        if (cancelled) stop();
        else unlisten = stop;
      } catch {
        // Not running inside Tauri (browser preview or tests); drag-and-drop stays off.
      }
    })();
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, [route]);

  const onCsvImported = useCallback(
    (result: { imported: number; skipped: number }) => {
      finish({
        kind: "events",
        count: result.imported,
        skipped: result.skipped,
        message: importSuccessMessage(result.imported, result.skipped),
      });
    },
    [finish],
  );

  const contextValue = useMemo<ImportContextValue>(() => ({ beginImport, importDemo }), [beginImport, importDemo]);

  return (
    <ImportContext.Provider value={contextValue}>
      {children}

      <CsvWizard open={csvPath !== null} initialPath={csvPath} onClose={closeCsv} onImported={onCsvImported} />
      <ImportPreviewDialog path={previewPath} onClose={closePreview} onImported={finish} />

      {dragActive ? (
        <div className="dropzone" data-testid="dropzone" aria-live="polite">
          <div className="dropzone__panel">
            <Upload className="dropzone__icon" size={28} aria-hidden="true" />
            <p className="dropzone__title">Drop files to import</p>
            <p className="dropzone__hint">
              Files are read locally and nothing leaves this machine. Drop several files to import them one at a time.
            </p>
            <div className="dropzone__types">
              {DROP_TYPES.map((type) => (
                <span className="chip chip--other" key={type}>
                  {type}
                </span>
              ))}
            </div>
            {dragPaths.length > 0 ? (
              <p className="dropzone__files">{dragPaths.map((candidate) => fileName(candidate)).join("  ")}</p>
            ) : null}
          </div>
        </div>
      ) : null}

      {toast ? <Toast tone={toast.tone} message={toast.message} onDismiss={() => setToast(null)} /> : null}
    </ImportContext.Provider>
  );
}
