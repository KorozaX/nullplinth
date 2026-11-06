import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { Upload, X } from "lucide-react";

import { api } from "../services/api";
import type { ImportPreview } from "../types/contracts";
import { errorMessage } from "../lib/async";
import { fileName, formatNumber } from "../lib/format";
import { captureSuccessMessage, importSuccessMessage } from "../lib/importResults";
import { classifyFile } from "../lib/importRouting";
import { Button, IconButton } from "./ui/Button";
import { ConfidenceChip } from "./ui/Badge";
import { ErrorState, LoadingState, Notice } from "./ui/Feedback";

export interface ImportOutcome {
  kind: "events" | "packets";
  count: number;
  skipped: number;
  message: string;
}

export interface ImportPreviewDialogProps {
  path: string | null;
  onClose: () => void;
  onImported: (outcome: ImportOutcome) => void;
}

export function ImportPreviewDialog({ path, onClose, onImported }: ImportPreviewDialogProps) {
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);

  useEffect(() => {
    if (!path) {
      setPreview(null);
      setError(null);
      setImportError(null);
      return;
    }
    let cancelled = false;
    setPreview(null);
    setError(null);
    setImportError(null);
    setLoading(true);
    api
      .previewImport(path)
      .then((result) => {
        if (!cancelled) setPreview(result);
      })
      .catch((cause: unknown) => {
        if (!cancelled) setError(errorMessage(cause));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [path]);

  if (!path) return null;

  const kind = classifyFile(path);

  async function startImport() {
    if (!path) return;
    setImporting(true);
    setImportError(null);
    try {
      if (kind === "pcap") {
        const capture = await api.importPcap(path);
        onImported({
          kind: "packets",
          count: capture.packetCount,
          skipped: 0,
          message: captureSuccessMessage(capture.name, capture.packetCount),
        });
      } else {
        const result = await api.importFile({ path });
        onImported({
          kind: "events",
          count: result.imported,
          skipped: result.skipped,
          message: importSuccessMessage(result.imported, result.skipped),
        });
      }
    } catch (cause) {
      setImportError(errorMessage(cause));
    } finally {
      setImporting(false);
    }
  }

  return createPortal(
    <div
      className="overlay overlay--center"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !importing) onClose();
      }}
    >
      <div className="wizard" role="dialog" aria-modal="true" aria-labelledby="import-preview-title" data-testid="import-preview">
        <header className="wizard__head">
          <div>
            <h2 className="wizard__title" id="import-preview-title">
              {kind === "pcap" ? "Packet capture preview" : "Import preview"}
            </h2>
            <p className="wizard__subtitle">
              Step 1 of 2 \u00B7 Confirm what was detected before importing
            </p>
          </div>
          <IconButton icon={X} label="Close import preview" onClick={onClose} disabled={importing} />
        </header>
        <div className="wizard__body">
          <div className="import-preview__meta">
            <span className="import-preview__file">{fileName(path)}</span>
            {preview ? <span className="chip chip--status-new">{preview.formatLabel}</span> : null}
            {preview ? <ConfidenceChip confidence={preview.confidence} /> : null}
            {preview && preview.estimatedRecords !== null && preview.estimatedRecords !== undefined ? (
              <span className="chip chip--other">~{formatNumber(preview.estimatedRecords)} records</span>
            ) : null}
            <span className="chip chip--other">{kind === "pcap" ? "PCAP" : "LOG"}</span>
          </div>

          {loading ? (
            <LoadingState label="Detecting format" />
          ) : error ? (
            kind === "pcap" ? (
              // A capture is binary: never let a preview failure block the import itself.
              <Notice tone="info">
                Format preview unavailable ({error}). The capture will still be parsed directly when
                you import it.
              </Notice>
            ) : (
              <ErrorState title="Could not read this file" message={error} onRetry={() => setPreview(null)} />
            )
          ) : preview ? (
            <>
              <p className="wizard__help">
                The detector recognized <strong>{preview.formatLabel}</strong> with {preview.confidence} confidence.
                Nothing has been stored yet.
              </p>
              {preview.warnings.length > 0 ? (
                <div>
                  <h3 className="subhead">Warnings</h3>
                  <ul className="warning-list">
                    {preview.warnings.map((warning) => (
                      <li key={warning}>{warning}</li>
                    ))}
                  </ul>
                </div>
              ) : null}
              {preview.sampleLines.length > 0 ? (
                <div>
                  <h3 className="subhead">Sample lines</h3>
                  <div className="import-preview__lines">{preview.sampleLines.join("\n")}</div>
                </div>
              ) : null}
              {importError ? <Notice tone="error">{importError}</Notice> : null}
            </>
          ) : null}
        </div>
        <footer className="wizard__foot">
          <span className="wizard__step">{kind === "pcap" ? "Packet import" : "Log import"}</span>
          <div className="wizard__foot-end">
            <Button variant="ghost" onClick={onClose} disabled={importing}>
              Cancel
            </Button>
            <Button
              icon={Upload}
              variant="primary"
              onClick={startImport}
              disabled={importing || loading || (preview === null && kind !== "pcap")}
            >
              {importing ? "Importing" : "Import"}
            </Button>
          </div>
        </footer>
      </div>
    </div>,
    document.body,
  );
}
