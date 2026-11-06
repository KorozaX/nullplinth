import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { createPortal } from "react-dom";
import { ArrowLeft, ArrowRight, FileSpreadsheet, Upload, X } from "lucide-react";

import { api } from "../services/api";
import type { CsvPreview, ImportProgress, ImportResult } from "../types/contracts";
import { useMode } from "../context/ModeContext";
import { errorMessage } from "../lib/async";
import { pickFile } from "../lib/dialog";
import { fileName, formatDuration, formatJson, formatNumber } from "../lib/format";
import {
  buildCsvMapping,
  CSV_FIELDS,
  delimiterLabel,
  derivedPreview,
  mappedCount,
  TIMESTAMP_FORMATS,
  validateDraft,
} from "../lib/csvMapping";
import type { CsvWizardDraft } from "../lib/csvMapping";
import { inspectSamples, suggestedDraft } from "../lib/csvValidation";
import { importSuccessMessage } from "../lib/importResults";
import { Button, IconButton } from "./ui/Button";
import { Field, Select, TextInput } from "./ui/Field";
import { LoadingState, Notice } from "./ui/Feedback";

type Step = "file" | "preview" | "mapping" | "importing" | "done";

const STEP_LABEL: Record<Step, string> = {
  file: "Step 1 of 3 \u00B7 Source file",
  preview: "Step 2 of 3 \u00B7 Preview",
  mapping: "Step 3 of 3 \u00B7 Column mapping",
  importing: "Step 3 of 3 \u00B7 Importing",
  done: "Import complete",
};

export interface CsvWizardProps {
  open: boolean;
  onClose: () => void;
  onImported: (result: ImportResult) => void;
  /** When set, the wizard opens straight into the preview for this file. */
  initialPath?: string | null;
}

export function CsvWizard({ open, onClose, onImported, initialPath = null }: CsvWizardProps) {
  const { isAnalyst } = useMode();
  const dialogRef = useRef<HTMLDivElement | null>(null);

  const [step, setStep] = useState<Step>("file");
  const [path, setPath] = useState<string | null>(null);
  const [preview, setPreview] = useState<CsvPreview | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [draft, setDraft] = useState<CsvWizardDraft | null>(null);
  const [suggestedCount, setSuggestedCount] = useState(0);
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [progress, setProgress] = useState<ImportProgress | null>(null);
  const [result, setResult] = useState<ImportResult | null>(null);

  const loadPreview = useCallback(async (selected: string) => {
    setPath(selected);
    setPreview(null);
    setPreviewError(null);
    setPreviewLoading(true);
    try {
      const loaded = await api.previewCsv(selected);
      setPreview(loaded);
      const nextDraft = suggestedDraft(loaded);
      setDraft(nextDraft);
      setSuggestedCount(Object.keys(loaded.suggestedMapping ?? {}).length);
      setStep("preview");
    } catch (cause) {
      setPreviewError(errorMessage(cause));
      setStep("file");
    } finally {
      setPreviewLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!open) return;
    setStep("file");
    setPath(null);
    setPreview(null);
    setPreviewError(null);
    setDraft(null);
    setSuggestedCount(0);
    setImporting(false);
    setImportError(null);
    setProgress(null);
    setResult(null);
    dialogRef.current?.focus();
  }, [open]);

  useEffect(() => {
    if (!open || !initialPath) return;
    void loadPreview(initialPath);
  }, [open, initialPath, loadPreview]);

  useEffect(() => {
    if (!open) return;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && step !== "importing") onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [open, step, onClose]);

  useEffect(() => {
    if (!open || step !== "importing") return;
    let cancelled = false;
    let stop: (() => void) | null = null;
    void (async () => {
      try {
        const { listen } = await import("@tauri-apps/api/event");
        const unlisten = await listen<ImportProgress>("import-progress", (event) => {
          if (!cancelled) setProgress(event.payload);
        });
        if (cancelled) unlisten();
        else stop = unlisten;
      } catch {
        // The event bridge is unavailable outside Tauri; the wizard still finishes.
      }
    })();
    return () => {
      cancelled = true;
      if (stop) stop();
    };
  }, [open, step]);

  const columns = preview && draft ? derivedPreview(preview, draft.hasHeader) : null;
  const effectiveColumns = columns ? columns.columns : [];
  const problem = draft && preview ? validateDraft(draft, effectiveColumns) : null;
  const inspection = preview && draft ? inspectSamples(preview, draft) : null;
  const allTimestampsBad =
    draft !== null &&
    draft.timestampColumn.length > 0 &&
    inspection !== null &&
    inspection.sampledRows > 0 &&
    inspection.unparsableTimestamps === inspection.sampledRows;
  const sampleBlocking = allTimestampsBad
    ? "Every sample row has an unparsable timestamp. Choose another column or timestamp format."
    : null;
  const importBlocked = problem !== null || sampleBlocking !== null;

  function patchDraft(patch: Partial<CsvWizardDraft>) {
    setDraft((current) => (current ? { ...current, ...patch } : current));
  }

  function setColumn(fieldKey: string, column: string) {
    setDraft((current) =>
      current ? { ...current, columnMap: { ...current.columnMap, [fieldKey]: column } } : current,
    );
  }

  async function chooseFile() {
    const selected = await pickFile("Choose a CSV file", [{ name: "CSV files", extensions: ["csv", "tsv"] }]);
    if (!selected) return;
    await loadPreview(selected);
  }

  async function startImport() {
    if (!path || !preview || !draft) return;
    if (validateDraft(draft, effectiveColumns) !== null || sampleBlocking !== null) return;
    setImportError(null);
    setProgress(null);
    setResult(null);
    setImporting(true);
    setStep("importing");
    const mapping = buildCsvMapping(preview, draft);
    try {
      const outcome = await api.importFile({
        path,
        name: fileName(path).replace(/\.[^.]+$/, ""),
        sourceType: "csv",
        csv: mapping,
      });
      setResult(outcome);
      setStep("done");
    } catch (cause) {
      setImportError(errorMessage(cause));
      setStep("mapping");
    } finally {
      setImporting(false);
    }
  }

  function reset() {
    setStep("file");
    setPath(null);
    setPreview(null);
    setDraft(null);
    setResult(null);
    setProgress(null);
    setImportError(null);
  }

  if (!open) return null;

  const previewTable = columns ? (
    <div className="wizard__preview">
      <table aria-label="CSV preview">
        <thead>
          <tr>
            {columns.columns.map((column, index) => (
              <th key={column + "-" + String(index)} scope="col">
                {column}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {columns.rows.slice(0, 50).map((row, rowIndex) => (
            <tr key={rowIndex}>
              {columns.columns.map((_column, cellIndex) => (
                <td key={cellIndex}>{row[cellIndex] ?? ""}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : null;

  let body: ReactNode = null;
  let footer: ReactNode = null;

  if (step === "file") {
    body = (
      <>
        <p className="wizard__help">
          Choose a comma or tab separated log file. Nothing is uploaded: the file is read locally, shown to you first,
          and only stored after you confirm the column mapping.
        </p>
        {previewError ? <Notice tone="error">{previewError}</Notice> : null}
        {previewLoading ? (
          <LoadingState label="Reading file" />
        ) : path ? (
          <div className="wizard__source">
            <FileSpreadsheet size={16} aria-hidden="true" />
            <span className="wizard__file">{path}</span>
          </div>
        ) : (
          <div className="wizard__source">No file selected yet.</div>
        )}
        <div className="toolbar">
          <Button icon={FileSpreadsheet} variant="primary" onClick={chooseFile} disabled={previewLoading}>
            {previewLoading ? "Reading" : "Choose CSV file"}
          </Button>
        </div>
      </>
    );
    footer = (
      <>
        <span className="wizard__step">{STEP_LABEL.file}</span>
        <div className="wizard__foot-end">
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
        </div>
      </>
    );
  } else if (step === "preview" && preview && draft && columns) {
    body = (
      <>
        <p className="wizard__help">
          Check that the columns were split correctly. The first row is treated as column names when the header toggle is
          on; turn it off if your file starts with data instead.
        </p>
        <div className="wizard__meta">
          <span className="wizard__file">{path ? fileName(path) : ""}</span>
          <span className="chip chip--other">delimiter: {delimiterLabel(preview.detectedDelimiter)}</span>
          <span className="chip chip--other">{formatNumber(columns.columns.length)} columns</span>
          <span className="chip chip--other">{formatNumber(columns.rows.length)} sample rows</span>
          {preview.estimatedRows !== null && preview.estimatedRows !== undefined ? (
            <span className="chip chip--status-new">~{formatNumber(preview.estimatedRows)} total rows</span>
          ) : null}
          <label className="checkbox">
            <input
              type="checkbox"
              checked={draft.hasHeader}
              onChange={(event) => patchDraft({ hasHeader: event.target.checked, columnMap: {}, timestampColumn: "" })}
            />
            First row contains column names
          </label>
        </div>
        {previewTable}
        {isAnalyst ? (
          <details className="disclosure">
            <summary>Raw detected preview</summary>
            <pre className="codeblock">
              {formatJson({
                columns: preview.columns,
                detectedDelimiter: preview.detectedDelimiter,
                hasHeader: preview.hasHeader,
                suggestedMapping: preview.suggestedMapping,
                estimatedRows: preview.estimatedRows,
              })}
            </pre>
          </details>
        ) : null}
      </>
    );
    footer = (
      <>
        <span className="wizard__step">{STEP_LABEL.preview}</span>
        <div className="wizard__foot-end">
          <Button icon={ArrowLeft} variant="ghost" onClick={() => setStep("file")}>
            Back
          </Button>
          <Button icon={ArrowRight} onClick={() => setStep("mapping")}>
            Continue to mapping
          </Button>
        </div>
      </>
    );
  } else if (step === "mapping" && preview && draft && columns) {
    body = (
      <>
        <p className="wizard__help">
          Tell the importer which column holds the timestamp and which columns hold each field. Only the timestamp and one
          other field are required; unmapped values are kept in the event's unmapped attributes.
        </p>
        {suggestedCount > 0 ? (
          <Notice tone="info">
            {formatNumber(suggestedCount)} column mappings were suggested from the header names. Adjust anything that looks
            wrong before importing.
          </Notice>
        ) : null}
        {importError ? <Notice tone="error">{importError}</Notice> : null}
        {problem ? <Notice tone="error">{problem}</Notice> : null}
        {sampleBlocking ? <Notice tone="error">{sampleBlocking}</Notice> : null}
        {inspection && inspection.warnings.length > 0 ? (
          <div>
            <h3 className="subhead">Validation warnings</h3>
            <ul className="warning-list">
              {inspection.warnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          </div>
        ) : null}
        <div className="wizard__mapping">
          <Field label="Timestamp column">
            <Select
              aria-label="Timestamp column"
              value={draft.timestampColumn}
              onChange={(event) => patchDraft({ timestampColumn: event.target.value })}
            >
              <option value="">Select a column</option>
              {columns.columns.map((column) => (
                <option key={column} value={column}>
                  {column}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Timestamp format">
            <Select
              aria-label="Timestamp format"
              value={draft.timestampFormat}
              onChange={(event) => patchDraft({ timestampFormat: event.target.value })}
            >
              {TIMESTAMP_FORMATS.map((format) => (
                <option key={format.value} value={format.value}>
                  {format.label}
                </option>
              ))}
            </Select>
          </Field>
          {draft.timestampFormat === "custom" ? (
            <Field label="Timestamp pattern" className="wizard__mapping-wide">
              <TextInput
                aria-label="Timestamp pattern"
                className="input--mono"
                value={draft.customFormat}
                placeholder="%d/%m/%Y %H:%M:%S"
                onChange={(event) => patchDraft({ customFormat: event.target.value })}
              />
            </Field>
          ) : null}
        </div>
        <div className="wizard__mapping">
          {CSV_FIELDS.map((field) => (
            <Field key={field.key} label={field.label}>
              <Select
                aria-label={field.label}
                value={draft.columnMap[field.key] ?? ""}
                onChange={(event) => setColumn(field.key, event.target.value)}
              >
                <option value="">Not mapped</option>
                {columns.columns.map((column) => (
                  <option key={column} value={column}>
                    {column}
                  </option>
                ))}
              </Select>
            </Field>
          ))}
        </div>
        <p className="wizard__help">
          {mappedCount(draft) === 0
            ? "No fields mapped yet."
            : String(mappedCount(draft)) + (mappedCount(draft) === 1 ? " field mapped." : " fields mapped.")}
        </p>
        {isAnalyst ? (
          <details className="disclosure">
            <summary>Raw mapping sent to the importer</summary>
            <pre className="codeblock">{formatJson(buildCsvMapping(preview, draft))}</pre>
          </details>
        ) : null}
      </>
    );
    footer = (
      <>
        <span className="wizard__step">{STEP_LABEL.mapping}</span>
        <div className="wizard__foot-end">
          <Button icon={ArrowLeft} variant="ghost" onClick={() => setStep("preview")} disabled={importing}>
            Back
          </Button>
          <Button icon={Upload} variant="primary" onClick={startImport} disabled={importBlocked || importing}>
            Import CSV
          </Button>
        </div>
      </>
    );
  } else if (step === "importing") {
    const percent =
      progress && progress.total && progress.total > 0
        ? Math.min(100, Math.round((progress.processed / progress.total) * 100))
        : null;
    body = (
      <div className="wizard__progress">
        <p className="wizard__help">{progress ? progress.message ?? progress.phase : "Starting the import."}</p>
        <div
          className="progress__track"
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={percent ?? undefined}
        >
          <div className="progress__fill" style={{ width: (percent === null ? 15 : percent) + "%" }} />
        </div>
        <p className="wizard__help">
          {progress
            ? formatNumber(progress.processed) +
              (progress.total !== null && progress.total !== undefined
                ? " of " + formatNumber(progress.total) + " rows"
                : " rows processed")
            : "Rows are stored in batches of 1000."}
        </p>
      </div>
    );
    footer = (
      <>
        <span className="wizard__step">{STEP_LABEL.importing}</span>
        <div className="wizard__foot-end">
          <Button variant="ghost" disabled>
            Importing
          </Button>
        </div>
      </>
    );
  } else if (step === "done" && result) {
    body = (
      <>
        <div className="wizard__ok">{importSuccessMessage(result.imported, result.skipped)}</div>
        <p className="wizard__help">Finished in {formatDuration(result.durationMs)}.</p>
        {result.warnings.length > 0 ? (
          <>
            <h3 className="subhead">Warnings ({formatNumber(result.warnings.length)})</h3>
            <div className="wizard__warnings">{result.warnings.join("\n")}</div>
          </>
        ) : (
          <p className="wizard__help">No warnings. Every record was normalized.</p>
        )}
      </>
    );
    footer = (
      <>
        <span className="wizard__step">{STEP_LABEL.done}</span>
        <div className="wizard__foot-end">
          <Button variant="ghost" onClick={reset}>
            Import another file
          </Button>
          <Button variant="primary" onClick={() => onImported(result)}>
            Done
          </Button>
        </div>
      </>
    );
  } else {
    body = <p className="wizard__help">Something went wrong in the wizard. Close it and try again.</p>;
    footer = (
      <div className="wizard__foot-end">
        <Button variant="ghost" onClick={onClose}>
          Close
        </Button>
      </div>
    );
  }

  return createPortal(
    <div
      className="overlay overlay--center"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && step !== "importing") onClose();
      }}
    >
      <div
        ref={dialogRef}
        className="wizard"
        role="dialog"
        aria-modal="true"
        aria-labelledby="csv-wizard-title"
        tabIndex={-1}
        data-testid="csv-wizard"
      >
        <header className="wizard__head">
          <div>
            <h2 className="wizard__title" id="csv-wizard-title">
              Import CSV
            </h2>
            <p className="wizard__subtitle">{STEP_LABEL[step]}</p>
          </div>
          <IconButton icon={X} label="Close CSV wizard" onClick={onClose} disabled={step === "importing"} />
        </header>
        <div className="wizard__body">{body}</div>
        <footer className="wizard__foot">{footer}</footer>
      </div>
    </div>,
    document.body,
  );
}
