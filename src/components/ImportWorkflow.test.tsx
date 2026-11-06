import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const webviewMock = vi.hoisted(() => ({
  handler: null as ((event: { payload: unknown }) => void) | null,
  onDragDropEvent: vi.fn(),
  getCurrentWebview: vi.fn(),
}));

vi.mock("../services/api", () => ({
  api: {
    previewCsv: vi.fn(),
    previewImport: vi.fn(),
    importFile: vi.fn(),
    importPcap: vi.fn(),
  },
}));
vi.mock("../lib/dialog", () => ({
  pickFile: vi.fn(),
  pickSavePath: vi.fn(),
}));
vi.mock("@tauri-apps/api/webview", () => ({
  getCurrentWebview: webviewMock.getCurrentWebview,
}));

import { ImportProvider, useImport } from "./ImportWorkflow";
import { api } from "../services/api";
import { ModeProvider } from "../context/ModeContext";
import { WorkspaceProvider } from "../context/WorkspaceContext";

function Triggers() {
  const { beginImport } = useImport();
  return (
    <div>
      <button type="button" onClick={() => void beginImport("/tmp/events.log")}>
        import log
      </button>
      <button type="button" onClick={() => void beginImport("/tmp/data.csv")}>
        import csv
      </button>
      <button type="button" onClick={() => void beginImport("/tmp/capture.pcap")}>
        import pcap
      </button>
    </div>
  );
}

function renderWorkflow() {
  return render(
    <WorkspaceProvider>
      <ModeProvider>
        <ImportProvider>
          <Triggers />
        </ImportProvider>
      </ModeProvider>
    </WorkspaceProvider>,
  );
}

const preview = {
  format: "suricata",
  formatLabel: "Suricata EVE JSON",
  confidence: "high",
  sampleLines: ['{"event_type":"alert"}'],
  estimatedRecords: 10,
  warnings: ["1 line ignored"],
};

beforeEach(() => {
  vi.clearAllMocks();
  webviewMock.handler = null;
  webviewMock.onDragDropEvent.mockReset();
  webviewMock.onDragDropEvent.mockImplementation((callback: (event: { payload: unknown }) => void) => {
    webviewMock.handler = callback;
    return Promise.resolve(() => undefined);
  });
  webviewMock.getCurrentWebview.mockReset();
  webviewMock.getCurrentWebview.mockReturnValue({ onDragDropEvent: webviewMock.onDragDropEvent });
  vi.mocked(api.previewImport).mockResolvedValue(preview);
  vi.mocked(api.previewCsv).mockResolvedValue({
    columns: ["ts", "src"],
    rows: [["2026-01-01T00:00:00Z", "10.0.0.5"]],
    detectedDelimiter: ",",
    hasHeader: true,
    suggestedMapping: {},
    estimatedRows: 1,
  });
  vi.mocked(api.importFile).mockResolvedValue({
    datasetId: 1,
    imported: 1,
    skipped: 0,
    warnings: [],
    durationMs: 4,
  });
});

describe("ImportProvider", () => {
  it("routes a log file through previewImport and reports the real count", async () => {
    const user = userEvent.setup();
    renderWorkflow();

    await user.click(screen.getByRole("button", { name: "import log" }));

    expect(vi.mocked(api.previewImport)).toHaveBeenCalledWith("/tmp/events.log");
    expect(await screen.findByTestId("import-preview")).toBeInTheDocument();
    expect((await screen.findAllByText("Suricata EVE JSON")).length).toBeGreaterThan(0);
    expect(screen.getByText("high")).toBeInTheDocument();
    expect(screen.getByText('{"event_type":"alert"}')).toBeInTheDocument();
    expect(screen.getByText("1 line ignored")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Import" }));

    expect(vi.mocked(api.importFile)).toHaveBeenCalledWith({ path: "/tmp/events.log" });
    expect(await screen.findByText("Successfully imported 1 event into NULLPLINTH.")).toBeInTheDocument();
    expect(screen.queryByTestId("import-preview")).not.toBeInTheDocument();
  });

  it("routes a CSV file into the mapping wizard", async () => {
    const user = userEvent.setup();
    renderWorkflow();

    await user.click(screen.getByRole("button", { name: "import csv" }));

    expect(await screen.findByTestId("csv-wizard")).toBeInTheDocument();
    await waitFor(() => expect(vi.mocked(api.previewCsv)).toHaveBeenCalledWith("/tmp/data.csv"));

    await user.click(screen.getByRole("button", { name: "Close CSV wizard" }));
    expect(screen.queryByTestId("csv-wizard")).not.toBeInTheDocument();
  });

  it("shows the drag overlay, routes dropped files and ignores unsupported types", async () => {
    renderWorkflow();
    await waitFor(() => expect(webviewMock.handler).not.toBeNull());

    act(() => {
      webviewMock.handler?.({ payload: { type: "enter", paths: ["/tmp/a.log"] } });
    });
    expect(await screen.findByTestId("dropzone")).toBeInTheDocument();
    expect(screen.getByText("a.log")).toBeInTheDocument();

    act(() => {
      webviewMock.handler?.({ payload: { type: "drop", paths: ["/tmp/a.log", "/tmp/b.exe"] } });
    });

    expect(await screen.findByTestId("import-preview")).toBeInTheDocument();
    expect(vi.mocked(api.previewImport)).toHaveBeenCalledWith("/tmp/a.log");
    expect(screen.queryByTestId("dropzone")).not.toBeInTheDocument();
    expect(screen.getByText(/Ignored an unsupported file: b.exe/)).toBeInTheDocument();
  });

  it("rejects a drop that contains only unsupported files", async () => {
    renderWorkflow();
    await waitFor(() => expect(webviewMock.handler).not.toBeNull());

    act(() => {
      webviewMock.handler?.({ payload: { type: "drop", paths: ["/tmp/tool.exe"] } });
    });

    expect(await screen.findByText(/Ignored an unsupported file: tool.exe/)).toBeInTheDocument();
    expect(screen.queryByTestId("import-preview")).not.toBeInTheDocument();
  });

  it("still imports a capture when the format preview fails", async () => {
    vi.mocked(api.previewImport).mockRejectedValueOnce(
      new Error("io: stream did not contain valid UTF-8"),
    );
    vi.mocked(api.importPcap).mockResolvedValueOnce({
      id: 1,
      name: "capture.pcap",
      fileName: "capture.pcap",
      fileHash: null,
      fileSize: null,
      linkType: "IEEE 802.11 (105)",
      packetCount: 42,
      importedAt: 0,
    });
    const user = userEvent.setup();
    renderWorkflow();
    await user.click(screen.getByRole("button", { name: "import pcap" }));
    await waitFor(() => expect(screen.getByText(/Format preview unavailable/i)).toBeInTheDocument());

    const importButton = screen.getByRole("button", { name: "Import" });
    expect(importButton).toBeEnabled();
    await user.click(importButton);
    await waitFor(() => expect(api.importPcap).toHaveBeenCalledWith("/tmp/capture.pcap"));
  });
});
