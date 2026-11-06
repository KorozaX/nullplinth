import { useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../services/api", () => ({
  api: { previewCsv: vi.fn(), importFile: vi.fn() },
}));
vi.mock("../lib/dialog", () => ({
  pickFile: vi.fn(),
  pickSavePath: vi.fn(),
}));

import { CsvWizard } from "./CsvWizard";
import { api } from "../services/api";
import { pickFile } from "../lib/dialog";
import { ModeProvider } from "../context/ModeContext";
import type { CsvPreview, ImportResult } from "../types/contracts";

const preview: CsvPreview = {
  columns: ["event_time", "src", "dst", "msg"],
  rows: [
    ["2026-01-01T00:00:00Z", "10.0.0.5", "10.0.0.9", "hello"],
    ["2026-01-01T00:00:01Z", "10.0.0.6", "10.0.0.9", "world"],
  ],
  detectedDelimiter: ",",
  hasHeader: true,
};

function Harness({ onImported }: { onImported: (result: ImportResult) => void }) {
  const [open, setOpen] = useState(true);
  return (
    <ModeProvider>
      <CsvWizard open={open} onClose={() => setOpen(false)} onImported={onImported} />
    </ModeProvider>
  );
}

async function reachPreview(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: "Choose CSV file" }));
  await screen.findByRole("table", { name: "CSV preview" });
}

async function reachMapping(user: ReturnType<typeof userEvent.setup>) {
  await reachPreview(user);
  await user.click(screen.getByRole("button", { name: "Continue to mapping" }));
}

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  vi.mocked(pickFile).mockResolvedValue("/tmp/events.csv");
  vi.mocked(api.previewCsv).mockResolvedValue(preview);
});

describe("CsvWizard", () => {
  it("renders the backend preview and navigates steps", async () => {
    const user = userEvent.setup();
    render(<Harness onImported={() => undefined} />);

    await reachPreview(user);

    expect(vi.mocked(api.previewCsv)).toHaveBeenCalledWith("/tmp/events.csv");
    expect(screen.getByRole("columnheader", { name: "event_time" })).toBeInTheDocument();
    expect(screen.getByText(/delimiter: comma/)).toBeInTheDocument();
    expect(screen.getAllByText(/Step 2 of 3/).length).toBeGreaterThan(0);

    await user.click(screen.getByRole("button", { name: "Back" }));
    expect(screen.getByRole("button", { name: "Choose CSV file" })).toBeInTheDocument();
    expect(screen.getAllByText(/Step 1 of 3/).length).toBeGreaterThan(0);
  });

  it("re-derives columns when the header toggle is turned off", async () => {
    const user = userEvent.setup();
    render(<Harness onImported={() => undefined} />);
    await reachPreview(user);

    await user.click(screen.getByLabelText("First row contains column names"));

    expect(screen.getByRole("columnheader", { name: "column_1" })).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: "event_time" })).not.toBeInTheDocument();
  });

  it("blocks the import until a timestamp and one field are mapped", async () => {
    const user = userEvent.setup();
    render(<Harness onImported={() => undefined} />);
    await reachMapping(user);

    expect(screen.getByRole("button", { name: "Import CSV" })).toBeDisabled();
    expect(screen.getByText("Map the timestamp column before importing.")).toBeInTheDocument();

    await user.selectOptions(screen.getByRole("combobox", { name: "Timestamp column" }), "event_time");
    expect(screen.getByRole("button", { name: "Import CSV" })).toBeDisabled();
    expect(screen.getByText("Map at least one other field so the events carry meaning.")).toBeInTheDocument();

    await user.selectOptions(screen.getByRole("combobox", { name: "Message" }), "msg");
    expect(screen.getByRole("button", { name: "Import CSV" })).toBeEnabled();
  });

  it("imports with the built mapping and shows the summary", async () => {
    const user = userEvent.setup();
    const onImported = vi.fn();
    vi.mocked(api.importFile).mockResolvedValue({
      datasetId: 1,
      imported: 120,
      skipped: 3,
      warnings: ["record 4: unparsable timestamp"],
      durationMs: 250,
    });

    render(<Harness onImported={onImported} />);
    await reachMapping(user);

    await user.selectOptions(screen.getByRole("combobox", { name: "Timestamp column" }), "event_time");
    await user.selectOptions(screen.getByRole("combobox", { name: "Source IP" }), "src");
    await user.selectOptions(screen.getByRole("combobox", { name: "Destination IP" }), "dst");
    await user.click(screen.getByRole("button", { name: "Import CSV" }));

    expect(await screen.findByText(/Imported 120 events/)).toBeInTheDocument();
    expect(screen.getByText(/record 4: unparsable timestamp/)).toBeInTheDocument();
    expect(vi.mocked(api.importFile)).toHaveBeenCalledWith(
      expect.objectContaining({
        path: "/tmp/events.csv",
        sourceType: "csv",
        csv: expect.objectContaining({
          timestampColumn: "event_time",
          hasHeader: true,
          delimiter: ",",
          columnMap: expect.objectContaining({ srcIp: "src", dstIp: "dst" }),
        }),
      }),
    );

    await user.click(screen.getByRole("button", { name: "Done" }));
    expect(onImported).toHaveBeenCalledWith(expect.objectContaining({ imported: 120 }));
  });
});
