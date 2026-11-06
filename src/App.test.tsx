import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("./services/api", () => ({
  api: {
    getOverview: vi.fn(),
    listDatasets: vi.fn(),
    deleteDataset: vi.fn(),
    loadDemoData: vi.fn(),
    previewCsv: vi.fn(),
    importFile: vi.fn(),
    searchEvents: vi.fn(),
    getEvent: vi.fn(),
    exportEvents: vi.fn(),
    importPcap: vi.fn(),
    listCaptures: vi.fn(),
    deleteCapture: vi.fn(),
    searchPackets: vi.fn(),
    getPacket: vi.fn(),
    listFlows: vi.fn(),
    getFlowPackets: vi.fn(),
    runDetection: vi.fn(),
    listAlerts: vi.fn(),
    getAlert: vi.fn(),
    updateAlertStatus: vi.fn(),
    createInvestigation: vi.fn(),
    listInvestigations: vi.fn(),
    getInvestigation: vi.fn(),
    updateInvestigation: vi.fn(),
    addInvestigationNote: vi.fn(),
    attachAlertToInvestigation: vi.fn(),
    exportInvestigation: vi.fn(),
    getSettings: vi.fn(),
    saveSettings: vi.fn(),
  },
}));

import { App } from "./App";
import { api } from "./services/api";
import {
  bruteForceAlert,
  defaultSettings,
  demoCapture,
  demoDataset,
  demoInvestigation,
  emptyOverview,
  eventRow,
  flowRow,
  packetRow,
  populatedOverview,
} from "./test/fixtures";

const SECTIONS: ReadonlyArray<{ label: string; marker: string }> = [
  { label: "Overview", marker: "No data imported yet" },
  { label: "Event Explorer", marker: "No events match this search" },
  { label: "Network Analyzer", marker: "No captures imported" },
  { label: "Alerts", marker: "No alerts yet" },
  { label: "Investigations", marker: "No investigations yet" },
  { label: "Data Sources", marker: "No datasets imported" },
  { label: "Settings", marker: "About NULLPLINTH" },
];

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  vi.mocked(api.getOverview).mockResolvedValue(emptyOverview);
  vi.mocked(api.listDatasets).mockResolvedValue([]);
  vi.mocked(api.listCaptures).mockResolvedValue([]);
  vi.mocked(api.searchEvents).mockResolvedValue({ total: 0, events: [], page: 1, pageSize: 50, durationMs: 1 });
  vi.mocked(api.searchPackets).mockResolvedValue({ total: 0, packets: [], page: 1, pageSize: 100, durationMs: 1 });
  vi.mocked(api.listFlows).mockResolvedValue([]);
  vi.mocked(api.listAlerts).mockResolvedValue([]);
  vi.mocked(api.listInvestigations).mockResolvedValue([]);
  vi.mocked(api.getSettings).mockResolvedValue(defaultSettings);
});

describe("App shell", () => {
  it("offers all seven sections and renders each empty state", async () => {
    const user = userEvent.setup();
    render(<App />);

    for (const section of SECTIONS) {
      await user.click(screen.getByRole("button", { name: section.label }));
      expect(await screen.findByRole("heading", { level: 1, name: section.label })).toBeInTheDocument();
      expect(await screen.findByText(section.marker)).toBeInTheDocument();
    }
  });

  it("switches experience mode, persists it and keeps screen state", async () => {
    const user = userEvent.setup();
    vi.mocked(api.searchEvents).mockResolvedValue({
      total: 1,
      events: [eventRow(1)],
      page: 1,
      pageSize: 50,
      durationMs: 2,
    });

    render(<App />);
    await user.click(screen.getByRole("button", { name: "Event Explorer" }));

    const freeText = await screen.findByPlaceholderText("Search messages, hosts, users");
    await user.type(freeText, "failed login");
    expect(await screen.findByRole("columnheader", { name: "Category" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Beginner" }));

    expect(screen.getByRole("button", { name: "Beginner" })).toHaveAttribute("aria-pressed", "true");
    expect(freeText).toHaveValue("failed login");
    expect(window.localStorage.getItem("nullplinth.mode")).toBe("beginner");
    expect(screen.queryByRole("columnheader", { name: "Category" })).not.toBeInTheDocument();
    expect(await screen.findByRole("columnheader", { name: "From" })).toBeInTheDocument();
  });

  it("supports keyboard focus navigation and activation", async () => {
    const user = userEvent.setup();
    render(<App />);

    await user.tab();
    expect(screen.getByRole("button", { name: "Overview" })).toHaveFocus();

    await user.tab();
    expect(screen.getByRole("button", { name: "Event Explorer" })).toHaveFocus();

    await user.keyboard("{Enter}");
    expect(await screen.findByRole("heading", { level: 1, name: "Event Explorer" })).toBeInTheDocument();
  });

  it("opens the CSV wizard from the Overview and Data Sources screens", async () => {
    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByRole("button", { name: "CSV wizard" }));
    expect(await screen.findByTestId("csv-wizard")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Close CSV wizard" }));
    expect(screen.queryByTestId("csv-wizard")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Data Sources" }));
    await user.click(await screen.findByRole("button", { name: "CSV wizard" }));
    expect(await screen.findByTestId("csv-wizard")).toBeInTheDocument();
  });

  it("renders each screen with mocked backend data", async () => {
    const user = userEvent.setup();
    vi.mocked(api.getOverview).mockResolvedValue(populatedOverview);
    vi.mocked(api.listDatasets).mockResolvedValue([demoDataset]);
    vi.mocked(api.listCaptures).mockResolvedValue([demoCapture]);
    vi.mocked(api.searchEvents).mockResolvedValue({
      total: 1,
      events: [eventRow(1)],
      page: 1,
      pageSize: 50,
      durationMs: 1,
    });
    vi.mocked(api.searchPackets).mockResolvedValue({
      total: 1,
      packets: [packetRow(1)],
      page: 1,
      pageSize: 100,
      durationMs: 1,
    });
    vi.mocked(api.listFlows).mockResolvedValue([flowRow(1)]);
    vi.mocked(api.listAlerts).mockResolvedValue([bruteForceAlert]);
    vi.mocked(api.listInvestigations).mockResolvedValue([demoInvestigation]);

    render(<App />);

    expect(await screen.findByText("1,234")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Event volume/ })).toBeInTheDocument();
    expect(screen.getByText("Recent alerts")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Event Explorer" }));
    expect(await screen.findByText("203.0.113.44:51234")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Network Analyzer" }));
    expect(await screen.findByText("10.0.0.10:51515")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Alerts" }));
    expect(await screen.findByText("Repeated authentication failures")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Investigations" }));
    expect(await screen.findByText("Suspicious outbound traffic")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Data Sources" }));
    expect(await screen.findByText("Synthetic demo dataset")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Settings" }));
    expect(await screen.findByLabelText(/Brute force threshold/)).toHaveValue(10);
  });
});
