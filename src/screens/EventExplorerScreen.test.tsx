import { beforeEach, describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../services/api", () => ({
  api: {
    listDatasets: vi.fn(),
    searchEvents: vi.fn(),
    getEvent: vi.fn(),
    exportEvents: vi.fn(),
  },
}));

import { EventExplorerScreen } from "./EventExplorerScreen";
import { api } from "../services/api";
import { demoDataset, eventDetail, eventRow } from "../test/fixtures";
import { renderWithMode } from "../test/renderWithMode";

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  vi.mocked(api.listDatasets).mockResolvedValue([demoDataset]);
  vi.mocked(api.searchEvents).mockResolvedValue({ total: 0, events: [], page: 1, pageSize: 50, durationMs: 1 });
});

describe("EventExplorerScreen", () => {
  it("renders rows, shows the result count and paginates", async () => {
    const user = userEvent.setup();
    vi.mocked(api.searchEvents).mockImplementation(async (query) => ({
      total: 120,
      events: [eventRow(1, { srcIp: "10.0.0." + String(query.page), srcPort: 1000 + query.page })],
      page: query.page,
      pageSize: query.pageSize,
      durationMs: 2,
    }));

    renderWithMode(<EventExplorerScreen />);

    expect(await screen.findByText("10.0.0.1:1001")).toBeInTheDocument();
    expect(screen.getAllByText(/120 events/).length).toBeGreaterThan(0);

    await user.click(screen.getByRole("button", { name: "Next page" }));

    expect(await screen.findByText("10.0.0.2:1002")).toBeInTheDocument();
    expect(vi.mocked(api.searchEvents)).toHaveBeenLastCalledWith(expect.objectContaining({ page: 2 }));
  });

  it("renders an informative empty state when nothing matches", async () => {
    renderWithMode(<EventExplorerScreen />);

    expect(await screen.findByText("No events match this search")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Next page" })).not.toBeInTheDocument();
  });

  it("uses unambiguous column headers with one source type and one source IP", async () => {
    vi.mocked(api.searchEvents).mockResolvedValue({
      total: 1,
      events: [eventRow(1)],
      page: 1,
      pageSize: 50,
      durationMs: 1,
    });

    renderWithMode(<EventExplorerScreen />);
    await screen.findByText("203.0.113.44:51234");

    expect(screen.getByRole("columnheader", { name: "Source type" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Source IP" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Destination IP" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Event type" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "App protocol" })).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: "Source" })).not.toBeInTheDocument();
    expect(screen.getAllByRole("columnheader", { name: "Source IP" })).toHaveLength(1);
  });

  it("opens the event detail drawer with the raw record for analysts", async () => {
    const user = userEvent.setup();
    vi.mocked(api.searchEvents).mockResolvedValue({
      total: 1,
      events: [eventRow(1)],
      page: 1,
      pageSize: 50,
      durationMs: 1,
    });
    vi.mocked(api.getEvent).mockResolvedValue(eventDetail(eventRow(1)));

    renderWithMode(<EventExplorerScreen />);

    await user.click(await screen.findByText("203.0.113.44:51234"));

    expect(await screen.findByTestId("event-detail")).toBeInTheDocument();
    expect(vi.mocked(api.getEvent)).toHaveBeenCalledWith(1);
    expect(await screen.findByText(/"event_type": "alert"/)).toBeInTheDocument();
  });
});
