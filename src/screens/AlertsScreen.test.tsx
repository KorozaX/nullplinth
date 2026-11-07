import { beforeEach, describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../services/api", () => ({
  api: {
    listAlerts: vi.fn(),
    getAlert: vi.fn(),
    runDetection: vi.fn(),
    updateAlertStatus: vi.fn(),
    getEvent: vi.fn(),
    createInvestigation: vi.fn(),
  },
}));

import { AlertsScreen } from "./AlertsScreen";
import { api } from "../services/api";
import { bruteForceAlert, eventDetail, eventRow } from "../test/fixtures";
import { renderWithMode } from "../test/renderWithMode";

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  vi.mocked(api.listAlerts).mockResolvedValue([bruteForceAlert]);
  vi.mocked(api.getAlert).mockResolvedValue({
    alert: bruteForceAlert,
    evidence: [{ kind: "event", refId: 1, summary: "failed login for jdoe", ts: 1767225845000 }],
  });
  vi.mocked(api.getEvent).mockResolvedValue(eventDetail(eventRow(1)));
});

describe("AlertsScreen", () => {
  it("shows alert detail with explanation, threshold and evidence", async () => {
    const user = userEvent.setup();
    renderWithMode(<AlertsScreen onOpenInvestigation={() => undefined} />);

    await user.click(await screen.findByText("Repeated authentication failures"));

    expect(await screen.findByTestId("alert-detail")).toBeInTheDocument();
    expect(await screen.findByText("Many failed logins from 203.0.113.44 in a short window.")).toBeInTheDocument();
    expect(screen.getByText("Block the source IP")).toBeInTheDocument();
    expect(screen.getByText("failed login for jdoe")).toBeInTheDocument();
    expect(screen.getAllByText("auth_bruteforce").length).toBeGreaterThan(0);
  });

  it("renders an empty state with a run detection action", async () => {
    vi.mocked(api.listAlerts).mockResolvedValue([]);
    renderWithMode(<AlertsScreen onOpenInvestigation={() => undefined} />);

    expect(await screen.findByText("No alerts yet")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Run detection" }).length).toBeGreaterThan(0);
  });

  it("renders only the endpoints that exist", async () => {
    vi.mocked(api.listAlerts).mockResolvedValue([
      { ...bruteForceAlert, id: 101, title: "Source only alert", srcIp: "203.0.113.44", dstIp: null },
      { ...bruteForceAlert, id: 102, title: "Destination only alert", srcIp: null, dstIp: "10.0.0.5" },
      { ...bruteForceAlert, id: 103, title: "No endpoint alert", srcIp: null, dstIp: null },
    ]);
    renderWithMode(<AlertsScreen onOpenInvestigation={() => undefined} />);

    const sourceRow = (await screen.findByText("Source only alert")).closest("tr");
    expect(sourceRow).not.toBeNull();
    expect(sourceRow?.textContent ?? "").toContain("203.0.113.44");
    expect(sourceRow?.textContent ?? "").not.toContain("\u2014");

    const destinationRow = (await screen.findByText("Destination only alert")).closest("tr");
    expect(destinationRow).not.toBeNull();
    expect(destinationRow?.textContent ?? "").toContain("10.0.0.5");
    expect(destinationRow?.textContent ?? "").not.toContain("\u2014");

    expect(await screen.findByText("no endpoint recorded")).toBeInTheDocument();
  });
});
