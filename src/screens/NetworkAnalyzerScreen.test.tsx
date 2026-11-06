import { beforeEach, describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../services/api", () => ({
  api: {
    listCaptures: vi.fn(),
    listFlows: vi.fn(),
    searchPackets: vi.fn(),
    getPacket: vi.fn(),
    getFlowPackets: vi.fn(),
    previewImport: vi.fn(),
    importFile: vi.fn(),
    importPcap: vi.fn(),
    previewCsv: vi.fn(),
  },
}));

import { NetworkAnalyzerScreen } from "./NetworkAnalyzerScreen";
import { api } from "../services/api";
import { demoCapture, flowRow, packetRow } from "../test/fixtures";
import { renderWithMode } from "../test/renderWithMode";

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  vi.mocked(api.listCaptures).mockResolvedValue([demoCapture]);
  vi.mocked(api.listFlows).mockResolvedValue([{ ...flowRow(1), transport: "TLS" }]);
  vi.mocked(api.searchPackets).mockResolvedValue({
    total: 1,
    packets: [
      packetRow(1, {
        protocol: "DNS",
        frameKind: "management",
        encrypted: true,
        summary: "802.11 management frame",
      }),
    ],
    page: 1,
    pageSize: 100,
    durationMs: 1,
  });
  vi.mocked(api.getPacket).mockResolvedValue({
    packet: packetRow(1, { protocol: "DNS", frameKind: "management", encrypted: true }),
    layers: [
      {
        name: "dns",
        label: "Domain Name System",
        fields: [{ name: "qname", value: "example.com" }],
        children: [],
      },
    ],
    hex: "deadbeef",
    ascii: "....",
    unsupported: null,
  });
});

describe("NetworkAnalyzerScreen", () => {
  it("renders protocol, frame-kind and encrypted chips and decodes a packet", async () => {
    const user = userEvent.setup();
    renderWithMode(<NetworkAnalyzerScreen />);

    const endpoints = await screen.findAllByText("10.0.0.10:51515");
    expect(endpoints.length).toBeGreaterThan(0);

    expect(screen.getByText("management")).toHaveClass("chip", "chip--management");
    expect(screen.getByText("Encrypted")).toHaveClass("chip--encrypted");
    expect(screen.getAllByText("DNS")[0]).toHaveClass("chip--dns");

    await user.click(screen.getAllByText("10.0.0.10:51515")[0]);

    expect(vi.mocked(api.getPacket)).toHaveBeenCalledWith(1);
    expect(await screen.findByText("Domain Name System")).toBeInTheDocument();
    expect(screen.getByText("qname")).toBeInTheDocument();
    expect(screen.getByText("de ad be ef")).toBeInTheDocument();
  });
});
