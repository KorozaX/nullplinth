import { beforeEach, describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../services/api", () => ({
  api: {
    getOverview: vi.fn(),
    networkTopology: vi.fn(),
  },
}));

import { OverviewScreen } from "./OverviewScreen";
import { api } from "../services/api";
import { demoTopology, emptyOverview, emptyTopology, populatedOverview } from "../test/fixtures";
import { renderWithMode } from "../test/renderWithMode";

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  vi.mocked(api.getOverview).mockResolvedValue(emptyOverview);
  vi.mocked(api.networkTopology).mockResolvedValue(emptyTopology);
});

describe("OverviewScreen composition", () => {
  it("renders the empty workbench with both import actions", async () => {
    renderWithMode(<OverviewScreen onNavigate={() => undefined} />);

    expect(await screen.findByText("No data imported yet")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Import data" }).length).toBeGreaterThan(0);
    expect((await screen.findAllByRole("button", { name: "Load demo dataset" })).length).toBeGreaterThan(0);
  });

  it("composes metrics, severity mix, protocol mix, rankings and the topology graph", async () => {
    vi.mocked(api.getOverview).mockResolvedValue(populatedOverview);
    vi.mocked(api.networkTopology).mockResolvedValue(demoTopology);

    renderWithMode(<OverviewScreen onNavigate={() => undefined} onSearch={() => undefined} />);

    expect(await screen.findByText("1,234")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Event volume over time/ })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Alert severity across/ })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Event severity across/ })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Protocol mix across/ })).toBeInTheDocument();

    expect(screen.getByText("Top sources")).toBeInTheDocument();
    expect(screen.getByText("Top destinations")).toBeInTheDocument();
    expect(screen.getByText("Event severity")).toBeInTheDocument();
    expect(screen.getByText("Top hosts")).toBeInTheDocument();
    expect(screen.getByText("Top ports")).toBeInTheDocument();
    expect(screen.getByText("Relationship graph")).toBeInTheDocument();
    expect(screen.getByText("Recent alerts")).toBeInTheDocument();

    expect(await screen.findByTestId("topology-graph")).toBeInTheDocument();
    expect(screen.getAllByText(/2 hosts/).length).toBeGreaterThan(0);
    expect(screen.getByText("srv-dc01")).toBeInTheDocument();
  });

  it("selects a topology node and routes it to the Event Explorer", async () => {
    const user = userEvent.setup();
    const onSearch = vi.fn();
    vi.mocked(api.getOverview).mockResolvedValue(populatedOverview);
    vi.mocked(api.networkTopology).mockResolvedValue(demoTopology);

    renderWithMode(<OverviewScreen onNavigate={() => undefined} onSearch={onSearch} />);

    const nodes = await screen.findAllByTestId("topology-node");
    expect(nodes.length).toBeGreaterThan(0);
    await user.click(nodes[0]);

    const investigate = await screen.findByRole("button", { name: "Investigate in Event Explorer" });
    await user.click(investigate);
    expect(onSearch).toHaveBeenCalled();
  });
});
