import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

import { TopologyGraph } from "./TopologyGraph";
import type { Topology, TopologyNode } from "../types/contracts";

const LAST_SEEN = 1767225600000;

function node(overrides: Partial<TopologyNode> & { id: string }): TopologyNode {
  return {
    label: overrides.id,
    kind: "external",
    events: 10,
    alerts: 0,
    severity: "none",
    lastSeen: LAST_SEEN,
    ...overrides,
  };
}

function sampleTopology(): Topology {
  return {
    nodes: [
      node({ id: "10.0.0.5", kind: "internal", events: 420, alerts: 2, severity: "critical" }),
      node({ id: "203.0.113.44", kind: "external", events: 120 }),
      node({ id: "8.8.8.8", kind: "external", events: 60, severity: "high" }),
      node({ id: "192.168.1.20", kind: "internal", events: 30, alerts: 1, severity: "medium" }),
      node({ id: "172.16.0.9", kind: "internal", events: 5 }),
      node({ id: "fd00::1", kind: "unknown", events: 2 }),
    ],
    edges: [
      { source: "10.0.0.5", target: "203.0.113.44", events: 300, transport: "tcp", appProto: "tls", severity: "none" },
      { source: "10.0.0.5", target: "8.8.8.8", events: 80, transport: "udp", appProto: "dns", severity: "high" },
      { source: "192.168.1.20", target: "10.0.0.5", events: 40, transport: "tcp", appProto: "http", severity: "medium" },
      { source: "8.8.8.8", target: "203.0.113.44", events: 20, transport: "tcp", appProto: null, severity: "none" },
      { source: "10.0.0.5", target: "172.16.0.9", events: 5, transport: "tcp", appProto: null, severity: "none" },
      { source: "172.16.0.9", target: "fd00::1", events: 1, transport: null, appProto: null, severity: "none" },
    ],
    truncated: false,
  };
}

function denseTopology(): Topology {
  const nodes: TopologyNode[] = Array.from({ length: 12 }, (_value, index) =>
    node({
      id: "10.0.1." + String(index + 1),
      kind: index % 2 === 0 ? "internal" : "external",
      events: 1200 - index * 100,
      alerts: index === 0 ? 3 : 0,
      severity: index === 0 ? "critical" : "none",
    }),
  );
  const edges = nodes.slice(0, 11).map((host, index) => ({
    source: host.id,
    target: nodes[index + 1].id,
    events: 200 - index * 10,
    transport: "tcp",
    appProto: null,
    severity: "none",
  }));
  return { nodes, edges, truncated: false };
}

const DENSE_TOP_LABELS = ["10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.1.4", "10.0.1.5", "10.0.1.6", "10.0.1.7", "10.0.1.8"];

function labelTexts(container: HTMLElement): string[] {
  return Array.from(container.querySelectorAll(".topology-node__label")).map(
    (element) => element.textContent ?? "",
  );
}

function nodeElement(container: HTMLElement, id: string): Element {
  const element = container.querySelector('[data-node-id="' + id + '"]');
  if (!element) throw new Error("node not found: " + id);
  return element;
}

describe("TopologyGraph", () => {
  it("shows an honest empty state and an import hint when there is no data", () => {
    render(<TopologyGraph data={{ nodes: [], edges: [], truncated: false }} />);

    const empty = screen.getByTestId("topology-empty");
    expect(empty).toBeInTheDocument();
    expect(empty.textContent ?? "").toMatch(/No hosts observed yet/);
    expect(empty.textContent ?? "").toMatch(/Import security events/);
    expect(screen.queryByTestId("topology-graph")).not.toBeInTheDocument();
  });

  it("treats missing data as empty", () => {
    render(<TopologyGraph data={null} />);
    expect(screen.getByTestId("topology-empty")).toBeInTheDocument();
  });

  it("explains when hosts exist but no conversation has been recorded", () => {
    const data: Topology = {
      nodes: [node({ id: "10.0.0.1", kind: "internal" }), node({ id: "10.0.0.2", kind: "internal" })],
      edges: [],
      truncated: false,
    };
    render(<TopologyGraph data={data} />);
    const empty = screen.getByTestId("topology-empty");
    expect(empty.textContent ?? "").toMatch(/no conversations yet/i);
  });

  it("renders one SVG with every host and conversation, plus an accessible name", () => {
    const { container } = render(<TopologyGraph data={sampleTopology()} />);

    expect(screen.getByTestId("topology-graph")).toBeInTheDocument();
    expect(screen.getAllByTestId("topology-node")).toHaveLength(6);
    expect(screen.getAllByTestId("topology-edge")).toHaveLength(6);
    expect(
      screen.getByRole("group", {
        name: /Network topology graph with 6 hosts and 6 conversations/,
      }),
    ).toBeInTheDocument();
    const nodes = Array.from(container.querySelectorAll('[data-testid="topology-node"]'));
    for (const element of nodes) {
      expect(element.getAttribute("transform")).toMatch(/^translate\(-?[\d.]+ -?[\d.]+\)$/);
    }
  });

  it("maps colour and shape to real severity and host kind", () => {
    const { container } = render(<TopologyGraph data={sampleTopology()} />);

    const expectations: Array<[string, string, string]> = [
      ["10.0.0.5", "var(--coral)", "circle"],
      ["203.0.113.44", "var(--teal)", "diamond"],
      ["8.8.8.8", "var(--orange)", "diamond"],
      ["192.168.1.20", "var(--orange)", "circle"],
      ["172.16.0.9", "var(--lime)", "circle"],
      ["fd00::1", "var(--gray)", "square"],
    ];
    for (const [id, color, shape] of expectations) {
      const element = nodeElement(container, id);
      expect(element.getAttribute("data-color")).toBe(color);
      expect(element.getAttribute("data-shape")).toBe(shape);
      const renderedShape = element.querySelector(".topology-node__shape");
      expect(renderedShape).not.toBeNull();
      expect(renderedShape?.getAttribute("fill")).toBe(color);
    }
  });

  it("shows the legend for colour and shape language", () => {
    render(<TopologyGraph data={sampleTopology()} />);
    const legend = screen.getByTestId("topology-legend");
    const text = legend.textContent ?? "";
    expect(text).toMatch(/External host/);
    expect(text).toMatch(/Internal host/);
    expect(text).toMatch(/High \/ medium alert/);
    expect(text).toMatch(/Critical alert/);
    expect(text).toMatch(/Unknown host/);
    expect(text).toMatch(/Line thickness/);
  });

  it("shows host details on hover and hides them on leave", () => {
    const { container } = render(<TopologyGraph data={sampleTopology()} />);
    const element = nodeElement(container, "203.0.113.44");

    expect(screen.queryByTestId("topology-tooltip")).not.toBeInTheDocument();
    fireEvent.mouseOver(element);
    const tooltip = screen.getByTestId("topology-tooltip");
    const text = tooltip.textContent ?? "";
    expect(text).toContain("203.0.113.44");
    expect(text).toMatch(/External/);
    expect(text).toMatch(/Severity/);
    expect(text).toMatch(/Info/);
    expect(text).toMatch(/Events/);
    expect(text).toContain("120");
    expect(text).toMatch(/Alerts/);
    expect(text).toMatch(/Last seen/);
    expect(text).toMatch(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/);

    fireEvent.mouseOut(element);
    expect(screen.queryByTestId("topology-tooltip")).not.toBeInTheDocument();
  });

  it("shows the tooltip on keyboard focus", () => {
    const { container } = render(<TopologyGraph data={sampleTopology()} />);
    const element = nodeElement(container, "8.8.8.8");
    fireEvent.focus(element);
    expect(screen.getByTestId("topology-tooltip").textContent ?? "").toContain("8.8.8.8");
    fireEvent.blur(element);
    expect(screen.queryByTestId("topology-tooltip")).not.toBeInTheDocument();
  });

  it("selects a host on click, highlights its edges and toggles off", () => {
    const onSelectNode = vi.fn();
    const { container } = render(
      <TopologyGraph data={sampleTopology()} onSelectNode={onSelectNode} />,
    );
    const element = nodeElement(container, "203.0.113.44");

    fireEvent.click(element);
    expect(onSelectNode).toHaveBeenCalledTimes(1);
    expect((onSelectNode.mock.calls[0][0] as TopologyNode).id).toBe("203.0.113.44");
    expect(element.getAttribute("aria-pressed")).toBe("true");

    const highlighted = container.querySelector(
      '[data-edge-source="10.0.0.5"][data-edge-target="203.0.113.44"]',
    );
    expect(highlighted?.getAttribute("class")).toContain("is-highlighted");
    const dimmed = container.querySelector(
      '[data-edge-source="192.168.1.20"][data-edge-target="10.0.0.5"]',
    );
    expect(dimmed?.getAttribute("class")).toContain("is-dimmed");
    const dimmedNode = nodeElement(container, "172.16.0.9");
    expect(dimmedNode.getAttribute("class")).toContain("is-dimmed");

    fireEvent.click(element);
    expect(onSelectNode).toHaveBeenLastCalledWith(null);
    expect(element.getAttribute("aria-pressed")).toBe("false");
  });

  it("clears the selection when the background is clicked", () => {
    const onSelectNode = vi.fn();
    const { container } = render(
      <TopologyGraph data={sampleTopology()} onSelectNode={onSelectNode} />,
    );
    fireEvent.click(nodeElement(container, "10.0.0.5"));
    expect(nodeElement(container, "10.0.0.5").getAttribute("aria-pressed")).toBe("true");
    const surface = container.querySelector(".topology-graph__surface");
    expect(surface).not.toBeNull();
    if (surface) fireEvent.click(surface);
    expect(onSelectNode).toHaveBeenLastCalledWith(null);
    expect(nodeElement(container, "10.0.0.5").getAttribute("aria-pressed")).toBe("false");
  });

  it("supports a controlled selection and keeps it until the parent changes it", () => {
    const onSelectNode = vi.fn();
    const { container, rerender } = render(
      <TopologyGraph
        data={sampleTopology()}
        selectedNodeId="8.8.8.8"
        onSelectNode={onSelectNode}
      />,
    );
    expect(nodeElement(container, "8.8.8.8").getAttribute("aria-pressed")).toBe("true");

    fireEvent.click(nodeElement(container, "10.0.0.5"));
    expect(onSelectNode).toHaveBeenCalledTimes(1);
    expect(nodeElement(container, "8.8.8.8").getAttribute("aria-pressed")).toBe("true");
    expect(nodeElement(container, "10.0.0.5").getAttribute("aria-pressed")).toBe("false");

    rerender(
      <TopologyGraph
        data={sampleTopology()}
        selectedNodeId="10.0.0.5"
        onSelectNode={onSelectNode}
      />,
    );
    expect(nodeElement(container, "10.0.0.5").getAttribute("aria-pressed")).toBe("true");
    expect(nodeElement(container, "8.8.8.8").getAttribute("aria-pressed")).toBe("false");
  });

  it("is keyboard operable: Enter and Space select, Escape clears", () => {
    const onSelectNode = vi.fn();
    const { container } = render(
      <TopologyGraph data={sampleTopology()} onSelectNode={onSelectNode} />,
    );
    const element = nodeElement(container, "10.0.0.5");
    expect(element.getAttribute("tabindex")).toBe("0");

    fireEvent.keyDown(element, { key: "Enter" });
    expect((onSelectNode.mock.calls[0][0] as TopologyNode).id).toBe("10.0.0.5");
    fireEvent.keyDown(element, { key: " " });
    expect(onSelectNode).toHaveBeenLastCalledWith(null);

    fireEvent.keyDown(element, { key: " " });
    expect((onSelectNode.mock.calls[2][0] as TopologyNode).id).toBe("10.0.0.5");
    fireEvent.keyDown(element, { key: "Escape" });
    expect(onSelectNode).toHaveBeenLastCalledWith(null);
  });

  it("gives every host a descriptive aria label with live data", () => {
    const { container } = render(<TopologyGraph data={sampleTopology()} />);
    const element = nodeElement(container, "10.0.0.5");
    const label = element.getAttribute("aria-label") ?? "";
    expect(label).toContain("10.0.0.5");
    expect(label).toContain("Internal host");
    expect(label).toContain("420 events");
    expect(label).toContain("2 alerts");
    expect(label).toContain("Critical");
    expect(label).toContain("last seen");
  });

  it("orders tab stops by activity", () => {
    const { container } = render(<TopologyGraph data={sampleTopology()} />);
    const order = Array.from(container.querySelectorAll('[data-testid="topology-node"]')).map(
      (element) => element.getAttribute("data-node-id"),
    );
    expect(order).toEqual([
      "10.0.0.5",
      "203.0.113.44",
      "8.8.8.8",
      "192.168.1.20",
      "172.16.0.9",
      "fd00::1",
    ]);
  });

  it("reports the display limit when the host cap hides hosts", () => {
    render(<TopologyGraph data={sampleTopology()} maxNodes={3} />);
    expect(screen.getAllByTestId("topology-node")).toHaveLength(3);
    const note = screen.getByTestId("topology-truncation");
    expect(note).toHaveAttribute("data-state", "client");
    expect(note.textContent ?? "").toMatch(/Showing 3 of 6 hosts and \d+ of 6 conversations/);
    expect(note.textContent ?? "").toContain("(display limit)");
    expect(note.textContent ?? "").not.toMatch(/server/i);
  });

  it("reports the display limit when the edge cap hides conversations", () => {
    render(<TopologyGraph data={sampleTopology()} maxEdges={2} />);
    expect(screen.getAllByTestId("topology-edge")).toHaveLength(2);
    const note = screen.getByTestId("topology-truncation");
    expect(note).toHaveAttribute("data-state", "client");
    expect(note.textContent ?? "").toMatch(
      /Showing all 6 hosts and 2 of 6 conversations/,
    );
  });

  it("distinguishes the server cap from the display limit", () => {
    const data = sampleTopology();
    data.truncated = true;
    render(<TopologyGraph data={data} />);
    const note = screen.getByTestId("topology-truncation");
    expect(note).toHaveAttribute("data-state", "server");
    const text = note.textContent ?? "";
    expect(text).toMatch(
      /Showing all 6 returned hosts and 6 returned conversations/,
    );
    expect(text).toContain("server returned only its busiest records");
    expect(text).not.toContain("display limit");
    expect(text).not.toMatch(/Showing 6 of 6/);
    expect(screen.getAllByTestId("topology-node")).toHaveLength(6);
  });

  it("mentions both caps when the display limit trims a server-capped result", () => {
    const data = sampleTopology();
    data.truncated = true;
    render(<TopologyGraph data={data} maxNodes={3} />);
    const note = screen.getByTestId("topology-truncation");
    expect(note).toHaveAttribute("data-state", "both");
    const text = note.textContent ?? "";
    expect(text).toContain("(display limit)");
    expect(text).toContain("The server also returned only its busiest records");
  });

  it("has no truncation note when everything fits", () => {
    render(<TopologyGraph data={sampleTopology()} />);
    expect(screen.queryByTestId("topology-truncation")).not.toBeInTheDocument();
  });

  it("exposes the reduced-motion mode for the container styles", () => {
    render(<TopologyGraph data={sampleTopology()} />);
    expect(screen.getByTestId("topology-graph")).toHaveAttribute("data-motion", "on");
  });

  it("labels only the most active hosts by default", () => {
    const { container } = render(<TopologyGraph data={denseTopology()} />);
    const labels = labelTexts(container);
    expect(labels).toHaveLength(8);
    expect(labels).toEqual(DENSE_TOP_LABELS);
    expect(labels).not.toContain("10.0.1.12");
    expect(container.querySelectorAll('[data-testid="topology-node"]')).toHaveLength(12);
  });

  it("honours the maxLabels prop", () => {
    const { container } = render(<TopologyGraph data={denseTopology()} maxLabels={3} />);
    expect(labelTexts(container)).toEqual(["10.0.1.1", "10.0.1.2", "10.0.1.3"]);
  });

  it("reveals a hidden host label on hover and hides it again", () => {
    const { container } = render(<TopologyGraph data={denseTopology()} />);
    const hidden = nodeElement(container, "10.0.1.12");
    expect(hidden.querySelector(".topology-node__label")).toBeNull();
    fireEvent.mouseOver(hidden);
    expect(hidden.querySelector(".topology-node__label")?.textContent).toBe("10.0.1.12");
    fireEvent.mouseOut(hidden);
    expect(hidden.querySelector(".topology-node__label")).toBeNull();
  });

  it("reveals a hidden host label on keyboard focus", () => {
    const { container } = render(<TopologyGraph data={denseTopology()} />);
    const hidden = nodeElement(container, "10.0.1.11");
    fireEvent.focus(hidden);
    expect(hidden.querySelector(".topology-node__label")?.textContent).toBe("10.0.1.11");
    fireEvent.blur(hidden);
    expect(hidden.querySelector(".topology-node__label")).toBeNull();
  });

  it("keeps the selected host label visible after the pointer leaves", () => {
    const { container } = render(<TopologyGraph data={denseTopology()} />);
    const hidden = nodeElement(container, "10.0.1.10");
    fireEvent.click(hidden);
    expect(hidden.querySelector(".topology-node__label")?.textContent).toBe("10.0.1.10");
    fireEvent.mouseOver(hidden);
    fireEvent.mouseOut(hidden);
    expect(hidden.querySelector(".topology-node__label")?.textContent).toBe("10.0.1.10");
    expect(hidden.getAttribute("aria-pressed")).toBe("true");
  });

  it("still exposes every host through the tooltip when labels are decluttered", () => {
    const { container } = render(<TopologyGraph data={denseTopology()} />);
    const hidden = nodeElement(container, "10.0.1.9");
    fireEvent.mouseOver(hidden);
    expect(screen.getByTestId("topology-tooltip").textContent ?? "").toContain("10.0.1.9");
  });
});