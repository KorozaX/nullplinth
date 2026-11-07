import { describe, expect, it } from "vitest";

import {
  TOPOLOGY_DEFAULT_MAX_LABELS,
  TOPOLOGY_DEFAULT_MAX_NODES,
  describeTruncation,
  prepareTopology,
  topologyEdgeColor,
  topologyKindLabel,
  topologyNodeColor,
  topologyNodeRadius,
  topologyNodeShape,
} from "./topologyLayout";
import type { Topology, TopologyEdge, TopologyNode } from "../types/contracts";

const LAST_SEEN = 1767225600000;

function node(id: string, overrides: Partial<TopologyNode> = {}): TopologyNode {
  return {
    id,
    label: id,
    kind: "external",
    events: 10,
    alerts: 0,
    severity: "none",
    lastSeen: LAST_SEEN,
    ...overrides,
  };
}

function edge(
  source: string,
  target: string,
  overrides: Partial<TopologyEdge> = {},
): TopologyEdge {
  return {
    source,
    target,
    events: 10,
    transport: "tcp",
    appProto: null,
    severity: "none",
    ...overrides,
  };
}

function topology(
  nodes: TopologyNode[],
  edges: TopologyEdge[],
  truncated = false,
): Topology {
  return { nodes, edges, truncated };
}

function sampleTopology(): Topology {
  const nodes = [
    node("10.0.0.5", { kind: "internal", events: 400, alerts: 2, severity: "critical" }),
    node("203.0.113.44", { kind: "external", events: 120 }),
    node("8.8.8.8", { kind: "external", events: 60, severity: "high" }),
    node("192.168.1.20", { kind: "internal", events: 30, alerts: 1, severity: "medium" }),
    node("172.16.0.9", { kind: "internal", events: 5 }),
    node("fd00::1", { kind: "unknown", events: 2 }),
    node("198.51.100.23", { kind: "external", events: 1 }),
  ];
  const edges = [
    edge("10.0.0.5", "203.0.113.44", { events: 300, appProto: "tls" }),
    edge("10.0.0.5", "8.8.8.8", { events: 80, transport: "udp", appProto: "dns", severity: "high" }),
    edge("192.168.1.20", "10.0.0.5", { events: 40, appProto: "http", severity: "medium" }),
    edge("8.8.8.8", "203.0.113.44", { events: 20 }),
    edge("10.0.0.5", "172.16.0.9", { events: 5 }),
    edge("172.16.0.9", "fd00::1", { events: 1 }),
  ];
  return topology(nodes, edges);
}

describe("topologyLayout", () => {
  it("returns an empty prepared graph for missing data", () => {
    const empty = prepareTopology(null);
    expect(empty.nodes).toEqual([]);
    expect(empty.edges).toEqual([]);
    expect(empty.totalNodes).toBe(0);
    expect(empty.totalEdges).toBe(0);
    expect(empty.truncated).toBe(false);
  });

  it("is deterministic: identical data and seed produce identical geometry", () => {
    const data = sampleTopology();
    const first = prepareTopology(data, { seed: 7 });
    const second = prepareTopology(data, { seed: 7 });
    const geometry = (result: ReturnType<typeof prepareTopology>) =>
      result.nodes.map((n) => [n.id, n.x, n.y, n.radius, n.color]);
    expect(geometry(first)).toEqual(geometry(second));
    expect(first.edges.map((e) => [e.key, e.width, e.opacity])).toEqual(
      second.edges.map((e) => [e.key, e.width, e.opacity]),
    );
  });

  it("orders hosts by activity and keeps the top maxNodes", () => {
    const nodes = Array.from({ length: 100 }, (_value, index) =>
      node("10.0.0." + String(index + 1), { events: index + 1 }),
    );
    const data = topology(nodes, []);
    const result = prepareTopology(data, { maxNodes: 80 });
    expect(result.nodes.length).toBe(80);
    expect(result.totalNodes).toBe(100);
    expect(result.hiddenNodes).toBe(20);
    expect(result.truncated).toBe(true);
    expect(result.nodes[0].id).toBe("10.0.0.100");
    expect(result.nodes[1].id).toBe("10.0.0.99");
  });

  it("uses the default node cap of 80 when the data is larger", () => {
    const nodes = Array.from({ length: 95 }, (_value, index) =>
      node("host-" + String(index), { events: index }),
    );
    const result = prepareTopology(topology(nodes, []));
    expect(result.nodes.length).toBe(TOPOLOGY_DEFAULT_MAX_NODES);
    expect(result.nodes.length).toBe(80);
  });

  it("drops edges to hidden hosts, self loops and keeps edge caps", () => {
    const data = topology(
      [
        node("a", { events: 30 }),
        node("b", { events: 20 }),
        node("c", { events: 10 }),
      ],
      [
        edge("a", "b", { events: 9 }),
        edge("b", "c", { events: 8 }),
        edge("a", "a", { events: 100 }),
        edge("a", "b", { events: 7 }),
      ],
    );
    const result = prepareTopology(data, { maxNodes: 2, maxEdges: 10 });
    expect(result.nodes.map((n) => n.id)).toEqual(["a", "b"]);
    expect(result.edges.length).toBe(2);
    expect(result.hiddenNodes).toBe(1);
    expect(result.hiddenEdges).toBe(1);
    expect(result.truncated).toBe(true);
    // Self loops are never rendered.
    expect(result.edges.every((e) => e.source !== e.target)).toBe(true);
  });

  it("caps conversations by event volume and keeps unique keys", () => {
    const nodes = Array.from({ length: 6 }, (_value, index) =>
      node("n" + String(index), { events: 100 - index }),
    );
    const edges: TopologyEdge[] = [];
    let volume = 1;
    for (let left = 0; left < nodes.length; left += 1) {
      for (let right = left + 1; right < nodes.length; right += 1) {
        edges.push(edge(nodes[left].id, nodes[right].id, { events: volume }));
        volume += 1;
      }
    }
    const result = prepareTopology(topology(nodes, edges), { maxEdges: 5 });
    expect(result.edges.length).toBe(5);
    expect(result.totalEdges).toBe(edges.length);
    expect(result.hiddenEdges).toBe(edges.length - 5);
    expect(new Set(result.edges.map((e) => e.key)).size).toBe(5);
    expect(result.edges[0].events).toBe(volume - 1);
  });

  it("keeps every host inside the view box and finite", () => {
    const result = prepareTopology(sampleTopology(), { width: 800, height: 400, padding: 40 });
    expect(result.width).toBe(800);
    expect(result.height).toBe(400);
    for (const item of result.nodes) {
      expect(Number.isFinite(item.x)).toBe(true);
      expect(Number.isFinite(item.y)).toBe(true);
      expect(item.x).toBeGreaterThanOrEqual(40);
      expect(item.x).toBeLessThanOrEqual(760);
      expect(item.y).toBeGreaterThanOrEqual(40);
      expect(item.y).toBeLessThanOrEqual(360);
    }
  });

  it("scales node radius with activity", () => {
    expect(topologyNodeRadius(0, 100)).toBe(7);
    expect(topologyNodeRadius(100, 100)).toBe(24);
    expect(topologyNodeRadius(25, 100)).toBeLessThan(topologyNodeRadius(75, 100));
    expect(topologyNodeRadius(0, 0)).toBe(7);
  });

  it("maps node colours to real severity and kind", () => {
    expect(topologyNodeColor("external", "none")).toBe("var(--teal)");
    expect(topologyNodeColor("internal", "none")).toBe("var(--lime)");
    expect(topologyNodeColor("internal", "low")).toBe("var(--lime)");
    expect(topologyNodeColor("external", "critical")).toBe("var(--coral)");
    expect(topologyNodeColor("internal", "high")).toBe("var(--orange)");
    expect(topologyNodeColor("external", "medium")).toBe("var(--orange)");
    expect(topologyNodeColor("unknown", "none")).toBe("var(--gray)");
    expect(topologyNodeColor("", "")).toBe("var(--gray)");
  });

  it("maps edge colours to severity", () => {
    expect(topologyEdgeColor("critical")).toBe("var(--coral)");
    expect(topologyEdgeColor("high")).toBe("var(--orange)");
    expect(topologyEdgeColor("medium")).toBe("var(--orange)");
    expect(topologyEdgeColor("low")).toBe("var(--gray)");
    expect(topologyEdgeColor("none")).toBe("var(--gray)");
  });

  it("maps kind to shape and label", () => {
    expect(topologyNodeShape("internal")).toBe("circle");
    expect(topologyNodeShape("external")).toBe("diamond");
    expect(topologyNodeShape("unknown")).toBe("square");
    expect(topologyNodeShape("mystery")).toBe("square");
    expect(topologyKindLabel("internal")).toBe("Internal");
    expect(topologyKindLabel("external")).toBe("External");
    expect(topologyKindLabel("mystery")).toBe("Unknown");
  });

  it("weights edges by conversation volume", () => {
    const result = prepareTopology(
      topology(
        [node("a", { events: 50 }), node("b", { events: 40 }), node("c", { events: 30 })],
        [edge("a", "b", { events: 10 }), edge("a", "c", { events: 1000 })],
      ),
    );
    const light = result.edges.find((e) => e.events === 10);
    const heavy = result.edges.find((e) => e.events === 1000);
    expect(light).toBeDefined();
    expect(heavy).toBeDefined();
    if (!light || !heavy) return;
    expect(heavy.width).toBeGreaterThan(light.width);
    expect(heavy.opacity).toBeGreaterThan(light.opacity);
    expect(heavy.color).toBe("var(--gray)");
  });

  it("handles a single host without NaN coordinates", () => {
    const result = prepareTopology(topology([node("solo", { events: 3 })], []));
    expect(result.nodes.length).toBe(1);
    const only = result.nodes[0];
    expect(Number.isFinite(only.x)).toBe(true);
    expect(Number.isFinite(only.y)).toBe(true);
    expect(result.edges).toEqual([]);
    expect(result.truncated).toBe(false);
  });

  it("exposes permanent labels only for the most active hosts", () => {
    const nodes = Array.from({ length: 12 }, (_value, index) =>
      node("10.0.1." + String(index + 1), { events: 1200 - index * 100 }),
    );
    const data = topology(nodes, []);
    const result = prepareTopology(data);
    expect(result.labelIds.length).toBe(TOPOLOGY_DEFAULT_MAX_LABELS);
    expect(result.labelIds).toEqual([
      "10.0.1.1",
      "10.0.1.2",
      "10.0.1.3",
      "10.0.1.4",
      "10.0.1.5",
      "10.0.1.6",
      "10.0.1.7",
      "10.0.1.8",
    ]);
    const limited = prepareTopology(data, { maxLabels: 3 });
    expect(limited.labelIds).toEqual(["10.0.1.1", "10.0.1.2", "10.0.1.3"]);
    const small = prepareTopology(topology(nodes.slice(0, 2), []));
    expect(small.labelIds.length).toBe(2);
    const none = prepareTopology(data, { maxLabels: 0 });
    expect(none.labelIds).toEqual([]);
  });

  it("describes the three truncation states honestly", () => {
    const full = prepareTopology(sampleTopology());
    const none = describeTruncation(full, false);
    expect(none.state).toBe("none");
    expect(none.message).toBe("");

    const clientOnly = describeTruncation(
      { ...full, hiddenNodes: 2, hiddenEdges: 1, truncated: true },
      false,
    );
    expect(clientOnly.state).toBe("client");
    expect(clientOnly.message).toContain("(display limit)");
    expect(clientOnly.message).not.toMatch(/server/i);

    const serverOnly = describeTruncation(full, true);
    expect(serverOnly.state).toBe("server");
    expect(serverOnly.message).toContain(
      "Showing all 7 returned hosts and 6 returned conversations",
    );
    expect(serverOnly.message).toContain("server returned only its busiest records");
    expect(serverOnly.message).not.toContain("display limit");
    expect(serverOnly.message).not.toContain("Showing 7 of 7");

    const both = describeTruncation(
      { ...full, hiddenNodes: 2, hiddenEdges: 1, truncated: true },
      true,
    );
    expect(both.state).toBe("both");
    expect(both.message).toContain("(display limit)");
    expect(both.message).toContain("The server also returned only its busiest records");
  });

  it("ignores malformed rows instead of rendering them", () => {
    const broken = {
      nodes: [
        { id: "", label: "empty", kind: "internal", events: 5, alerts: 0, severity: "none", lastSeen: 0 },
        { id: "ok", label: "", kind: "internal", events: 5, alerts: 0, severity: "none", lastSeen: 0 },
      ],
      edges: [
        { source: "ok", target: "ok", events: 5, transport: null, appProto: null, severity: "none" },
        { source: "ok", target: "missing", events: 4, transport: null, appProto: null, severity: "none" },
      ],
      truncated: false,
    } as Topology;
    const result = prepareTopology(broken);
    expect(result.nodes.map((n) => n.id)).toEqual(["ok"]);
    expect(result.nodes[0].label).toBe("ok");
    expect(result.edges).toEqual([]);
  });
});