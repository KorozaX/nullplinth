import type { Topology, TopologyEdge, TopologyNode } from "../types/contracts";

/**
 * Deterministic, dependency-free layout for the Overview relationship graph.
 *
 * The same Topology input plus the same options always produces byte-identical
 * node positions: the seeded Fruchterman-Reingold relaxation is capped, there is
 * no randomness outside the local PRNG and no time or DOM input is read.
 */

export const TOPOLOGY_WIDTH = 960;
export const TOPOLOGY_HEIGHT = 520;
export const TOPOLOGY_DEFAULT_MAX_NODES = 80;
export const TOPOLOGY_DEFAULT_MAX_EDGES = 240;
/** How many of the busiest hosts keep a permanent text label. */
export const TOPOLOGY_DEFAULT_MAX_LABELS = 8;
export const TOPOLOGY_DEFAULT_ITERATIONS = 200;
export const TOPOLOGY_DEFAULT_SEED = 0x5eed1e;

export type TopologyKind = "internal" | "external" | "unknown";
export type TopologyNodeShape = "circle" | "diamond" | "square";

export interface TopologyLayoutOptions {
  width?: number;
  height?: number;
  maxNodes?: number;
  maxEdges?: number;
  /** Number of most active hosts that always keep a label. */
  maxLabels?: number;
  iterations?: number;
  seed?: number;
  padding?: number;
}

export interface TopologyNodeLayout {
  id: string;
  label: string;
  kind: TopologyKind;
  events: number;
  alerts: number;
  severity: string;
  lastSeen: number;
  x: number;
  y: number;
  radius: number;
  color: string;
  shape: TopologyNodeShape;
}

export interface TopologyEdgeLayout {
  /** Unique render key; stable for the same input ordering. */
  key: string;
  source: string;
  target: string;
  events: number;
  transport: string | null;
  appProto: string | null;
  severity: string;
  color: string;
  width: number;
  opacity: number;
}

export interface PreparedTopology {
  nodes: TopologyNodeLayout[];
  edges: TopologyEdgeLayout[];
  /** Ids of the most active hosts whose labels stay visible; others show on hover/focus/select. */
  labelIds: string[];
  totalNodes: number;
  totalEdges: number;
  hiddenNodes: number;
  hiddenEdges: number;
  /** True when the rendered graph is smaller than the data it represents. */
  truncated: boolean;
  width: number;
  height: number;
}

// ------------------------------------------------------------- semantics

export function normalizeTopologyKind(kind: string | null | undefined): TopologyKind {
  const lowered = (kind ?? "").trim().toLowerCase();
  if (lowered === "internal" || lowered === "external") return lowered;
  return "unknown";
}

function normalizeSeverity(severity: string | null | undefined): string {
  const lowered = (severity ?? "").trim().toLowerCase();
  return lowered.length > 0 ? lowered : "none";
}

export function topologyKindLabel(kind: string | null | undefined): string {
  const normalized = normalizeTopologyKind(kind);
  if (normalized === "internal") return "Internal";
  if (normalized === "external") return "External";
  return "Unknown";
}

/**
 * Colour encodes the worst real signal on a host:
 * critical -> coral, high/medium -> orange, clean internal -> lime,
 * plain external traffic -> teal, anything else -> grey.
 */
export function topologyNodeColor(
  kind: string | null | undefined,
  severity: string | null | undefined,
): string {
  const normalizedSeverity = normalizeSeverity(severity);
  if (normalizedSeverity === "critical") return "var(--coral)";
  if (normalizedSeverity === "high" || normalizedSeverity === "medium") return "var(--orange)";
  const normalizedKind = normalizeTopologyKind(kind);
  if (normalizedKind === "internal") return "var(--lime)";
  if (normalizedKind === "external") return "var(--teal)";
  return "var(--gray)";
}

/** Edges follow the same severity language, normal conversations stay grey. */
export function topologyEdgeColor(severity: string | null | undefined): string {
  const normalized = normalizeSeverity(severity);
  if (normalized === "critical") return "var(--coral)";
  if (normalized === "high" || normalized === "medium") return "var(--orange)";
  return "var(--gray)";
}

/** Shape is a second, non-colour signal for the host kind. */
export function topologyNodeShape(kind: string | null | undefined): TopologyNodeShape {
  const normalized = normalizeTopologyKind(kind);
  if (normalized === "internal") return "circle";
  if (normalized === "external") return "diamond";
  return "square";
}

/** Activity radius: 7 px for a quiet host up to 24 px for the busiest one. */
export function topologyNodeRadius(events: number, maxEvents: number): number {
  const safeMax = Number.isFinite(maxEvents) && maxEvents > 0 ? maxEvents : 1;
  const safeEvents = Number.isFinite(events) && events > 0 ? events : 0;
  const ratio = Math.min(1, Math.sqrt(safeEvents / safeMax));
  return 7 + ratio * 17;
}

// ---------------------------------------------------------------- helpers

function clampNumber(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, value));
}

function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface CleanNode {
  id: string;
  label: string;
  kind: TopologyKind;
  events: number;
  alerts: number;
  severity: string;
  lastSeen: number;
}

function sanitizeNode(node: TopologyNode): CleanNode | null {
  if (!node || typeof node.id !== "string") return null;
  const id = node.id.trim();
  if (id.length === 0) return null;
  const events = Number.isFinite(node.events) && node.events > 0 ? node.events : 0;
  const alerts = Number.isFinite(node.alerts) && node.alerts > 0 ? node.alerts : 0;
  const lastSeen = Number.isFinite(node.lastSeen) ? node.lastSeen : 0;
  return {
    id,
    label: typeof node.label === "string" && node.label.trim().length > 0 ? node.label : id,
    kind: normalizeTopologyKind(node.kind),
    events,
    alerts,
    severity: normalizeSeverity(node.severity),
    lastSeen,
  };
}

function sanitizeEdge(edge: TopologyEdge): TopologyEdge | null {
  if (!edge || typeof edge.source !== "string" || typeof edge.target !== "string") return null;
  const source = edge.source.trim();
  const target = edge.target.trim();
  if (source.length === 0 || target.length === 0 || source === target) return null;
  const events = Number.isFinite(edge.events) && edge.events > 0 ? edge.events : 0;
  return {
    source,
    target,
    events,
    transport: typeof edge.transport === "string" && edge.transport.length > 0 ? edge.transport : null,
    appProto: typeof edge.appProto === "string" && edge.appProto.length > 0 ? edge.appProto : null,
    severity: normalizeSeverity(edge.severity),
  };
}

function nodeOrder(left: CleanNode, right: CleanNode): number {
  if (right.events !== left.events) return right.events - left.events;
  if (right.alerts !== left.alerts) return right.alerts - left.alerts;
  return left.id < right.id ? -1 : left.id > right.id ? 1 : 0;
}

// ----------------------------------------------------------------- layout

interface Position {
  x: number;
  y: number;
}

function initialPositions(
  count: number,
  width: number,
  height: number,
  padding: number,
  random: () => number,
): Position[] {
  const centerX = width / 2;
  const centerY = height / 2;
  const baseRadius = Math.max(20, Math.min(width, height) / 2 - padding);
  if (count === 1) return [{ x: centerX, y: centerY }];
  const positions: Position[] = [];
  for (let index = 0; index < count; index += 1) {
    const angle = (index / count) * Math.PI * 2 + random() * 0.18;
    const radius = baseRadius * (0.55 + random() * 0.4);
    positions.push({
      x: centerX + Math.cos(angle) * radius,
      y: centerY + Math.sin(angle) * radius,
    });
  }
  return positions;
}

/**
 * Seeded Fruchterman-Reingold relaxation with a fixed iteration budget and a
 * bounding box. O(nodes^2) per iteration, which stays cheap because the caller
 * caps the rendered node count.
 */
function relax(
  count: number,
  edgePairs: ReadonlyArray<readonly [number, number]>,
  width: number,
  height: number,
  padding: number,
  iterations: number,
  seed: number,
): Position[] {
  const random = mulberry32(seed);
  const positions = initialPositions(count, width, height, padding, random);
  if (count <= 1) return positions;

  const centerX = width / 2;
  const centerY = height / 2;
  const k = Math.sqrt(((width - padding * 2) * (height - padding * 2)) / count) * 0.86;
  const dx = new Float64Array(count);
  const dy = new Float64Array(count);
  const budget = Math.max(1, Math.round(iterations));

  for (let iteration = 0; iteration < budget; iteration += 1) {
    const temperature = ((width + height) / 2) * 0.09 * (1 - iteration / budget) + 0.2;
    dx.fill(0);
    dy.fill(0);

    // Repulsion between every pair.
    for (let i = 0; i < count; i += 1) {
      const pi = positions[i];
      for (let j = i + 1; j < count; j += 1) {
        const pj = positions[j];
        let diffX = pi.x - pj.x;
        let diffY = pi.y - pj.y;
        if (diffX === 0 && diffY === 0) {
          diffX = (random() - 0.5) * 0.1;
          diffY = (random() - 0.5) * 0.1;
        }
        const distance = Math.max(0.05, Math.sqrt(diffX * diffX + diffY * diffY));
        const force = (k * k) / distance;
        const unitX = diffX / distance;
        const unitY = diffY / distance;
        dx[i] += unitX * force;
        dy[i] += unitY * force;
        dx[j] -= unitX * force;
        dy[j] -= unitY * force;
      }
    }

    // Attraction along observed conversations.
    for (const pair of edgePairs) {
      const left = positions[pair[0]];
      const right = positions[pair[1]];
      const diffX = left.x - right.x;
      const diffY = left.y - right.y;
      const distance = Math.max(0.05, Math.sqrt(diffX * diffX + diffY * diffY));
      const force = (distance * distance) / k;
      const unitX = diffX / distance;
      const unitY = diffY / distance;
      dx[pair[0]] -= unitX * force;
      dy[pair[0]] -= unitY * force;
      dx[pair[1]] += unitX * force;
      dy[pair[1]] += unitY * force;
    }

    // Weak gravity keeps disconnected hosts inside the frame.
    for (let i = 0; i < count; i += 1) {
      dx[i] += (centerX - positions[i].x) * 0.014;
      dy[i] += (centerY - positions[i].y) * 0.014;
    }

    const minX = padding;
    const maxX = width - padding;
    const minY = padding;
    const maxY = height - padding;
    for (let i = 0; i < count; i += 1) {
      const length = Math.sqrt(dx[i] * dx[i] + dy[i] * dy[i]);
      if (!Number.isFinite(length) || length <= 0) continue;
      const step = Math.min(length, temperature);
      positions[i].x = clampNumber(positions[i].x + (dx[i] / length) * step, minX, maxX);
      positions[i].y = clampNumber(positions[i].y + (dy[i] / length) * step, minY, maxY);
    }
  }

  return positions.map((position) => ({
    x: clampNumber(position.x, padding, width - padding),
    y: clampNumber(position.y, padding, height - padding),
  }));
}

// ------------------------------------------------------------------ public

/**
 * Prepare the render model: select the most active hosts, keep only edges
 * between them, lay everything out deterministically and derive colours,
 * shapes and edge weights.
 */
export function prepareTopology(
  data: Topology | null | undefined,
  options: TopologyLayoutOptions = {},
): PreparedTopology {
  const width = Math.max(200, Math.round(options.width ?? TOPOLOGY_WIDTH));
  const height = Math.max(160, Math.round(options.height ?? TOPOLOGY_HEIGHT));
  const padding = Math.max(16, Math.round(options.padding ?? 44));
  const maxNodes = Math.max(1, Math.round(options.maxNodes ?? TOPOLOGY_DEFAULT_MAX_NODES));
  const maxEdges = Math.max(0, Math.round(options.maxEdges ?? TOPOLOGY_DEFAULT_MAX_EDGES));
  const iterations = Math.max(1, Math.round(options.iterations ?? TOPOLOGY_DEFAULT_ITERATIONS));
  const seed = options.seed ?? TOPOLOGY_DEFAULT_SEED;

  const rawNodes = (data?.nodes ?? [])
    .map(sanitizeNode)
    .filter((node): node is CleanNode => node !== null);
  const rawEdges = (data?.edges ?? [])
    .map(sanitizeEdge)
    .filter((edge): edge is TopologyEdge => edge !== null);

  // Deduplicate host ids defensively; keep the most active record.
  const uniqueNodes: CleanNode[] = [];
  const seenIds = new Set<string>();
  for (const node of rawNodes.slice().sort(nodeOrder)) {
    if (seenIds.has(node.id)) continue;
    seenIds.add(node.id);
    uniqueNodes.push(node);
  }

  const selectedNodes = uniqueNodes.slice(0, maxNodes);
  const selectedIds = new Set(selectedNodes.map((node) => node.id));
  const maxEvents = selectedNodes.reduce((max, node) => Math.max(max, node.events), 0);

  const connectedEdges = rawEdges
    .filter((edge) => selectedIds.has(edge.source) && selectedIds.has(edge.target))
    .map((edge, index) => ({ edge, index }))
    .sort((left, right) => {
      if (right.edge.events !== left.edge.events) return right.edge.events - left.edge.events;
      if (left.edge.source !== right.edge.source) {
        return left.edge.source < right.edge.source ? -1 : 1;
      }
      if (left.edge.target !== right.edge.target) {
        return left.edge.target < right.edge.target ? -1 : 1;
      }
      return left.index - right.index;
    })
    .slice(0, maxEdges)
    .map((entry) => entry.edge);

  const maxEdgeEvents = connectedEdges.reduce((max, edge) => Math.max(max, edge.events), 0);

  const indexById = new Map<string, number>();
  selectedNodes.forEach((node, index) => indexById.set(node.id, index));
  const edgePairs = connectedEdges
    .map((edge) => {
      const source = indexById.get(edge.source);
      const target = indexById.get(edge.target);
      if (source === undefined || target === undefined) return null;
      return [source, target] as const;
    })
    .filter((pair): pair is readonly [number, number] => pair !== null);

  const positions = relax(
    selectedNodes.length,
    edgePairs,
    width,
    height,
    padding,
    iterations,
    seed,
  );

  const nodes: TopologyNodeLayout[] = selectedNodes.map((node, index) => {
    const position = positions[index] ?? { x: width / 2, y: height / 2 };
    return {
      ...node,
      x: position.x,
      y: position.y,
      radius: topologyNodeRadius(node.events, maxEvents),
      color: topologyNodeColor(node.kind, node.severity),
      shape: topologyNodeShape(node.kind),
    };
  });

  const edges: TopologyEdgeLayout[] = connectedEdges.map((edge, index) => {
    const ratio = maxEdgeEvents > 0 ? Math.min(1, edge.events / maxEdgeEvents) : 0;
    return {
      key: edge.source + "--" + edge.target + "--" + String(index),
      source: edge.source,
      target: edge.target,
      events: edge.events,
      transport: edge.transport,
      appProto: edge.appProto,
      severity: edge.severity,
      color: topologyEdgeColor(edge.severity),
      width: 0.9 + ratio * 3.1,
      opacity: 0.28 + ratio * 0.5,
    };
  });

  const maxLabels = Math.max(0, Math.round(options.maxLabels ?? TOPOLOGY_DEFAULT_MAX_LABELS));
  const labelIds = nodes.slice(0, maxLabels).map((node) => node.id);

  const totalNodes = uniqueNodes.length;
  const totalEdges = rawEdges.length;
  return {
    nodes,
    edges,
    labelIds,
    totalNodes,
    totalEdges,
    hiddenNodes: Math.max(0, totalNodes - nodes.length),
    hiddenEdges: Math.max(0, totalEdges - edges.length),
    truncated: totalNodes > nodes.length || totalEdges > edges.length,
    width,
    height,
  };
}
// ------------------------------------------------------------ truncation

export type TopologyTruncationState = "none" | "client" | "server" | "both";

export interface TopologyTruncation {
  state: TopologyTruncationState;
  message: string;
}

/**
 * Turns the two independent caps into one honest sentence.
 *
 * - none:   everything the data contained is visible
 * - client: this component hid hosts/conversations past maxNodes/maxEdges
 * - server: the backend returned only its busiest records (data.truncated)
 * - both:   a display limit hides more of an already capped result
 */
export function describeTruncation(
  prepared: PreparedTopology,
  serverTruncated: boolean,
): TopologyTruncation {
  const clientLimited = prepared.hiddenNodes > 0 || prepared.hiddenEdges > 0;
  if (!clientLimited && !serverTruncated) {
    return { state: "none", message: "" };
  }
  const parts: string[] = [];
  if (clientLimited) {
    const nodesPart =
      prepared.hiddenNodes > 0
        ? String(prepared.nodes.length) + " of " + String(prepared.totalNodes) + " hosts"
        : "all " + String(prepared.totalNodes) + " hosts";
    const edgesPart =
      prepared.hiddenEdges > 0
        ? String(prepared.edges.length) + " of " + String(prepared.totalEdges) + " conversations"
        : "all " + String(prepared.totalEdges) + " conversations";
    parts.push("Showing " + nodesPart + " and " + edgesPart + " (display limit).");
  }
  if (serverTruncated) {
    if (clientLimited) {
      parts.push("The server also returned only its busiest records; more may exist.");
    } else {
      parts.push(
        "Showing all " +
          String(prepared.totalNodes) +
          " returned hosts and " +
          String(prepared.totalEdges) +
          " returned conversations \u00b7 the server returned only its busiest records; more may exist.",
      );
    }
  }
  const state: TopologyTruncationState =
    clientLimited && serverTruncated ? "both" : clientLimited ? "client" : "server";
  return { state, message: parts.join(" ") };
}
