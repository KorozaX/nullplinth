import { useCallback, useEffect, useMemo, useState } from "react";

import type { Topology, TopologyNode } from "../types/contracts";
import { formatNumber, formatTimestamp } from "../lib/format";
import { severityLabel } from "../lib/semantic";
import {
  TOPOLOGY_DEFAULT_MAX_EDGES,
  TOPOLOGY_DEFAULT_MAX_LABELS,
  TOPOLOGY_DEFAULT_MAX_NODES,
  describeTruncation,
  prepareTopology,
  topologyKindLabel,
} from "../lib/topologyLayout";
import type { TopologyNodeLayout } from "../lib/topologyLayout";

export interface TopologyGraphProps {
  /** Real topology from api.networkTopology(); no data means the honest empty state. */
  data: Topology | null | undefined;
  /** Called with the clicked/activated host, or null when the selection is cleared. */
  onSelectNode?: (node: TopologyNode | null) => void;
  /** Optional controlled selection (host id). When set, the component does not keep its own. */
  selectedNodeId?: string | null;
  /** Render cap for hosts (default 80, most active first). */
  maxNodes?: number;
  /** Render cap for conversations (default 240, busiest first). */
  maxEdges?: number;
  /** How many of the most active hosts keep an always-visible label (default 8). */
  maxLabels?: number;
  /** Extra class on the figure element (the container owner styles the frame). */
  className?: string;
  /** Optional accessible name for the SVG graph. */
  ariaLabel?: string;
}

const LEGEND: ReadonlyArray<{
  key: string;
  label: string;
  color: string;
  shape: "circle" | "diamond" | "square";
}> = [
  { key: "external", label: "External host", color: "var(--teal)", shape: "diamond" },
  { key: "internal", label: "Internal host", color: "var(--lime)", shape: "circle" },
  { key: "high", label: "High / medium alert", color: "var(--orange)", shape: "circle" },
  { key: "critical", label: "Critical alert", color: "var(--coral)", shape: "circle" },
  { key: "unknown", label: "Unknown host", color: "var(--gray)", shape: "square" },
];

function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    const query = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduced(query.matches);
    const onChange = (event: MediaQueryListEvent) => setReduced(event.matches);
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, []);
  return reduced;
}

function nodeAriaLabel(node: TopologyNodeLayout): string {
  const alerts =
    node.alerts === 0
      ? "no alerts"
      : formatNumber(node.alerts) + (node.alerts === 1 ? " alert" : " alerts");
  return [
    node.label,
    node.id,
    topologyKindLabel(node.kind) + " host",
    formatNumber(node.events) + " events",
    alerts,
    "severity " + severityLabel(node.severity),
    "last seen " + formatTimestamp(node.lastSeen, "analyst"),
  ].join(", ");
}

function NodeShape({
  node,
  selected,
}: {
  node: TopologyNodeLayout;
  selected: boolean;
}) {
  const strokeWidth = selected ? 2.6 : 1.2;
  const shared = {
    className: "topology-node__shape",
    fill: node.color,
    fillOpacity: 0.88,
    stroke: node.color,
    strokeWidth,
    strokeOpacity: 1,
    "data-shape": node.shape,
  };
  if (node.shape === "diamond") {
    const radius = node.radius;
    const path =
      "M 0 " + String(-radius) + " L " + String(radius) + " 0 L 0 " +
      String(radius) + " L " + String(-radius) + " 0 Z";
    return <path {...shared} d={path} />;
  }
  if (node.shape === "square") {
    const half = node.radius * 0.82;
    return (
      <rect
        {...shared}
        x={-half}
        y={-half}
        width={half * 2}
        height={half * 2}
        rx={3}
      />
    );
  }
  return <circle {...shared} r={node.radius} />;
}

/**
 * Flagship Overview visualisation: a pure-SVG relationship graph built only from
 * observed hosts (nodes) and observed conversations (edges). Layout is memoised
 * and deterministic; the component never invents nodes, edges or severity.
 */
export function TopologyGraph({
  data,
  onSelectNode,
  selectedNodeId,
  maxNodes = TOPOLOGY_DEFAULT_MAX_NODES,
  maxEdges = TOPOLOGY_DEFAULT_MAX_EDGES,
  maxLabels = TOPOLOGY_DEFAULT_MAX_LABELS,
  className,
  ariaLabel,
}: TopologyGraphProps) {
  const reducedMotion = usePrefersReducedMotion();
  const [internalSelected, setInternalSelected] = useState<string | null>(null);
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [focusedId, setFocusedId] = useState<string | null>(null);

  const options = useMemo(
    () => ({ maxNodes, maxEdges, maxLabels }),
    [maxNodes, maxEdges, maxLabels],
  );
  const layout = useMemo(() => prepareTopology(data, options), [data, options]);

  const nodeLookup = useMemo(() => {
    const map = new Map<string, TopologyNodeLayout>();
    for (const node of layout.nodes) map.set(node.id, node);
    return map;
  }, [layout]);

  /** Permanent labels for the busiest hosts; every other label appears on hover/focus/select. */
  const labelIds = useMemo(() => new Set(layout.labelIds), [layout]);

  const requestedSelection = selectedNodeId !== undefined ? selectedNodeId : internalSelected;
  const activeSelection = useMemo(() => {
    if (!requestedSelection) return null;
    return nodeLookup.has(requestedSelection) ? requestedSelection : null;
  }, [nodeLookup, requestedSelection]);

  const neighbourIds = useMemo(() => {
    const ids = new Set<string>();
    if (!activeSelection) return ids;
    for (const edge of layout.edges) {
      if (edge.source === activeSelection) ids.add(edge.target);
      if (edge.target === activeSelection) ids.add(edge.source);
    }
    return ids;
  }, [activeSelection, layout.edges]);

  const applySelection = useCallback(
    (id: string | null) => {
      if (selectedNodeId === undefined) setInternalSelected(id);
      const next =
        id === null ? null : data?.nodes.find((node) => node.id === id) ?? null;
      onSelectNode?.(next);
    },
    [data, onSelectNode, selectedNodeId],
  );

  const toggleSelection = useCallback(
    (id: string) => {
      applySelection(activeSelection === id ? null : id);
    },
    [activeSelection, applySelection],
  );

  const tooltipNode = nodeLookup.get(hoveredId ?? focusedId ?? "") ?? null;

  const hasNodes = layout.nodes.length > 0;
  const hasEdges = layout.edges.length > 0;
  const anyEdgeInData = (data?.edges.length ?? 0) > 0;
  const serverTruncated = Boolean(data?.truncated);
  const truncation = useMemo(
    () => describeTruncation(layout, serverTruncated),
    [layout, serverTruncated],
  );
  const graphLabel =
    ariaLabel ??
    "Network topology graph with " +
      String(layout.nodes.length) +
      " hosts and " +
      String(layout.edges.length) +
      " conversations";
  const rootClass = "topology-graph" + (className ? " " + className : "");

  if (!hasNodes) {
    return (
      <div className={rootClass} data-testid="topology-empty" role="status">
        <p className="topology-graph__empty-title">No hosts observed yet.</p>
        <p className="muted">
          Import security events or load the demo dataset; the graph then draws
          the hosts and conversations those records actually mention.
        </p>
      </div>
    );
  }

  if (!hasEdges) {
    return (
      <div className={rootClass} data-testid="topology-empty" role="status">
        <p className="topology-graph__empty-title">
          {anyEdgeInData
            ? "No conversations between the hosts shown here."
            : "Hosts observed, but no conversations yet."}
        </p>
        <p className="muted">
          {anyEdgeInData
            ? "The display limit selected hosts that have no recorded source/target pair. Raise the limit to include their conversations."
            : "Records mention these hosts, but no event or alert has linked a source to a destination between them yet."}
        </p>
      </div>
    );
  }

  const tooltipLeft = tooltipNode
    ? (tooltipNode.x / layout.width) * 100
    : 0;
  const tooltipTop = tooltipNode
    ? (tooltipNode.y / layout.height) * 100
    : 0;

  return (
    <figure
      className={rootClass}
      data-motion={reducedMotion ? "off" : "on"}
      data-testid="topology-graph"
      style={{ margin: 0, position: "relative" }}
    >
      <div style={{ position: "relative", width: "100%" }}>
        <svg
          className="topology-graph__svg"
          viewBox={"0 0 " + String(layout.width) + " " + String(layout.height)}
          role="group"
          aria-label={graphLabel}
          style={{ display: "block", width: "100%", height: "auto" }}
        >
          <rect
            className="topology-graph__surface"
            x={0}
            y={0}
            width={layout.width}
            height={layout.height}
            fill="transparent"
            aria-hidden="true"
            onClick={() => applySelection(null)}
          />
          <g className="topology-graph__edges" aria-hidden="true">
            {layout.edges.map((edge) => {
              const source = nodeLookup.get(edge.source);
              const target = nodeLookup.get(edge.target);
              if (!source || !target) return null;
              const highlighted =
                activeSelection !== null &&
                (edge.source === activeSelection || edge.target === activeSelection);
              const dimmed = activeSelection !== null && !highlighted;
              const classes =
                "topology-edge" +
                (highlighted ? " is-highlighted" : "") +
                (dimmed ? " is-dimmed" : "");
              return (
                <line
                  key={edge.key}
                  className={classes}
                  data-testid="topology-edge"
                  data-severity={edge.severity}
                  data-edge-source={edge.source}
                  data-edge-target={edge.target}
                  x1={source.x}
                  y1={source.y}
                  x2={target.x}
                  y2={target.y}
                  stroke={edge.color}
                  strokeWidth={highlighted ? edge.width + 0.8 : edge.width}
                  strokeOpacity={highlighted ? 0.95 : dimmed ? 0.1 : edge.opacity}
                  strokeLinecap="round"
                />
              );
            })}
          </g>
          <g className="topology-graph__nodes">
            {layout.nodes.map((node) => {
              const isSelected = activeSelection === node.id;
              const isNeighbour = neighbourIds.has(node.id);
              const dimmed =
                activeSelection !== null && !isSelected && !isNeighbour;
              const classes =
                "topology-node" +
                (isSelected ? " is-selected" : "") +
                (isNeighbour ? " is-neighbour" : "") +
                (dimmed ? " is-dimmed" : "");
              const showLabel =
                labelIds.has(node.id) ||
                isSelected ||
                hoveredId === node.id ||
                focusedId === node.id;
              return (
                <g
                  key={node.id}
                  className={classes}
                  data-testid="topology-node"
                  data-node-id={node.id}
                  data-kind={node.kind}
                  data-severity={node.severity}
                  data-shape={node.shape}
                  data-color={node.color}
                  data-selected={isSelected ? "true" : "false"}
                  transform={"translate(" + String(node.x) + " " + String(node.y) + ")"}
                  role="button"
                  tabIndex={0}
                  aria-label={nodeAriaLabel(node)}
                  aria-pressed={isSelected}
                  style={{
                    cursor: "pointer",
                    opacity: dimmed ? 0.35 : 1,
                    transition: reducedMotion ? "none" : "opacity var(--t-fast) var(--ease)",
                  }}
                  onClick={(event) => {
                    event.stopPropagation();
                    toggleSelection(node.id);
                  }}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " " || event.key === "Spacebar") {
                      event.preventDefault();
                      toggleSelection(node.id);
                    } else if (event.key === "Escape") {
                      event.preventDefault();
                      applySelection(null);
                    }
                  }}
                  onMouseEnter={() => setHoveredId(node.id)}
                  onMouseLeave={() => setHoveredId(null)}
                  onFocus={() => setFocusedId(node.id)}
                  onBlur={() => setFocusedId(null)}
                >
                  <NodeShape node={node} selected={isSelected} />
                  {node.alerts > 0 ? (
                    <g
                      className="topology-node__alert-badge"
                      transform={
                        "translate(" + String(node.radius * 0.78) + " " + String(-node.radius * 0.78) + ")"
                      }
                    >
                      <circle r={7} fill="var(--coral)" stroke="var(--bg)" strokeWidth={1} />
                      <text
                        textAnchor="middle"
                        y={3}
                        fontSize={8}
                        fontWeight={700}
                        fill="var(--bg)"
                      >
                        {node.alerts > 99 ? "99+" : String(node.alerts)}
                      </text>
                    </g>
                  ) : null}
                  {showLabel ? (
                    <text
                      className="topology-node__label"
                      y={node.radius + 13}
                      textAnchor="middle"
                      fontSize={10}
                      fill="var(--fg-secondary)"
                      style={{ pointerEvents: "none", fontFamily: "var(--font-mono)" }}
                    >
                      {node.label}
                    </text>
                  ) : null}
                </g>
              );
            })}
          </g>
        </svg>
        {tooltipNode ? (
          <div
            className="topology-tooltip"
            data-testid="topology-tooltip"
            role="tooltip"
            style={{
              position: "absolute",
              left: String(tooltipLeft) + "%",
              top: String(tooltipTop) + "%",
              transform: "translate(-50%, calc(-100% - 12px))",
              pointerEvents: "none",
              background: "var(--surface-2)",
              border: "1px solid var(--line-strong)",
              borderRadius: "var(--r-sm)",
              boxShadow: "var(--shadow-panel)",
              padding: "8px 10px",
              minWidth: "180px",
              zIndex: 5,
            }}
          >
            <div
              className="mono"
              style={{ color: "var(--fg)", fontSize: "var(--fs-sm)", fontWeight: 600 }}
            >
              {tooltipNode.id}
            </div>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "auto auto",
                gap: "2px 10px",
                marginTop: "6px",
                fontSize: "var(--fs-xs)",
                color: "var(--fg-secondary)",
              }}
            >
              <span style={{ color: "var(--fg-muted)" }}>Kind</span>
              <span>{topologyKindLabel(tooltipNode.kind)}</span>
              <span style={{ color: "var(--fg-muted)" }}>Severity</span>
              <span
                style={{
                  color: tooltipNode.color,
                  fontWeight: 600,
                }}
              >
                {severityLabel(tooltipNode.severity)}
              </span>
              <span style={{ color: "var(--fg-muted)" }}>Events</span>
              <span>{formatNumber(tooltipNode.events)}</span>
              <span style={{ color: "var(--fg-muted)" }}>Alerts</span>
              <span>{formatNumber(tooltipNode.alerts)}</span>
              <span style={{ color: "var(--fg-muted)" }}>Last seen</span>
              <span className="mono">
                {formatTimestamp(tooltipNode.lastSeen, "analyst")}
              </span>
            </div>
          </div>
        ) : null}
      </div>
      <figcaption className="sr-only">
        {"Network topology derived from stored events and alerts: " +
          String(layout.nodes.length) +
          " hosts and " +
          String(layout.edges.length) +
          " conversations rendered." +
          (truncation.state === "none"
            ? ""
            : " Display limits or the server cap may hide some relationships.")}
      </figcaption>
      <div
        className="topology-graph__legend"
        data-testid="topology-legend"
        aria-label="Topology legend"
        style={{
          display: "flex",
          flexWrap: "wrap",
          alignItems: "center",
          gap: "var(--s-4)",
          marginTop: "var(--s-4)",
        }}
      >
        {LEGEND.map((item) => (
          <span
            key={item.key}
            className="topology-legend__item"
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "var(--s-2)",
              fontSize: "var(--fs-xs)",
              color: "var(--fg-secondary)",
            }}
          >
            <span
              aria-hidden="true"
              style={{
                display: "inline-block",
                width: 10,
                height: 10,
                background: item.color,
                borderRadius: item.shape === "circle" ? "50%" : "2px",
                transform: item.shape === "diamond" ? "rotate(45deg)" : undefined,
              }}
            />
            {item.label}
          </span>
        ))}
        <span
          className="topology-legend__item"
          style={{ fontSize: "var(--fs-xs)", color: "var(--fg-muted)" }}
        >
          Line thickness = conversation volume
        </span>
      </div>
      {truncation.state !== "none" ? (
        <p
          className="topology-graph__truncation muted"
          data-testid="topology-truncation"
          data-state={truncation.state}
          style={{ marginTop: "var(--s-2)", fontSize: "var(--fs-xs)" }}
        >
          {truncation.message}
        </p>
      ) : null}
    </figure>
  );
}
