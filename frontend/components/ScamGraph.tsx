"use client";

import dynamic from "next/dynamic";
import { useMemo, useRef, useState } from "react";
import type { ForceGraphMethods, LinkObject, NodeObject } from "react-force-graph-2d";

export type ScamGraphNode = {
  id: string;
  type: string;
};

export type ScamGraphLink = {
  source: string;
  target: string;
};

export type ScamGraphData = {
  nodes: ScamGraphNode[];
  links: ScamGraphLink[];
};

const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), {
  ssr: false,
});

const TYPE_COLORS: Record<string, string> = {
  domain: "#22d3ee",
  ip: "#60a5fa",
  wallet: "#f97316",
  telegram: "#a78bfa",
  email: "#34d399",
  signal: "#ef4444",
};

const LEGEND_ITEMS = [
  { type: "domain", label: "Domain" },
  { type: "ip", label: "IP" },
  { type: "wallet", label: "Wallet" },
  { type: "telegram", label: "Telegram" },
  { type: "email", label: "Email" },
  { type: "signal", label: "Signal" },
];

export default function ScamGraph({ graph }: { graph: ScamGraphData }) {
  const graphRef = useRef<ForceGraphMethods | undefined>(undefined);
  const [focusedNodeId, setFocusedNodeId] = useState<string | null>(null);
  const hasData = graph.nodes.length > 0;

  const normalizedData = useMemo(() => {
    const nodes = graph.nodes.map((node) => ({
      ...node,
      color: TYPE_COLORS[node.type] || "#94a3b8",
      val: node.type === "domain" ? 8 : node.type === "wallet" ? 6 : 4,
    }));

    const links = graph.links.map((link) => ({
      source:
        typeof link.source === "string"
          ? link.source
          : (link.source as { id?: string }).id || "",
      target:
        typeof link.target === "string"
          ? link.target
          : (link.target as { id?: string }).id || "",
    }));

    return { nodes, links };
  }, [graph]);

  const endpointId = (endpoint: unknown): string => {
    if (typeof endpoint === "string" || typeof endpoint === "number") {
      return String(endpoint);
    }
    if (
      typeof endpoint === "object" &&
      endpoint !== null &&
      "id" in endpoint &&
      (typeof endpoint.id === "string" || typeof endpoint.id === "number")
    ) {
      return String(endpoint.id);
    }
    return "";
  };

  const connectedNodeIds = useMemo(() => {
    if (!focusedNodeId) return new Set<string>();
    const connected = new Set<string>([focusedNodeId]);
    for (const link of normalizedData.links) {
      const source = String(link.source);
      const target = String(link.target);
      if (source === focusedNodeId) connected.add(target);
      if (target === focusedNodeId) connected.add(source);
    }
    return connected;
  }, [focusedNodeId, normalizedData.links]);

  const handleZoomIn = () => {
    const current = graphRef.current?.zoom?.() ?? 1;
    graphRef.current?.zoom?.(current * 1.2, 250);
  };

  const handleZoomOut = () => {
    const current = graphRef.current?.zoom?.() ?? 1;
    graphRef.current?.zoom?.(current / 1.2, 250);
  };

  const handleFit = () => {
    graphRef.current?.zoomToFit?.(400, 60);
    setFocusedNodeId(null);
  };

  const shortId = (id: string) =>
    id.length > 26 ? `${id.slice(0, 23)}...` : id;

  return (
    <div className="glass-panel w-full overflow-hidden rounded-2xl border border-[var(--border-soft)] shadow-[0_14px_50px_rgba(4,12,22,0.44)]">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border-soft)] px-3 py-2">
        <div className="flex flex-wrap items-center gap-3">
          {LEGEND_ITEMS.map((item) => (
            <span
              key={item.type}
              className="mono inline-flex items-center gap-1.5 text-[10px] text-[#b6c7d5]"
            >
              <span
                className="w-2 h-2 rounded-full"
                style={{ backgroundColor: TYPE_COLORS[item.type] || "#94a3b8" }}
              />
              {item.label}
            </span>
          ))}
        </div>

        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={handleZoomOut}
            className="mono rounded border border-[var(--border-soft)] px-2 py-1 text-[10px] text-[var(--text-muted)] transition-colors hover:border-[var(--border-strong)] hover:text-white"
          >
            -
          </button>
          <button
            type="button"
            onClick={handleZoomIn}
            className="mono rounded border border-[var(--border-soft)] px-2 py-1 text-[10px] text-[var(--text-muted)] transition-colors hover:border-[var(--border-strong)] hover:text-white"
          >
            +
          </button>
          <button
            type="button"
            onClick={handleFit}
            className="mono rounded border border-[var(--border-soft)] px-2 py-1 text-[10px] text-[var(--text-muted)] transition-colors hover:border-[var(--border-strong)] hover:text-white"
          >
            Fit
          </button>
        </div>
      </div>

      <div className="h-[400px] w-full">
        {hasData ? (
          <ForceGraph2D
            ref={graphRef}
            width={900}
            height={400}
            graphData={normalizedData}
            nodeLabel={(node: NodeObject) => {
              const type =
                typeof node.type === "string" ? node.type : "infrastructure";
              return `${type}: ${String(node.id ?? "unknown")}`;
            }}
            nodeColor={(node: NodeObject) => {
              const color =
                typeof node.color === "string" ? node.color : "#94a3b8";
              if (!focusedNodeId) return color;
              return connectedNodeIds.has(String(node.id))
                ? color
                : "rgba(148,163,184,0.25)";
            }}
            nodeCanvasObjectMode={() => "after"}
            nodeCanvasObject={(node: NodeObject, ctx: CanvasRenderingContext2D) => {
              const label = shortId(String(node.id));
              const fontSize = 10;
              ctx.font = `${fontSize}px monospace`;
              ctx.fillStyle = "rgba(226,232,240,0.9)";
              ctx.fillText(label, (node.x || 0) + 6, (node.y || 0) + 3);
            }}
            linkDirectionalArrowLength={4}
            linkDirectionalArrowRelPos={1}
            linkColor={(link: LinkObject) => {
              if (!focusedNodeId) return "rgba(148,163,184,0.45)";
              const source = String(endpointId(link.source));
              const target = String(endpointId(link.target));
              return source === focusedNodeId || target === focusedNodeId
                ? "rgba(34,211,238,0.9)"
                : "rgba(148,163,184,0.12)";
            }}
            linkWidth={(link: LinkObject) => {
              if (!focusedNodeId) return 1.2;
              const source = String(endpointId(link.source));
              const target = String(endpointId(link.target));
              return source === focusedNodeId || target === focusedNodeId
                ? 2.2
                : 0.8;
            }}
            onNodeClick={(node: NodeObject) => {
              const id = String(node?.id || "");
              if (!id) return;
              setFocusedNodeId((prev) => (prev === id ? null : id));
            }}
          />
        ) : (
          <div className="mono flex h-full w-full items-center justify-center text-xs text-gray-500">
            No graph data yet
          </div>
        )}
      </div>

      <div className="mono flex flex-wrap items-center justify-between gap-2 border-t border-[var(--border-soft)] px-3 py-2 text-[10px] text-[#9cb2c4]">
        <span>Tip: click a node to focus connected infrastructure.</span>
        <span>
          {focusedNodeId ? `Focused: ${shortId(focusedNodeId)}` : "Focus: none"}
        </span>
      </div>
    </div>
  );
}
