import React, { useEffect, useRef, useCallback, useState } from "react";
import * as d3 from "d3";
import { GraphNode, GraphEdge, getRiskColor } from "../../types";
import { useAppDispatch } from "../../hooks/redux";
import { setSourceNode, setTargetNode } from "../../features/paths/pathsSlice";

interface NetworkGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  selectedNode: string | null;
  highlightedPath: string[] | null;
  onNodeClick: (nodeId: string) => void;
}

const NODE_RADIUS = 18;

const nodeIcon = (type: string) => {
  switch (type) {
    case "router": return "⬡";
    case "firewall": return "⬔";
    case "server": return "▣";
    case "endpoint": return "◉";
    default: return "●";
  }
};

const NetworkGraph: React.FC<NetworkGraphProps> = ({
  nodes,
  edges,
  selectedNode,
  highlightedPath,
  onNodeClick,
}) => {
  const dispatch = useAppDispatch();
  const svgRef = useRef<SVGSVGElement>(null);
  const simulationRef = useRef<d3.Simulation<GraphNode, GraphEdge> | null>(null);
  const zoomRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const gRef = useRef<d3.Selection<SVGGElement, unknown, null, undefined> | null>(null);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; nodeId: string } | null>(null);

  const getNodeColor = useCallback(
    (node: GraphNode) => {
      if (highlightedPath && highlightedPath.includes(node.id)) {
        return "#00d4ff";
      }
      return getRiskColor(node.risk);
    },
    [highlightedPath]
  );

  const isPathEdge = useCallback(
    (edge: GraphEdge) => {
      if (!highlightedPath || highlightedPath.length < 2) return false;
      const src = typeof edge.source === "string" ? edge.source : edge.source.id;
      const tgt = typeof edge.target === "string" ? edge.target : edge.target.id;
      for (let i = 0; i < highlightedPath.length - 1; i++) {
        if (
          (highlightedPath[i] === src && highlightedPath[i + 1] === tgt) ||
          (highlightedPath[i] === tgt && highlightedPath[i + 1] === src)
        )
          return true;
      }
      return false;
    },
    [highlightedPath]
  );

  // Hide context menu on any click outside
  useEffect(() => {
    const handleClick = () => setContextMenu(null);
    window.addEventListener("click", handleClick);
    return () => window.removeEventListener("click", handleClick);
  }, []);

  useEffect(() => {
    if (!svgRef.current || nodes.length === 0) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const width = svgRef.current.clientWidth || 800;
    const height = svgRef.current.clientHeight || 600;

    const simNodes = nodes.map((node) => ({ ...node }));
    const simEdges = edges.map((edge) => ({ ...edge }));

    // Defs: arrow markers + glow filter
    const defs = svg.append("defs");

    defs
      .append("marker")
      .attr("id", "arrow-default")
      .attr("viewBox", "0 -5 10 10")
      .attr("refX", NODE_RADIUS + 12)
      .attr("refY", 0)
      .attr("markerWidth", 6)
      .attr("markerHeight", 6)
      .attr("orient", "auto")
      .append("path")
      .attr("d", "M0,-5L10,0L0,5")
      .attr("fill", "#1e2d3d");

    defs
      .append("marker")
      .attr("id", "arrow-path")
      .attr("viewBox", "0 -5 10 10")
      .attr("refX", NODE_RADIUS + 12)
      .attr("refY", 0)
      .attr("markerWidth", 6)
      .attr("markerHeight", 6)
      .attr("orient", "auto")
      .append("path")
      .attr("d", "M0,-5L10,0L0,5")
      .attr("fill", "#00d4ff");

    const glowFilter = defs.append("filter").attr("id", "glow");
    glowFilter.append("feGaussianBlur").attr("stdDeviation", "3").attr("result", "coloredBlur");
    const feMerge = glowFilter.append("feMerge");
    feMerge.append("feMergeNode").attr("in", "coloredBlur");
    feMerge.append("feMergeNode").attr("in", "SourceGraphic");

    const pathGlow = defs.append("filter").attr("id", "pathGlow");
    pathGlow.append("feGaussianBlur").attr("stdDeviation", "4").attr("result", "coloredBlur");
    const feMerge2 = pathGlow.append("feMerge");
    feMerge2.append("feMergeNode").attr("in", "coloredBlur");
    feMerge2.append("feMergeNode").attr("in", "SourceGraphic");

    // Main group for zoom/pan
    const g = svg.append("g").attr("class", "zoom-group");
    gRef.current = g;

    // Zoom behavior
    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.2, 4])
      .on("zoom", (event) => {
        g.attr("transform", event.transform);
      });

    zoomRef.current = zoom;
    svg.call(zoom);

    // Double-click to reset zoom
    svg.on("dblclick.zoom", () => {
      svg
        .transition()
        .duration(600)
        .call(zoom.transform, d3.zoomIdentity.translate(width / 2, height / 2).scale(0.85));
    });

    // Initial transform
    svg.call(
      zoom.transform,
      d3.zoomIdentity.translate(width / 2, height / 2).scale(0.85)
    );

    // Edges
    const edgeGroup = g.append("g").attr("class", "edges");
    const edgeSel = edgeGroup
      .selectAll<SVGLineElement, GraphEdge>("line")
      .data(simEdges)
      .enter()
      .append("line")
      .attr("class", (d) => (isPathEdge(d) ? "animated-edge highlighted-edge" : "animated-edge"))
      .attr("stroke", (d) => (isPathEdge(d) ? "#00d4ff" : "#1e2d3d"))
      .attr("stroke-width", (d) => (isPathEdge(d) ? 2.5 : 1.2))
      .attr("stroke-opacity", (d) => (isPathEdge(d) ? 1 : 0.5))
      .attr("marker-end", (d) => `url(#${isPathEdge(d) ? "arrow-path" : "arrow-default"})`)
      .attr("filter", (d) => (isPathEdge(d) ? "url(#pathGlow)" : "none"))
      .attr("stroke-dasharray", "6 10")
      .attr("stroke-dashoffset", 0);

    // Edge labels (protocol)
    const edgeLabelGroup = g.append("g").attr("class", "edge-labels");
    const edgeLabels = edgeLabelGroup
      .selectAll<SVGTextElement, GraphEdge>("text")
      .data(simEdges.filter((e) => isPathEdge(e)))
      .enter()
      .append("text")
      .attr("font-size", "8px")
      .attr("fill", "#00d4ff80")
      .attr("text-anchor", "middle")
      .attr("font-family", "'JetBrains Mono', monospace")
      .text((d) => d.protocol || "");

    // Nodes
    const nodeGroup = g.append("g").attr("class", "nodes");
    const nodeSel = nodeGroup
      .selectAll<SVGGElement, GraphNode>("g.node")
      .data(simNodes, (d) => d.id)
      .enter()
      .append("g")
      .attr("class", "node")
      .attr("cursor", "pointer")
      .call(
        d3
          .drag<SVGGElement, GraphNode>()
          .on("start", (event, d) => {
            if (!event.active) simulationRef.current?.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on("drag", (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on("end", (event, d) => {
            if (!event.active) simulationRef.current?.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          })
      )
      .on("click", (event, d) => {
        event.stopPropagation();
        onNodeClick(d.id);
      })
      .on("contextmenu", function (event: MouseEvent, d: GraphNode) {
        event.preventDefault();
        setContextMenu({ x: event.clientX, y: event.clientY, nodeId: d.id });
      });

    // Outer ring (risk color halo)
    nodeSel
      .append("circle")
      .attr("r", NODE_RADIUS + 5)
      .attr("fill", "none")
      .attr("stroke", (d) => getNodeColor(d))
      .attr("stroke-width", 1)
      .attr("stroke-opacity", 0.3);

    // Node body
    nodeSel
      .append("circle")
      .attr("r", NODE_RADIUS)
      .attr("fill", "#0d1421")
      .attr("stroke", (d) => getNodeColor(d))
      .attr("stroke-width", (d) => (selectedNode === d.id ? 3 : 1.5))
      .attr("filter", (d) =>
        selectedNode === d.id || (highlightedPath && highlightedPath.includes(d.id))
          ? "url(#glow)"
          : "none"
      );

    // Risk fill arc
    nodeSel.each(function (d) {
      const group = d3.select(this);
      const arcGen = d3
        .arc<any>()
        .innerRadius(0)
        .outerRadius(NODE_RADIUS - 4)
        .startAngle(0)
        .endAngle((d.risk / 100) * 2 * Math.PI);
      group
        .append("path")
        .attr("d", arcGen({}))
        .attr("fill", getNodeColor(d))
        .attr("opacity", 0.2);
    });

    // Node label (below)
    nodeSel
      .append("text")
      .attr("y", NODE_RADIUS + 14)
      .attr("text-anchor", "middle")
      .attr("font-size", "9px")
      .attr("font-family", "'JetBrains Mono', monospace")
      .attr("fill", "#f2f8ff")
      .attr("opacity", 0.85)
      .text((d) => d.label);

    // Risk score text
    nodeSel
      .append("text")
      .attr("text-anchor", "middle")
      .attr("dominant-baseline", "central")
      .attr("font-size", "8px")
      .attr("font-family", "'JetBrains Mono', monospace")
      .attr("font-weight", "700")
      .attr("fill", (d) => getNodeColor(d))
      .text((d) => d.risk.toFixed(0));

    // Force simulation
    const simulation = d3
      .forceSimulation<GraphNode>(simNodes)
      .force(
        "link",
        d3
          .forceLink<GraphNode, GraphEdge>(simEdges)
          .id((d) => d.id)
          .distance(120)
          .strength(0.5)
      )
      .force("charge", d3.forceManyBody().strength(-400))
      .force("center", d3.forceCenter(0, 0))
      .force("collision", d3.forceCollide(NODE_RADIUS + 20))
      .alphaDecay(0.02);

    simulationRef.current = simulation;

    simulation.on("tick", () => {
      edgeSel
        .attr("x1", (d) => (d.source as GraphNode).x ?? 0)
        .attr("y1", (d) => (d.source as GraphNode).y ?? 0)
        .attr("x2", (d) => (d.target as GraphNode).x ?? 0)
        .attr("y2", (d) => (d.target as GraphNode).y ?? 0);

      edgeLabels
        .attr("x", (d) => {
          const sx = (d.source as GraphNode).x ?? 0;
          const tx = (d.target as GraphNode).x ?? 0;
          return (sx + tx) / 2;
        })
        .attr("y", (d) => {
          const sy = (d.source as GraphNode).y ?? 0;
          const ty = (d.target as GraphNode).y ?? 0;
          return (sy + ty) / 2 - 5;
        });

      nodeSel.attr("transform", (d) => `translate(${d.x ?? 0},${d.y ?? 0})`);
    });

    return () => {
      simulation.stop();
    };
  }, [nodes, edges]);

  // Update colors when highlighting changes
  useEffect(() => {
    if (!gRef.current) return;
    const g = gRef.current;

    g.selectAll<SVGLineElement, GraphEdge>("line")
      .attr("stroke", (d) => (isPathEdge(d) ? "#00d4ff" : "#1e2d3d"))
      .attr("stroke-width", (d) => (isPathEdge(d) ? 2.5 : 1.2))
      .attr("stroke-opacity", (d) => (isPathEdge(d) ? 1 : 0.5))
      .attr("marker-end", (d) => `url(#${isPathEdge(d) ? "arrow-path" : "arrow-default"})`)
      .attr("filter", (d) => (isPathEdge(d) ? "url(#pathGlow)" : "none"));

    g.selectAll<SVGGElement, GraphNode>("g.node").each(function (d) {
      const group = d3.select(this);
      const color = getNodeColor(d);
      const isHighlighted =
        selectedNode === d.id ||
        (highlightedPath && highlightedPath.includes(d.id));

      group
        .select("circle:nth-child(2)")
        .attr("stroke", color)
        .attr("stroke-width", isHighlighted ? 3 : 1.5)
        .attr("filter", isHighlighted ? "url(#glow)" : "none");

      group.select("circle:first-child").attr("stroke", color);
      group
        .select("text:last-of-type")
        .attr("fill", color);
    });
  }, [highlightedPath, selectedNode, getNodeColor, isPathEdge]);

  const handleZoomIn = () => {
    if (!svgRef.current || !zoomRef.current) return;
    d3.select(svgRef.current)
      .transition()
      .duration(300)
      .call(zoomRef.current.scaleBy, 1.4);
  };

  const handleZoomOut = () => {
    if (!svgRef.current || !zoomRef.current) return;
    d3.select(svgRef.current)
      .transition()
      .duration(300)
      .call(zoomRef.current.scaleBy, 0.7);
  };

  const handleZoomReset = () => {
    if (!svgRef.current || !zoomRef.current) return;
    const width = svgRef.current.clientWidth || 800;
    const height = svgRef.current.clientHeight || 600;
    d3.select(svgRef.current)
      .transition()
      .duration(500)
      .call(
        zoomRef.current.transform,
        d3.zoomIdentity.translate(width / 2, height / 2).scale(0.85)
      );
  };

  return (
    <div className="relative w-full h-full bg-void rounded-lg border border-border overflow-hidden graph-ambient">
      {/* Scanline overlay */}
      <div className="absolute inset-0 pointer-events-none opacity-[0.05] bg-grid-pattern bg-grid animate-scan" />
      <div className="absolute inset-0 pointer-events-none bg-gradient-radial opacity-10" />
      <div className="absolute inset-0 pointer-events-none bg-noise opacity-5" />
      <div className="moving-dots" />

      <svg ref={svgRef} className="w-full h-full" />

      {/* Zoom controls */}
      <div className="absolute bottom-4 right-4 flex flex-col gap-1.5">
        {[
          { label: "+", action: handleZoomIn, title: "Zoom In" },
          { label: "⊙", action: handleZoomReset, title: "Reset View" },
          { label: "−", action: handleZoomOut, title: "Zoom Out" },
        ].map((btn) => (
          <button
            key={btn.label}
            onClick={btn.action}
            title={btn.title}
            className="w-8 h-8 flex items-center justify-center rounded bg-surface border border-border text-text-secondary hover:border-accent hover:text-accent transition-all text-sm font-mono"
          >
            {btn.label}
          </button>
        ))}
      </div>

      {/* Legend */}
      <div className="absolute bottom-4 left-4 flex flex-col gap-1 bg-surface/80 backdrop-blur border border-border rounded-lg p-3">
        <p className="text-[9px] font-mono text-text-dim uppercase tracking-widest mb-1">Risk Level</p>
        {[
          { color: "#30d158", label: "Low   <30" },
          { color: "#ffd60a", label: "Med  30-60" },
          { color: "#ff9f0a", label: "High 60-80" },
          { color: "#ff2d55", label: "Crit  >80" },
        ].map((item) => (
          <div key={item.label} className="flex items-center gap-2">
            <div
              className="w-2 h-2 rounded-full"
              style={{ backgroundColor: item.color, boxShadow: `0 0 4px ${item.color}` }}
            />
            <span className="text-[9px] font-mono text-text-dim">{item.label}</span>
          </div>
        ))}
      </div>

      {/* Zoom instructions */}
      <div className="absolute top-3 left-1/2 -translate-x-1/2">
        <span className="text-[9px] font-mono text-text-dim bg-surface/60 px-2 py-1 rounded border border-border/50">
          scroll to zoom · drag to pan · dbl-click to reset · right-click node for options
        </span>
      </div>

      {/* Right-click context menu */}
      {contextMenu && (
        <div
          className="fixed z-50 bg-surface border border-border rounded-lg p-2 shadow-xl"
          style={{ left: contextMenu.x, top: contextMenu.y }}
          onMouseLeave={() => setContextMenu(null)}
        >
          <button
            className="block w-full text-left px-3 py-1.5 text-xs font-mono hover:bg-accent/10 hover:text-accent rounded transition"
            onClick={() => {
              dispatch(setSourceNode(contextMenu.nodeId));
              setContextMenu(null);
            }}
          >
            Set as Source
          </button>
          <button
            className="block w-full text-left px-3 py-1.5 text-xs font-mono hover:bg-accent/10 hover:text-accent rounded transition"
            onClick={() => {
              dispatch(setTargetNode(contextMenu.nodeId));
              setContextMenu(null);
            }}
          >
            Set as Target
          </button>
        </div>
      )}
    </div>
  );
};

export default NetworkGraph;