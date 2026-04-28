import React from "react";
import { useAppSelector, useAppDispatch } from "../../hooks/redux";
import { setActivePanel } from "../../features/ui/uiSlice";
import AttackPathsPanel from "../panels/AttackPathsPanel";
import RemediationPanel from "../panels/RemediationPanel";
import AlertsPanel from "../panels/AlertsPanel";
import { AttackPath } from "../../types";

interface RightPanelProps {
  onPathSelect: (path: AttackPath) => void;
}

const PANEL_TITLES = {
  graph: "Network Overview",
  paths: "Attack Path Analysis",
  remediation: "AI Remediation Plan",
  alerts: "Threat Alerts",
};

const RightPanel: React.FC<RightPanelProps> = ({ onPathSelect }) => {
  const dispatch = useAppDispatch();
  const { activePanel } = useAppSelector((s) => s.ui);

  const tabs = [
    { id: "graph", label: "Graph", icon: "⬡" },
    { id: "paths", label: "Paths", icon: "↯" },
    { id: "remediation", label: "Remediate", icon: "⚕" },
    { id: "alerts", label: "Alerts", icon: "⚡" },
  ] as const;

  return (
    <aside className="w-80 h-full flex flex-col bg-surface border-l border-border">
      {/* Tabs */}
      <div className="flex border-b border-border shrink-0">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => dispatch(setActivePanel(tab.id))}
            className={`flex-1 py-3 text-[10px] font-mono uppercase tracking-wider transition-all flex flex-col items-center gap-0.5 ${
              activePanel === tab.id
                ? "text-accent border-b-2 border-accent bg-accent/5"
                : "text-text-dim hover:text-text-secondary border-b-2 border-transparent"
            }`}
          >
            <span className="text-sm">{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>

      {/* Panel title */}
      <div className="px-4 py-3 border-b border-border shrink-0">
        <p className="text-xs font-display font-semibold text-text-primary">
          {PANEL_TITLES[activePanel]}
        </p>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-3 scrollbar-thin">
        {activePanel === "paths" && <AttackPathsPanel onPathSelect={onPathSelect} />}
        {activePanel === "remediation" && <RemediationPanel />}
        {activePanel === "alerts" && <AlertsPanel onPathSelect={onPathSelect} />}
        {activePanel === "graph" && <GraphInfoPanel />}
      </div>
    </aside>
  );
};

const GraphInfoPanel: React.FC = () => {
  const result = useAppSelector((s) => s.analysis.result);
  const selectedNodeId = useAppSelector((s) => s.analysis.selectedNode);

  if (!result) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-center gap-3">
        <span className="text-4xl opacity-30">⬡</span>
        <p className="text-text-dim font-body text-sm">No network data loaded.</p>
        <p className="text-text-dim font-mono text-xs">Run a new analysis to begin.</p>
      </div>
    );
  }

  const riskDist = {
    critical: result.nodes.filter((n) => n.risk >= 80).length,
    high: result.nodes.filter((n) => n.risk >= 60 && n.risk < 80).length,
    medium: result.nodes.filter((n) => n.risk >= 30 && n.risk < 60).length,
    low: result.nodes.filter((n) => n.risk < 30).length,
  };

  const selectedNode = selectedNodeId ? result.nodes.find((n) => n.id === selectedNodeId) : null;

  return (
    <div className="space-y-4 animate-fade-up">
      {/* Risk distribution */}
      <div className="bg-panel rounded-xl border border-border p-3">
        <p className="text-[9px] font-mono text-text-dim uppercase tracking-widest mb-3">
          Risk Distribution
        </p>
        <div className="space-y-2">
          {[
            { label: "Critical (>80)", count: riskDist.critical, color: "#ff2d55", max: result.nodes.length },
            { label: "High (60–80)", count: riskDist.high, color: "#ff9f0a", max: result.nodes.length },
            { label: "Medium (30–60)", count: riskDist.medium, color: "#ffd60a", max: result.nodes.length },
            { label: "Low (<30)", count: riskDist.low, color: "#30d158", max: result.nodes.length },
          ].map((item) => (
            <div key={item.label}>
              <div className="flex justify-between items-center mb-0.5">
                <span className="text-[9px] font-mono text-text-dim">{item.label}</span>
                <span className="text-[9px] font-mono" style={{ color: item.color }}>
                  {item.count}
                </span>
              </div>
              <div className="h-1 bg-border rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full"
                  style={{
                    width: `${(item.count / item.max) * 100}%`,
                    backgroundColor: item.color,
                  }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Node list */}
      <div>
        <p className="text-[9px] font-mono text-text-dim uppercase tracking-widest mb-2">
          All Nodes
        </p>
        <div className="space-y-1">
          {[...result.nodes]
            .sort((a, b) => b.risk - a.risk)
            .map((node) => {
              const color =
                node.risk >= 80
                  ? "#ff2d55"
                  : node.risk >= 60
                  ? "#ff9f0a"
                  : node.risk >= 30
                  ? "#ffd60a"
                  : "#30d158";
              return (
                <div
                  key={node.id}
                  className={`flex items-center gap-2.5 px-2.5 py-2 rounded-lg border transition-all ${
                    selectedNode?.id === node.id
                      ? "border-accent/40 bg-accent/5"
                      : "border-border hover:border-border/80 bg-panel/50"
                  }`}
                >
                  <div
                    className="w-2 h-2 rounded-full shrink-0"
                    style={{ backgroundColor: color, boxShadow: `0 0 4px ${color}` }}
                  />
                  <span className="text-xs font-body text-text-secondary flex-1 truncate">
                    {node.label}
                  </span>
                  <span
                    className="text-[10px] font-mono font-bold shrink-0"
                    style={{ color }}
                  >
                    {node.risk.toFixed(0)}
                  </span>
                </div>
              );
            })}
        </div>
      </div>
    </div>
  );
};

export default RightPanel;
