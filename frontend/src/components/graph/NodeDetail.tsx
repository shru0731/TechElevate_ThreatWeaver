import React from "react";
import { GraphNode, getRiskColor, getRiskLevel } from "../../types";

interface NodeDetailProps {
  node: GraphNode;
  onClose: () => void;
}

const RISK_BADGE: Record<string, string> = {
  safe: "bg-safe/10 text-safe border-safe/30",
  low: "bg-mid/10 text-mid border-mid/30",
  medium: "bg-warn/10 text-warn border-warn/30",
  high: "bg-danger/10 text-danger border-danger/30",
  critical: "bg-danger/20 text-danger border-danger/50 animate-pulse-slow",
};

const NodeDetail: React.FC<NodeDetailProps> = ({ node, onClose }) => {
  const riskColor = getRiskColor(node.risk);
  const riskLevel = getRiskLevel(node.risk);

  return (
    <div className="animate-fade-up bg-panel border border-border rounded-xl overflow-hidden shadow-2xl">
      {/* Header */}
      <div className="flex items-start justify-between p-4 border-b border-border">
        <div className="flex items-center gap-3">
          <div
            className="w-10 h-10 rounded-lg flex items-center justify-center text-lg border"
            style={{ borderColor: `${riskColor}40`, backgroundColor: `${riskColor}10` }}
          >
            {node.type === "router" ? "⬡" : node.type === "server" ? "▣" : node.type === "firewall" ? "⬔" : "◉"}
          </div>
          <div>
            <p className="text-text-primary font-display font-semibold text-sm">{node.label}</p>
            <p className="text-text-dim font-mono text-xs">{node.ip}</p>
          </div>
        </div>
        <button
          onClick={onClose}
          className="text-muted hover:text-text-secondary transition-colors text-lg leading-none mt-0.5"
        >
          ×
        </button>
      </div>

      <div className="p-4 space-y-4">
        {/* Risk meter */}
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[10px] font-mono text-text-dim uppercase tracking-widest">Risk Score</span>
            <span
              className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${RISK_BADGE[riskLevel]}`}
            >
              {riskLevel.toUpperCase()}
            </span>
          </div>
          <div className="h-1.5 bg-border rounded-full overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-700"
              style={{
                width: `${node.risk}%`,
                backgroundColor: riskColor,
                boxShadow: `0 0 8px ${riskColor}`,
              }}
            />
          </div>
          <div className="flex justify-between mt-1">
            <span className="text-[9px] font-mono text-text-dim">0</span>
            <span className="text-xs font-mono font-bold" style={{ color: riskColor }}>
              {node.risk.toFixed(1)}
            </span>
            <span className="text-[9px] font-mono text-text-dim">100</span>
          </div>
        </div>

        {/* Meta */}
        <div className="grid grid-cols-2 gap-2">
          {[
            { label: "Type", value: node.type },
            { label: "OS", value: node.os || "—" },
          ].map((item) => (
            <div key={item.label} className="bg-surface rounded-lg p-2.5 border border-border">
              <p className="text-[9px] font-mono text-text-dim uppercase tracking-wider mb-1">{item.label}</p>
              <p className="text-xs font-mono text-text-primary capitalize">{item.value}</p>
            </div>
          ))}
        </div>

        {/* Services */}
        {node.services && node.services.length > 0 && (
          <div>
            <p className="text-[9px] font-mono text-text-dim uppercase tracking-widest mb-2">Services</p>
            <div className="flex flex-wrap gap-1">
              {node.services.map((svc) => (
                <span key={svc} className="text-[10px] font-mono px-2 py-0.5 rounded bg-accent/5 border border-accent/20 text-accent/80">
                  {svc}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Vulnerabilities */}
        {node.vulnerabilities && node.vulnerabilities.length > 0 && (
          <div>
            <p className="text-[9px] font-mono text-danger uppercase tracking-widest mb-2">⚠ CVEs Detected</p>
            <div className="space-y-1">
              {node.vulnerabilities.map((cve) => (
                <div key={cve} className="flex items-center gap-2 text-[10px] font-mono text-danger/80 bg-danger/5 rounded px-2 py-1 border border-danger/20">
                  <span className="w-1 h-1 rounded-full bg-danger inline-block" />
                  {cve}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default NodeDetail;
