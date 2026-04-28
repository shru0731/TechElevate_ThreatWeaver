import React from "react";
import { useLocation } from "react-router-dom";
import { useAppSelector } from "../../hooks/redux";

const RightPanel: React.FC = () => {
  const location = useLocation();
  const result = useAppSelector((s) => s.analysis.result);
  const activePath = useAppSelector((s) => s.paths.paths.find((p) => p.id === s.paths.activePath));
  const plan = useAppSelector((s) => (s.remediation.activePlanId ? s.remediation.plans[s.remediation.activePlanId] : null));
  const pathCount = useAppSelector((s) => s.paths.paths.length);

  const getRouteTitle = () => {
    if (location.pathname.startsWith("/attack-paths")) return "Attack Path Summary";
    if (location.pathname.startsWith("/remediation")) return "Remediation Sidebar";
    if (location.pathname.startsWith("/alerts")) return "Alerts Summary";
    if (location.pathname.startsWith("/exports")) return "Export Guidance";
    if (location.pathname.startsWith("/profile")) return "Profile Snapshot";
    if (location.pathname.startsWith("/admin")) return "Admin Sidebar";
    return "Network Overview";
  };

  const renderDashboardSummary = () => {
    if (!result) {
      return (
        <div className="flex h-full items-center justify-center text-text-dim">
          No network data yet. Run a new analysis to populate the dashboard.
        </div>
      );
    }

    const riskDist = {
      critical: result.nodes.filter((n) => n.risk >= 80).length,
      high: result.nodes.filter((n) => n.risk >= 60 && n.risk < 80).length,
      medium: result.nodes.filter((n) => n.risk >= 30 && n.risk < 60).length,
      low: result.nodes.filter((n) => n.risk < 30).length,
    };

    return (
      <div className="space-y-4">
        <div className="rounded-3xl border border-border bg-panel p-4">
          <p className="text-[10px] font-mono text-text-dim uppercase tracking-[0.3em] mb-3">Overview</p>
          <p className="text-sm text-text-primary mb-3">Total nodes: {result.nodes.length}</p>
          <div className="space-y-2">
            {[
              { label: "Critical", value: riskDist.critical, color: "#ff2d55" },
              { label: "High", value: riskDist.high, color: "#ff9f0a" },
              { label: "Medium", value: riskDist.medium, color: "#ffd60a" },
              { label: "Low", value: riskDist.low, color: "#30d158" },
            ].map((item) => (
              <div key={item.label} className="flex items-center justify-between text-sm text-text-secondary">
                <span>{item.label}</span>
                <span className="font-semibold" style={{ color: item.color }}>
                  {item.value}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-3xl border border-border bg-panel p-4">
          <p className="text-[10px] font-mono text-text-dim uppercase tracking-[0.3em] mb-3">Current risk score</p>
          <p className="text-3xl font-display font-bold text-accent">{result.gnri.toFixed(1)}</p>
          <p className="mt-2 text-sm text-text-secondary">Higher values indicate greater network risk.</p>
        </div>
      </div>
    );
  };

  const renderAttackPathSummary = () => (
    <div className="space-y-4">
      <div className="rounded-3xl border border-border bg-panel p-4">
        <p className="text-[10px] font-mono text-text-dim uppercase tracking-[0.3em] mb-3">Paths found</p>
        <p className="text-3xl font-display font-bold text-white">{pathCount}</p>
        <p className="mt-2 text-sm text-text-secondary">Predicted attack paths available for review.</p>
      </div>
      <div className="rounded-3xl border border-border bg-panel p-4 text-sm text-text-secondary">
        Select a path to surface remediation guidance and see where it traverses the network.
      </div>
    </div>
  );

  const renderRemediationSummary = () => (
    <div className="space-y-4">
      {plan ? (
        <div className="rounded-3xl border border-border bg-panel p-4">
          <p className="text-[10px] font-mono text-text-dim uppercase tracking-[0.3em] mb-3">Active plan</p>
          <p className="text-lg font-semibold text-white">{plan.summary || "Remediation plan ready"}</p>
          <p className="mt-2 text-sm text-text-secondary">Confidence {plan.confidence?.toFixed(2) ?? "N/A"}</p>
        </div>
      ) : (
        <div className="rounded-3xl border border-border bg-panel p-4 text-sm text-text-dim">
          No remediation plan selected yet. Select a path to generate recommendations.
        </div>
      )}
    </div>
  );

  const renderAlertsSummary = () => (
    <div className="space-y-4">
      <div className="rounded-3xl border border-border bg-panel p-4">
        <p className="text-[10px] font-mono text-text-dim uppercase tracking-[0.3em] mb-3">Alert health</p>
        <p className="text-lg font-display font-bold text-white">{pathCount} predicted paths</p>
        <p className="mt-2 text-sm text-text-secondary">Critical and high-risk paths are prioritized for review.</p>
      </div>
    </div>
  );

  const renderExportsSummary = () => (
    <div className="space-y-4">
      <div className="rounded-3xl border border-border bg-panel p-4">
        <p className="text-[10px] font-mono text-text-dim uppercase tracking-[0.3em] mb-3">Export guidance</p>
        <p className="text-sm text-text-secondary">Download your analysis snapshots in PDF, JSON, or CSV format.</p>
      </div>
    </div>
  );

  const renderContextContent = () => {
    if (location.pathname.startsWith("/attack-paths")) return renderAttackPathSummary();
    if (location.pathname.startsWith("/remediation")) return renderRemediationSummary();
    if (location.pathname.startsWith("/alerts")) return renderAlertsSummary();
    if (location.pathname.startsWith("/exports")) return renderExportsSummary();
    return renderDashboardSummary();
  };

  return (
    <aside className="w-80 h-full flex flex-col bg-surface border-l border-border">
      <div className="px-4 py-3 border-b border-border shrink-0">
        <p className="text-xs font-display font-semibold text-text-primary">{getRouteTitle()}</p>
      </div>
      <div className="flex-1 overflow-y-auto p-3 scrollbar-thin">{renderContextContent()}</div>
    </aside>
  );
};

export default RightPanel;
