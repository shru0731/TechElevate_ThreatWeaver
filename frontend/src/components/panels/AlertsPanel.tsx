import React from "react";
import { useNavigate } from "react-router-dom";
import { useAppDispatch, useAppSelector } from "../../hooks/redux";
import { setActivePath } from "../../features/paths/pathsSlice";
import { fetchRemediation } from "../../features/remediation/remediationSlice";
import { AttackPath } from "../../types";

const AlertsPanel: React.FC<{ onPathSelect: (path: AttackPath) => void }> = ({ onPathSelect }) => {
  const dispatch = useAppDispatch();
  const paths = useAppSelector((s) => s.paths.paths);
  const nodes = useAppSelector((s) => s.analysis.result?.nodes || []);
  const gnri = useAppSelector((s) => s.analysis.result?.gnri);

  const getLabel = (id: string) => nodes.find((n) => n.id === id)?.label || id;

  const formatRisk = (risk: number | undefined) =>
    Number.isFinite(risk) ? risk.toFixed(1) : "N/A";

  const formatLikelihood = (likelihood: number | undefined) =>
    Number.isFinite(likelihood) ? `${(likelihood * 100).toFixed(0)}%` : "N/A";

  const getSafeNodes = (path: AttackPath) =>
    Array.isArray(path.nodes) ? path.nodes : [];

  const criticalPaths = paths.filter((p) => p.risk >= 90);
  const highPaths = paths.filter((p) => p.risk >= 75 && p.risk < 90);
  const medPaths = paths.filter((p) => p.risk < 75);

  const navigate = useNavigate();

  const handleAlertClick = (path: AttackPath) => {
    dispatch(setActivePath(path.id));
    onPathSelect(path);
    dispatch(fetchRemediation(path.id));
    navigate("/remediation");
  };

  if (paths.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-center gap-3">
        <span className="text-4xl opacity-30">⚡</span>
        <p className="text-text-dim font-body text-sm">No alerts yet.</p>
        <p className="text-text-dim font-mono text-xs">Run an analysis to detect threats.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4 animate-fade-up">
      {/* GNRI Alert */}
      {gnri !== undefined && gnri >= 70 && (
        <div className="rounded-xl border border-danger/50 bg-danger/5 p-3.5 flex items-start gap-3">
          <div className="w-6 h-6 rounded-full bg-danger/20 flex items-center justify-center shrink-0 mt-0.5 animate-pulse-slow">
            <span className="text-danger text-xs">!</span>
          </div>
          <div>
            <p className="text-xs font-display font-bold text-danger">Network Risk Elevated</p>
            <p className="text-[10px] font-mono text-text-secondary mt-0.5">
              GNRI score of {Number.isFinite(gnri) ? gnri.toFixed(1) : "N/A"} indicates significant exposure across the network.
            </p>
          </div>
        </div>
      )}

      {/* Summary row */}
      <div className="grid grid-cols-3 gap-2">
        {[
          { count: criticalPaths.length, label: "Critical", color: "text-danger", bg: "bg-danger/10 border-danger/30" },
          { count: highPaths.length, label: "High", color: "text-warn", bg: "bg-warn/10 border-warn/30" },
          { count: medPaths.length, label: "Medium", color: "text-mid", bg: "bg-mid/10 border-mid/30" },
        ].map((item) => (
          <div key={item.label} className={`rounded-lg border ${item.bg} p-2.5 text-center`}>
            <p className={`text-2xl font-display font-bold ${item.color}`}>{item.count}</p>
            <p className="text-[9px] font-mono text-text-dim uppercase tracking-wider">{item.label}</p>
          </div>
        ))}
      </div>

      {/* Critical alerts */}
      {criticalPaths.length > 0 && (
        <div>
          <p className="text-[9px] font-mono text-danger uppercase tracking-widest mb-2 flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-danger animate-pulse inline-block" />
            Critical Threats
          </p>
          <div className="space-y-2">
            {criticalPaths.map((path) => (
              <AlertCard
                key={path.id}
                path={path}
                getLabel={getLabel}
                onClick={() => handleAlertClick(path)}
                severity="critical"
              />
            ))}
          </div>
        </div>
      )}

      {/* High alerts */}
      {highPaths.length > 0 && (
        <div>
          <p className="text-[9px] font-mono text-warn uppercase tracking-widest mb-2 flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-warn inline-block" />
            High Risk
          </p>
          <div className="space-y-2">
            {highPaths.map((path) => (
              <AlertCard
                key={path.id}
                path={path}
                getLabel={getLabel}
                onClick={() => handleAlertClick(path)}
                severity="high"
              />
            ))}
          </div>
        </div>
      )}

      {/* Medium/low */}
      {medPaths.length > 0 && (
        <div>
          <p className="text-[9px] font-mono text-mid uppercase tracking-widest mb-2 flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-mid inline-block" />
            Medium Risk
          </p>
          <div className="space-y-2">
            {medPaths.map((path) => (
              <AlertCard
                key={path.id}
                path={path}
                getLabel={getLabel}
                onClick={() => handleAlertClick(path)}
                severity="medium"
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

const SEVERITY_STYLES = {
  critical: "border-danger/40 bg-danger/5 hover:border-danger/70",
  high: "border-warn/30 bg-warn/5 hover:border-warn/60",
  medium: "border-mid/30 bg-mid/5 hover:border-mid/60",
};

const SEVERITY_SCORE_COLOR = {
  critical: "text-danger",
  high: "text-warn",
  medium: "text-mid",
};

const AlertCard: React.FC<{
  path: AttackPath;
  getLabel: (id: string) => string;
  onClick: () => void;
  severity: "critical" | "high" | "medium";
}> = ({ path, getLabel, onClick, severity }) => (
  <div
    onClick={onClick}
    className={`rounded-lg border ${SEVERITY_STYLES[severity]} p-3 cursor-pointer transition-all`}
  >
    <div className="flex items-center justify-between mb-1.5">
      <div className="flex items-center gap-2">
        {severity === "critical" && (
          <span className="w-2 h-2 rounded-full bg-danger animate-pulse" />
        )}
        <span className={`text-sm font-display font-bold ${SEVERITY_SCORE_COLOR[severity]}`}>
          {formatRisk(path.risk)}
        </span>
        <span className="text-[9px] font-mono text-text-dim">risk score</span>
      </div>
      <span className="text-[9px] font-mono text-text-dim">
        {formatLikelihood(path.likelihood)} likely
      </span>
    </div>
    <div className="flex items-center gap-1 flex-wrap">
      {getSafeNodes(path).slice(0, 4).map((nodeId, ni, arr) => (
        <React.Fragment key={nodeId}>
          <span className="text-[9px] font-mono text-text-dim">{getLabel(nodeId)}</span>
          {ni < arr.length - 1 && <span className="text-[9px] text-text-dim">›</span>}
        </React.Fragment>
      ))}
      {getSafeNodes(path).length > 4 && (
        <span className="text-[9px] font-mono text-text-dim">+{getSafeNodes(path).length - 4}</span>
      )}
    </div>
  </div>
);

export default AlertsPanel;
