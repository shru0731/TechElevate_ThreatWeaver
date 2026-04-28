import React from "react";
import { useNavigate } from "react-router-dom";
import { useAppDispatch, useAppSelector } from "../../hooks/redux";
import { setActivePath } from "../../features/paths/pathsSlice";
import { fetchRemediation } from "../../features/remediation/remediationSlice";
import { AttackPath } from "../../types";

const riskBg = (risk: number) => {
  if (risk >= 90) return "border-danger/40 bg-danger/5";
  if (risk >= 75) return "border-warn/40 bg-warn/5";
  return "border-mid/40 bg-mid/5";
};

const riskText = (risk: number) => {
  if (risk >= 90) return "text-danger";
  if (risk >= 75) return "text-warn";
  return "text-mid";
};

interface Props {
  onPathSelect: (path: AttackPath) => void;
}

const AttackPathsPanel: React.FC<Props> = ({ onPathSelect }) => {
  const dispatch = useAppDispatch();
  const { paths, loading, activePath } = useAppSelector((s) => s.paths);
  const nodes = useAppSelector((s) => s.analysis.result?.nodes || []);

  const getLabel = (id: string) =>
    nodes.find((n) => n.id === id)?.label || id;

  const formatRisk = (risk: number | undefined) =>
    Number.isFinite(risk) ? risk.toFixed(1) : "N/A";

  const formatLikelihood = (likelihood: number | undefined) =>
    Number.isFinite(likelihood) ? `${(likelihood * 100).toFixed(0)}%` : "N/A";

  const getSafeRisk = (risk: number | undefined) =>
    Number.isFinite(risk) ? risk : 0;

  const getSafeLikelihood = (likelihood: number | undefined) =>
    Number.isFinite(likelihood) ? Math.max(0, Math.min(1, likelihood)) : 0;

  const handlePathClick = (path: AttackPath) => {
    dispatch(setActivePath(path.id));
    onPathSelect(path);
  };

  const navigate = useNavigate();

  const handleRemediate = (e: React.MouseEvent, pathId: string) => {
    e.stopPropagation();
    dispatch(fetchRemediation(pathId));
    navigate("/remediation");
  };

  if (loading) {
    return (
      <div className="flex flex-col gap-4 p-1">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="h-24 bg-panel rounded-xl border border-border animate-pulse" />
        ))}
      </div>
    );
  }

  if (paths.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-center gap-3">
        <span className="text-4xl opacity-30">↯</span>
        <p className="text-text-dim font-body text-sm">No attack paths predicted yet.</p>
        <p className="text-text-dim font-mono text-xs">Run "Predict Attack Paths" to analyze.</p>
      </div>
    );
  }

  return (
    <div className="space-y-2.5">
      <div className="flex items-center justify-between mb-1">
        <span className="text-[9px] font-mono text-text-dim uppercase tracking-widest">
          {paths.length} Paths Detected
        </span>
        <span className="text-[9px] font-mono text-danger bg-danger/10 border border-danger/20 px-2 py-0.5 rounded-full">
          Sorted by risk
        </span>
      </div>

      {[...paths]
        .sort((a, b) => b.risk - a.risk)
        .map((path, idx) => (
          <div
            key={path.id}
            onClick={() => handlePathClick(path)}
            className={`rounded-xl border p-3.5 cursor-pointer transition-all hover:scale-[1.01] ${
              activePath === path.id
                ? "border-accent/50 bg-accent/5"
                : riskBg(path.risk)
            }`}
          >
            {/* Header row */}
            <div className="flex items-start justify-between gap-2 mb-2.5">
              <div className="flex items-center gap-2">
                <span className="text-[9px] font-mono text-text-dim w-4">{idx + 1}</span>
                <span
                  className={`text-xl font-display font-bold leading-none ${riskText(getSafeRisk(path.risk))}`}
                >
                  {formatRisk(path.risk)}
                </span>
                <span className="text-[9px] font-mono text-text-dim">risk</span>
              </div>
              <div className="text-right">
                <div className="text-[9px] font-mono text-text-dim">Likelihood</div>
                <div className="text-xs font-mono font-bold text-warn">
                  {formatLikelihood(path.likelihood)}
                </div>
              </div>
            </div>

            {/* Path visualization */}
            <div className="flex items-center gap-1 flex-wrap mb-3">
              {(Array.isArray(path.nodes) ? path.nodes : []).map((nodeId, ni) => (
                <React.Fragment key={nodeId}>
                  <span className="text-[9px] font-mono bg-surface border border-border px-1.5 py-0.5 rounded text-text-secondary">
                    {getLabel(nodeId)}
                  </span>
                  {ni < (Array.isArray(path.nodes) ? path.nodes.length : 0) - 1 && (
                    <span className="text-text-dim text-[9px]">→</span>
                  )}
                </React.Fragment>
              ))}
            </div>

            {/* Likelihood bar */}
            <div className="h-0.5 bg-border rounded-full overflow-hidden mb-3">
              <div
                className="h-full rounded-full"
                style={{
                  width: `${getSafeLikelihood(path.likelihood) * 100}%`,
                  backgroundColor:
                    getSafeRisk(path.risk) >= 90
                      ? "#ff2d55"
                      : getSafeRisk(path.risk) >= 75
                      ? "#ff9f0a"
                      : "#ffd60a",
                }}
              />
            </div>

            <button
              onClick={(e) => handleRemediate(e, path.id)}
              className="text-[9px] font-mono text-accent/70 hover:text-accent transition-colors flex items-center gap-1"
            >
              ⚕ Generate Remediation Plan →
            </button>
          </div>
        ))}
    </div>
  );
};

export default AttackPathsPanel;
