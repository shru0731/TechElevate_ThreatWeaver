import React from "react";
import { useAppSelector } from "../../hooks/redux";
import { RemediationPlan } from "../../types";

const RemediationPanel: React.FC = () => {
  const { plans, activePlanId, loading } = useAppSelector((s) => s.remediation);
  const paths = useAppSelector((s) => s.paths.paths);
  const plan: RemediationPlan | null = activePlanId ? plans[activePlanId] : null;
  const activePath = paths.find((p) => p.id === activePlanId);

  if (loading) {
    return (
      <div className="space-y-3 p-1">
        <div className="h-12 bg-panel rounded-xl border border-border animate-pulse" />
        {[...Array(3)].map((_, i) => (
          <div key={i} className="h-28 bg-panel rounded-xl border border-border animate-pulse" />
        ))}
      </div>
    );
  }

  if (!plan) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-center gap-3">
        <span className="text-4xl opacity-30">⚕</span>
        <p className="text-text-dim font-body text-sm">No remediation plan generated yet.</p>
        <p className="text-text-dim font-mono text-xs">Click a path → "Generate Remediation Plan"</p>
      </div>
    );
  }

  return (
    <div className="space-y-3 animate-fade-up">
      {/* Header card */}
      <div className={`rounded-xl border border-accent/30 bg-accent/5 p-4`}>
        <div className="flex items-center justify-between mb-2">
          <span className="text-[9px] font-mono text-text-dim uppercase tracking-widest">
            AI Remediation Plan
          </span>
          <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full border bg-accent/20 text-accent border-accent/40`}>
            {plan.priority || "HIGH"}
          </span>
        </div>
        {activePath && (
          <p className="text-xs font-mono text-text-secondary">
            Path: {activePath.nodes.join(" → ")}
          </p>
        )}
        <p className="text-xs font-body text-text-primary mt-3">{plan.summary}</p>
        <div className="flex gap-4 mt-3">
          <div>
            <p className="text-lg font-display font-bold text-text-primary">{plan.recommended_actions.length}</p>
            <p className="text-[9px] font-mono text-text-dim">Action Steps</p>
          </div>
          <div>
            <p className="text-lg font-display font-bold text-safe">{plan.confidence.toFixed(2)}</p>
            <p className="text-[9px] font-mono text-text-dim">Confidence</p>
          </div>
          <div>
            <p className="text-lg font-display font-bold text-mid">{plan.provider}</p>
            <p className="text-[9px] font-mono text-text-dim">Provider</p>
          </div>
        </div>
      </div>

      {/* Steps list */}
      <div className="rounded-xl border border-border bg-panel/50 p-3 space-y-2">
        {plan.recommended_actions.map((step, idx) => (
          <div key={idx} className="flex items-start gap-2">
            <div className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 bg-accent" />
            <p className="text-xs font-body text-text-primary">{step}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

export default RemediationPanel;