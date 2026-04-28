import React, { useState } from "react";
import { useAppDispatch, useAppSelector } from "../../hooks/redux";
import {
  startLiveAnalysis,
  pollJobStatus,
} from "../../api/threatweaverApi";
import { setAnalysisResult, setLastScannedAt, setLoading, setError } from "../../features/analysis/analysisSlice";
import { predictPathsThunk } from "../../features/paths/pathsSlice";
import { setActivePanel } from "../../features/ui/uiSlice";
import GnriGauge from "./GnriGauge";

const Sidebar: React.FC = () => {
  const dispatch = useAppDispatch();
  const { result, loading: analysisLoading, ipRange } = useAppSelector((s) => s.analysis);
  const { loading: pathsLoading } = useAppSelector((s) => s.paths);
  const { activePanel } = useAppSelector((s) => s.ui);
  const [localIp, setLocalIp] = useState(ipRange);

  const handleAnalyze = async () => {
    if (!localIp) return;
    dispatch(setLoading(true));
    dispatch(setError(null));
    try {
      const { job_id } = await startLiveAnalysis(localIp);
      // Poll job status
      let job: any;
      do {
        await new Promise((r) => setTimeout(r, 2000));
        job = await pollJobStatus(job_id);
      } while (job.status === "queued" || job.status === "running");

      if (job.status === "succeeded" && job.result) {
        const res = job.result;
        // Transform result to analysisResult shape
        // The result contains snapshot_id, risk_scores, attack_paths, remediation
        dispatch(
          setAnalysisResult({
            snapshot_id: String(res.snapshot_id),
            gnri: 100 - (res.risk_scores?.overall ?? 0), // approximate, will be corrected later
            nodes: [/* we need to extract from attack paths */],
            edges: [/* ... */],
          })
        );
        dispatch(setLastScannedAt(new Date().toISOString()));
        dispatch(setActivePanel("graph"));
      } else {
        dispatch(setError(job.error_message || "Analysis failed"));
      }
    } catch (err: any) {
      dispatch(setError(err.message));
    } finally {
      dispatch(setLoading(false));
    }
  };

  const handlePredict = () => {
    if (!result) return;
    dispatch(
      predictPathsThunk({
        snapshotId: parseInt(result.snapshot_id, 10),
        source: result.nodes[0]?.id || "",
        target: result.nodes[result.nodes.length - 1]?.id || "",
      })
    );
    dispatch(setActivePanel("paths"));
  };

  const navItems = [
    { id: "graph", label: "Network Map", icon: "⬡" },
    { id: "paths", label: "Attack Paths", icon: "↯" },
    { id: "remediation", label: "Remediation", icon: "⚕" },
    { id: "alerts", label: "Alerts", icon: "⚡" },
  ] as const;

  return (
    <aside className="w-64 h-full flex flex-col bg-surface border-r border-border overflow-hidden">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-border">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-accent/10 border border-accent/30 flex items-center justify-center">
            <span className="text-accent text-sm font-bold">TW</span>
          </div>
          <div>
            <p className="text-text-primary font-display font-bold text-sm tracking-wide">ThreatWeaver</p>
            <p className="text-text-dim font-mono text-[9px] uppercase tracking-widest">v2.4.1 · Secure</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="px-3 pt-4 space-y-0.5">
        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => dispatch(setActivePanel(item.id))}
            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all text-left group ${
              activePanel === item.id
                ? "bg-accent/10 border border-accent/20 text-accent"
                : "text-text-secondary hover:bg-border/50 hover:text-text-primary border border-transparent"
            }`}
          >
            <span className="text-base w-5 text-center">{item.icon}</span>
            <span className="font-body text-xs font-medium">{item.label}</span>
            {activePanel === item.id && (
              <span className="ml-auto w-1 h-1 rounded-full bg-accent" />
            )}
          </button>
        ))}
      </nav>

      {/* GNRI Score */}
      {result && (
        <div className="mx-3 mt-4 p-4 bg-panel rounded-xl border border-border">
          <GnriGauge score={result.gnri} />
        </div>
      )}

      {/* Analysis config */}
      <div className="mt-auto px-3 pb-4 space-y-2.5 border-t border-border pt-4">
        <div>
          <label className="block text-[9px] font-mono text-text-dim uppercase tracking-widest mb-1.5">
            IP Range / CIDR
          </label>
          <input
            value={localIp}
            onChange={(e) => setLocalIp(e.target.value)}
            className="w-full bg-panel border border-border rounded-lg px-3 py-2 text-xs font-mono text-text-primary focus:outline-none focus:border-accent/50 focus:ring-1 focus:ring-accent/20 transition-all"
            placeholder="192.168.1.0/24"
          />
        </div>

        <button
          onClick={handleAnalyze}
          disabled={analysisLoading}
          className="w-full py-2.5 rounded-lg bg-accent text-void text-xs font-display font-bold tracking-wide hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2"
          style={{ boxShadow: analysisLoading ? "none" : "0 0 16px #00d4ff30" }}
        >
          {analysisLoading ? (
            <>
              <span className="w-3 h-3 border border-void border-t-transparent rounded-full animate-spin" />
              Scanning...
            </>
          ) : (
            <>⬡ New Analysis</>
          )}
        </button>

        <button
          onClick={handlePredict}
          disabled={!result || pathsLoading}
          className="w-full py-2.5 rounded-lg bg-panel border border-danger/30 text-danger text-xs font-display font-semibold tracking-wide hover:bg-danger/10 disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2"
        >
          {pathsLoading ? (
            <>
              <span className="w-3 h-3 border border-danger border-t-transparent rounded-full animate-spin" />
              Predicting...
            </>
          ) : (
            <>↯ Predict Attack Paths</>
          )}
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;