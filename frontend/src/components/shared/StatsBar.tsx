import React, { useEffect, useState } from "react";
import { useAppSelector } from "../../hooks/redux";

const StatItem: React.FC<{ label: string; value: string | number; accent?: boolean }> = ({
  label,
  value,
  accent,
}) => (
  <div className="flex items-center gap-3 px-4 border-r border-border last:border-r-0">
    <div>
      <p className="text-[9px] font-mono text-text-dim uppercase tracking-widest">{label}</p>
      <p className={`text-sm font-display font-bold ${accent ? "text-accent" : "text-text-primary"}`}>
        {value}
      </p>
    </div>
  </div>
);

const StatsBar: React.FC = () => {
  const result = useAppSelector((s) => s.analysis.result);
  const paths = useAppSelector((s) => s.paths.paths);
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const criticalNodes = result?.nodes.filter((n) => n.risk >= 80).length ?? 0;
  const criticalPaths = paths.filter((p) => p.risk >= 90).length;

  return (
    <header className="h-12 bg-surface border-b border-border flex items-center justify-between px-0 overflow-hidden">
      <div className="flex items-center h-full">
        {result ? (
          <>
            <StatItem label="Nodes" value={result.nodes.length} />
            <StatItem label="Edges" value={result.edges.length} />
            <StatItem label="Critical Nodes" value={criticalNodes} accent={criticalNodes > 0} />
            <StatItem label="Attack Paths" value={paths.length} />
            <StatItem label="Critical Paths" value={criticalPaths} accent={criticalPaths > 0} />
            <StatItem label="Snapshot" value={result.snapshot_id.slice(0, 16)} />
          </>
        ) : (
          <div className="px-4">
            <p className="text-text-dim font-mono text-xs">
              No analysis loaded — enter an IP range and click New Analysis
            </p>
          </div>
        )}
      </div>

      <div className="flex items-center gap-3 px-4 border-l border-border h-full">
        <div className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse" />
        <span className="text-[10px] font-mono text-text-secondary">
          {time.toISOString().slice(11, 19)} UTC
        </span>
      </div>
    </header>
  );
};

export default StatsBar;
