import React from "react";
import { useAppSelector } from "../hooks/redux";
interface TopBarProps {
  onExport: (format: "pdf" | "json" | "csv") => void;
}

const TopBar: React.FC<TopBarProps> = ({ onExport }) => {
  const { result, lastScannedAt } = useAppSelector((s) => s.analysis);
  const gnri = result?.gnri ?? 0;

  return (
    <header className="h-14 border-b border-border bg-surface flex items-center justify-between px-6">
      <div className="flex items-center gap-4">
        <span className="text-accent font-display font-bold text-sm tracking-wide">ThreatWeaver</span>
        <span className="text-text-dim text-xs font-mono">v1.0</span>
      </div>

      <div className="flex items-center gap-6">
        {result && (
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono text-text-dim uppercase tracking-widest">GNRI</span>
            <span
              className={`text-lg font-display font-bold ${
                gnri >= 80 ? "text-danger" : gnri >= 60 ? "text-warn" : gnri >= 30 ? "text-mid" : "text-safe"
              }`}
            >
              {gnri.toFixed(1)}
            </span>
            <span className="text-[9px] font-mono text-text-dim">/100</span>
          </div>
        )}

        {lastScannedAt && (
          <span className="text-[9px] font-mono text-text-dim">
            Last scan: {new Date(lastScannedAt).toLocaleString()}
          </span>
        )}
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={() => onExport("pdf")}
          className="text-[10px] font-mono text-text-secondary hover:text-accent transition border border-border rounded px-2 py-1"
        >
          Export PDF
        </button>
        <button
          onClick={() => onExport("json")}
          className="text-[10px] font-mono text-text-secondary hover:text-accent transition border border-border rounded px-2 py-1"
        >
          JSON
        </button>
        <button
          onClick={() => onExport("csv")}
          className="text-[10px] font-mono text-text-secondary hover:text-accent transition border border-border rounded px-2 py-1"
        >
          CSV
        </button>
      </div>
    </header>
  );
};

export default TopBar;