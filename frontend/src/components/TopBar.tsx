import React from "react";
import { useLocation } from "react-router-dom";
import { useAppSelector } from "../hooks/redux";

interface TopBarProps {
  onExport: (format: "pdf" | "json" | "csv") => void;
  onLogout: () => void;
  showExportControls: boolean;
}

const routeTitles: Record<string, string> = {
  "/dashboard": "Dashboard",
  "/profile": "Profile",
  "/admin": "Admin",
  "/exports": "Exports",
  "/attack-paths": "Attack Paths",
  "/remediation": "Remediation",
  "/alerts": "Alerts",
};

const TopBar: React.FC<TopBarProps> = ({ onExport, onLogout, showExportControls }) => {
  const location = useLocation();
  const { result, lastScannedAt } = useAppSelector((s) => s.analysis);
  const gnri = result?.gnri ?? 0;
  const title = routeTitles[location.pathname] || "ThreatWeaver";

  return (
    <header className="h-14 border-b border-border bg-surface flex items-center justify-between px-6">
      <div className="flex flex-col justify-center">
        <span className="text-lg font-display font-bold tracking-wide text-text-primary">{title}</span>
        <span className="text-[10px] font-mono text-text-dim uppercase tracking-widest">Secure analytics workspace</span>
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
        {showExportControls && (
          <>
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
          </>
        )}
        <button
          onClick={onLogout}
          className="text-[10px] font-mono text-text-secondary hover:text-danger transition border border-border rounded px-2 py-1"
        >
          Logout
        </button>
      </div>
    </header>
  );
};

export default TopBar;