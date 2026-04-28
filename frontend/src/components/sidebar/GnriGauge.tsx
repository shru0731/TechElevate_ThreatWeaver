import React from "react";

interface GnriGaugeProps {
  score: number;
}

const GnriGauge: React.FC<GnriGaugeProps> = ({ score }) => {
  const color =
    score < 40 ? "#30d158" : score < 60 ? "#ffd60a" : score < 80 ? "#ff9f0a" : "#ff2d55";
  const label =
    score < 40 ? "HEALTHY" : score < 60 ? "ELEVATED" : score < 80 ? "HIGH RISK" : "CRITICAL";

  const r = 28;
  const circ = 2 * Math.PI * r;
  const filled = (score / 100) * circ;

  return (
    <div className="flex flex-col items-center gap-1">
      <p className="text-[9px] font-mono text-text-dim uppercase tracking-widest self-start">
        Global Network Risk Index
      </p>
      <div className="relative w-20 h-20">
        <svg viewBox="0 0 80 80" className="w-full h-full -rotate-90">
          <circle cx="40" cy="40" r={r} fill="none" stroke="#1e2d3d" strokeWidth="5" />
          <circle
            cx="40"
            cy="40"
            r={r}
            fill="none"
            stroke={color}
            strokeWidth="5"
            strokeDasharray={`${filled} ${circ - filled}`}
            strokeLinecap="round"
            style={{ filter: `drop-shadow(0 0 6px ${color})` }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-lg font-display font-bold" style={{ color }}>
            {score.toFixed(0)}
          </span>
        </div>
      </div>
      <span
        className="text-[9px] font-mono font-bold tracking-widest px-2 py-0.5 rounded-full border"
        style={{ color, borderColor: `${color}40`, backgroundColor: `${color}10` }}
      >
        {label}
      </span>
    </div>
  );
};

export default GnriGauge;
