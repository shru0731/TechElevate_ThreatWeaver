import React from "react";

interface LoadingOverlayProps {
  message?: string;
}

const LoadingOverlay: React.FC<LoadingOverlayProps> = ({
  message = "Scanning network topology...",
}) => {
  return (
    <div className="absolute inset-0 bg-void/80 backdrop-blur-sm flex flex-col items-center justify-center z-10 rounded-lg">
      <div className="relative mb-6">
        {/* Rings */}
        {[1, 2, 3].map((i) => (
          <div
            key={i}
            className="absolute rounded-full border border-accent/30 animate-ping"
            style={{
              inset: `-${i * 14}px`,
              animationDelay: `${i * 0.15}s`,
              animationDuration: "2s",
            }}
          />
        ))}
        <div className="w-12 h-12 rounded-full border-2 border-accent/60 border-t-accent animate-spin" />
        <div
          className="absolute inset-2 rounded-full border border-accent/20 animate-spin"
          style={{ animationDirection: "reverse", animationDuration: "1.5s" }}
        />
      </div>
      <p className="text-accent font-mono text-sm tracking-widest uppercase">{message}</p>
      <p className="text-text-dim font-mono text-xs mt-1">
        {new Date().toISOString().slice(0, 19).replace("T", " ")} UTC
      </p>
    </div>
  );
};

export default LoadingOverlay;
