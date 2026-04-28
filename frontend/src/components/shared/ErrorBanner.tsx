import React from "react";

interface ErrorBannerProps {
  message: string;
  onDismiss: () => void;
}

const ErrorBanner: React.FC<ErrorBannerProps> = ({ message, onDismiss }) => (
  <div className="flex items-center gap-3 px-4 py-3 bg-danger/10 border border-danger/40 rounded-xl animate-fade-up">
    <span className="text-danger font-bold shrink-0">✕</span>
    <p className="text-danger font-mono text-xs flex-1">{message}</p>
    <button
      onClick={onDismiss}
      className="text-danger/60 hover:text-danger transition-colors text-sm font-mono"
    >
      dismiss
    </button>
  </div>
);

export default ErrorBanner;
