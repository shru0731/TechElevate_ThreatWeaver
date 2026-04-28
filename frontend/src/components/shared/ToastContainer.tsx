import React, { useEffect } from "react";
import { useAppDispatch, useAppSelector } from "../../hooks/redux";
import { removeToast } from "../../features/ui/uiSlice";

const TOAST_STYLES = {
  success: "border-safe/40 bg-safe/10 text-safe",
  error: "border-danger/40 bg-danger/10 text-danger",
  warning: "border-warn/40 bg-warn/10 text-warn",
  info: "border-accent/40 bg-accent/10 text-accent",
};

const TOAST_ICONS = {
  success: "✓",
  error: "✕",
  warning: "⚠",
  info: "ℹ",
};

const ToastItem: React.FC<{ id: string; message: string; type: keyof typeof TOAST_STYLES }> = ({
  id,
  message,
  type,
}) => {
  const dispatch = useAppDispatch();

  useEffect(() => {
    const timer = setTimeout(() => dispatch(removeToast(id)), 4000);
    return () => clearTimeout(timer);
  }, [id, dispatch]);

  return (
    <div
      className={`flex items-center gap-3 px-4 py-3 rounded-xl border backdrop-blur-sm shadow-xl animate-fade-up font-body text-sm ${TOAST_STYLES[type]}`}
    >
      <span className="font-bold">{TOAST_ICONS[type]}</span>
      <span>{message}</span>
      <button
        onClick={() => dispatch(removeToast(id))}
        className="ml-auto opacity-60 hover:opacity-100 transition-opacity text-xs"
      >
        ×
      </button>
    </div>
  );
};

const ToastContainer: React.FC = () => {
  const toasts = useAppSelector((s) => s.ui.toasts);

  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-2 min-w-72 max-w-sm">
      {toasts.map((t) => (
        <ToastItem key={t.id} {...t} />
      ))}
    </div>
  );
};

export default ToastContainer;
