import React, { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate, useLocation, useNavigate } from "react-router-dom";
import LandingPage from "./LandingPage";
import LoginForm from "./components/LoginForm";
import RegisterForm from "./RegisterForm";
import MainLayout from "./MainLayout";
import Dashboard from "./components/Dashboard";
import ProfilePage from "./ProfilePage";
import AdminPage from "./AdminPage";
import ExportsPage from "./ExportsPage";
import { getMe } from "./api/threatweaverApi";
import AttackPathsPanel from "./components/panels/AttackPathsPanel";
import RemediationPanel from "./components/panels/RemediationPanel";
import AlertsPanel from "./components/panels/AlertsPanel";
import { AttackPath } from "./types";

const isAuthenticated = () => Boolean(localStorage.getItem("tw_token"));

const RequireAuth: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const location = useLocation();
  const [status, setStatus] = useState<"pending" | "authenticated" | "unauthenticated">(
    isAuthenticated() ? "pending" : "unauthenticated"
  );

  useEffect(() => {
    let active = true;
    if (!isAuthenticated()) {
      setStatus("unauthenticated");
      return;
    }

    const verifyToken = async () => {
      try {
        await getMe();
        if (active) setStatus("authenticated");
      } catch {
        localStorage.removeItem("tw_token");
        localStorage.removeItem("tw_refresh_token");
        if (active) setStatus("unauthenticated");
      }
    };

    verifyToken();
    return () => {
      active = false;
    };
  }, []);

  if (status === "unauthenticated") {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  if (status === "pending") {
    return (
      <div className="min-h-screen bg-void text-text-primary flex items-center justify-center px-4">
        <div className="rounded-3xl border border-border bg-surface p-8 text-center shadow-xl">
          <p className="text-lg font-semibold text-white">Checking authentication…</p>
          <p className="mt-2 text-sm text-text-secondary">Please wait while we verify your session.</p>
        </div>
      </div>
    );
  }

  return <>{children}</>;
};

const RedirectIfAuth: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  if (isAuthenticated()) {
    return <Navigate to="/dashboard" replace />;
  }
  return <>{children}</>;
};

const RequireAdmin: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [status, setStatus] = useState<"pending" | "allowed" | "denied">("pending");
  const location = useLocation();

  useEffect(() => {
    let active = true;
    const verifyAdmin = async () => {
      try {
        const user = await getMe();
        if (active) {
          setStatus(user.role === "admin" ? "allowed" : "denied");
        }
      } catch {
        if (active) setStatus("denied");
      }
    };

    verifyAdmin();
    return () => {
      active = false;
    };
  }, []);

  if (status === "pending") {
    return (
      <div className="min-h-screen bg-void text-text-primary flex items-center justify-center px-4">
        <div className="rounded-3xl border border-border bg-surface p-8 text-center shadow-xl">
          <p className="text-lg font-semibold text-white">Checking admin access…</p>
          <p className="mt-2 text-sm text-text-secondary">Please wait while we verify your role.</p>
        </div>
      </div>
    );
  }

  if (status === "denied") {
    return <Navigate to="/dashboard" replace state={{ from: location }} />;
  }

  return <>{children}</>;
};

const LoginRoute: React.FC = () => {
  const navigate = useNavigate();
  return <LoginForm onLoginSuccess={() => navigate("/dashboard")} />;
};

const AttackPathsPage: React.FC = () => {
  const handlePathSelect = (_path: AttackPath) => {};
  return (
    <div className="flex h-full min-h-0 flex-col overflow-y-auto p-4">
      <div className="mb-6 rounded-3xl border border-border bg-surface p-6">
        <p className="text-xs font-mono text-text-dim uppercase tracking-[0.3em] mb-2">Attack paths</p>
        <h1 className="text-3xl font-display font-bold text-white">Predicted attack paths</h1>
        <p className="mt-2 text-sm text-text-secondary max-w-2xl">
          Review predicted paths across the network and select paths for remediation.
        </p>
      </div>
      <div className="flex-1 overflow-hidden rounded-3xl border border-border bg-panel p-5">
        <AttackPathsPanel onPathSelect={handlePathSelect} />
      </div>
    </div>
  );
};

const RemediationPage: React.FC = () => (
  <div className="flex h-full min-h-0 flex-col overflow-y-auto p-4">
    <div className="mb-6 rounded-3xl border border-border bg-surface p-6">
      <p className="text-xs font-mono text-text-dim uppercase tracking-[0.3em] mb-2">Remediation</p>
      <h1 className="text-3xl font-display font-bold text-white">Remediation plans</h1>
      <p className="mt-2 text-sm text-text-secondary max-w-2xl">
        Review AI-generated remediation recommendations for the selected attack path.
      </p>
    </div>
    <div className="flex-1 overflow-hidden rounded-3xl border border-border bg-panel p-5">
      <RemediationPanel />
    </div>
  </div>
);

const AlertsPage: React.FC = () => {
  const handlePathSelect = (_path: AttackPath) => {};
  return (
    <div className="flex h-full min-h-0 flex-col overflow-y-auto p-4">
      <div className="mb-6 rounded-3xl border border-border bg-surface p-6">
        <p className="text-xs font-mono text-text-dim uppercase tracking-[0.3em] mb-2">Threat alerts</p>
        <h1 className="text-3xl font-display font-bold text-white">Alerts</h1>
        <p className="mt-2 text-sm text-text-secondary max-w-2xl">
          Explore alerts and high-risk attack paths generated from the latest analysis.
        </p>
      </div>
      <div className="flex-1 overflow-hidden rounded-3xl border border-border bg-panel p-5">
        <AlertsPanel onPathSelect={handlePathSelect} />
      </div>
    </div>
  );
};

const App: React.FC = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/login" element={<RedirectIfAuth><LoginRoute /></RedirectIfAuth>} />
        <Route path="/register" element={<RedirectIfAuth><RegisterForm /></RedirectIfAuth>} />

        <Route element={<RequireAuth><MainLayout /></RequireAuth>}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/attack-paths" element={<AttackPathsPage />} />
          <Route path="/remediation" element={<RemediationPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/exports" element={<ExportsPage />} />
          <Route path="/profile" element={<ProfilePage />} />
          <Route path="/admin" element={<RequireAdmin><AdminPage /></RequireAdmin>} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
};

export default App;
