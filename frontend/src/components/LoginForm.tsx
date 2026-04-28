import React, { useState } from "react";
import { extractApiErrorMessage, login } from "../api/threatweaverApi";

interface LoginFormProps {
  onLoginSuccess: () => void;
}

const LoginForm: React.FC<LoginFormProps> = ({ onLoginSuccess }) => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const normalizedEmail = email.trim().toLowerCase();
      const normalizedPassword = password;
      const tokenPair = await login({ email: normalizedEmail, password: normalizedPassword });
      localStorage.setItem("tw_token", tokenPair.access_token);
      localStorage.setItem("tw_refresh_token", tokenPair.refresh_token);
      onLoginSuccess();
    } catch (err: any) {
      setError(extractApiErrorMessage(err, "Login failed"));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-void px-4">
      <div className="w-full max-w-md p-8 bg-panel border border-border rounded-3xl shadow-lg">
        <h1 className="text-2xl font-bold text-text-primary mb-2">ThreatWeaver Login</h1>
        <p className="text-sm text-text-secondary mb-6">
          Sign in with an analyst or admin account to run live scans.
        </p>
        {error && <div className="mb-4 text-sm text-danger">{error}</div>}
        <form onSubmit={handleSubmit} className="space-y-4">
          <label className="block text-xs uppercase tracking-[0.25em] text-text-dim">
            Email
            <input
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="mt-2 w-full rounded-xl border border-border bg-void px-3 py-2 text-sm text-text-primary focus:border-accent/50 focus:outline-none focus:ring-1 focus:ring-accent/20"
              placeholder="analyst@example.com"
              type="email"
              required
            />
          </label>

          <label className="block text-xs uppercase tracking-[0.25em] text-text-dim">
            Password
            <input
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="mt-2 w-full rounded-xl border border-border bg-void px-3 py-2 text-sm text-text-primary focus:border-accent/50 focus:outline-none focus:ring-1 focus:ring-accent/20"
              placeholder="••••••••"
              type="password"
              required
            />
          </label>

          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-xl bg-accent px-4 py-3 text-sm font-semibold text-void transition hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading ? "Signing in..." : "Sign in"}
          </button>
        </form>
        <p className="mt-6 text-xs text-text-secondary">
          If you don’t have an analyst/admin account yet, create one via the backend or use an existing authorized user.
        </p>
      </div>
    </div>
  );
};

export default LoginForm;
