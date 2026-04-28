import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { extractApiErrorMessage, login, register } from "./api/threatweaverApi";

const RegisterForm: React.FC = () => {
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);
    try {
      const normalizedEmail = email.trim().toLowerCase();
      const normalizedUsername = username.trim();
      const normalizedPassword = password;
      await register({ email: normalizedEmail, password: normalizedPassword, username: normalizedUsername });
      const tokenPair = await login({ email: normalizedEmail, password: normalizedPassword });
      localStorage.setItem("tw_token", tokenPair.access_token);
      localStorage.setItem("tw_refresh_token", tokenPair.refresh_token);
      navigate("/dashboard");
    } catch (err: any) {
      setError(extractApiErrorMessage(err, "Unable to register. Please try again."));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-void px-4 py-10">
      <div className="w-full max-w-lg rounded-[2rem] border border-border bg-surface p-10 shadow-[0_24px_90px_-60px_rgba(0,212,255,0.6)]">
        <div className="mb-8">
          <h1 className="text-3xl font-display font-bold text-white mb-2">Create your account</h1>
          <p className="text-sm text-text-secondary">Register as an analyst or admin and start analyzing your network.</p>
        </div>

        {error && <div className="mb-5 rounded-2xl border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">{error}</div>}

        <form onSubmit={handleSubmit} className="space-y-4">
          <label className="block text-xs uppercase tracking-[0.3em] text-text-dim">
            Email
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="mt-2 w-full rounded-2xl border border-border bg-void px-4 py-3 text-sm text-text-primary outline-none transition focus:border-accent/70 focus:ring-1 focus:ring-accent/20"
              placeholder="you@example.com"
            />
          </label>

          <label className="block text-xs uppercase tracking-[0.3em] text-text-dim">
            Username
            <input
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="mt-2 w-full rounded-2xl border border-border bg-void px-4 py-3 text-sm text-text-primary outline-none transition focus:border-accent/70 focus:ring-1 focus:ring-accent/20"
              placeholder="threatweaver_user"
            />
          </label>

          <label className="block text-xs uppercase tracking-[0.3em] text-text-dim">
            Password
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="mt-2 w-full rounded-2xl border border-border bg-void px-4 py-3 text-sm text-text-primary outline-none transition focus:border-accent/70 focus:ring-1 focus:ring-accent/20"
              placeholder="Enter a secure password"
            />
          </label>

          <label className="block text-xs uppercase tracking-[0.3em] text-text-dim">
            Confirm Password
            <input
              type="password"
              required
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="mt-2 w-full rounded-2xl border border-border bg-void px-4 py-3 text-sm text-text-primary outline-none transition focus:border-accent/70 focus:ring-1 focus:ring-accent/20"
              placeholder="Repeat your password"
            />
          </label>

          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-2xl bg-accent px-5 py-3 text-sm font-semibold text-void transition hover:bg-accent/90 disabled:opacity-60 disabled:cursor-not-allowed"
          >
            {loading ? "Creating account..." : "Create account"}
          </button>
        </form>

        <p className="mt-6 text-center text-sm text-text-secondary">
          Already have an account?{' '}
          <Link to="/login" className="text-accent hover:text-accent/80">
            Sign in
          </Link>
        </p>
      </div>
    </div>
  );
};

export default RegisterForm;
