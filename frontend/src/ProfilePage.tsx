import React, { useEffect, useState } from "react";
import { getMe, UserResponse } from "./api/threatweaverApi";
import LoadingOverlay from "./components/shared/LoadingOverlay";

const ProfilePage: React.FC = () => {
  const [user, setUser] = useState<UserResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadProfile = async () => {
      try {
        const profile = await getMe();
        setUser(profile);
      } catch (err: any) {
        setError(err?.response?.data?.detail || err?.message || "Unable to load profile.");
      } finally {
        setLoading(false);
      }
    };

    loadProfile();
  }, []);

  return (
    <div className="flex h-full min-h-0 flex-col overflow-y-auto p-4">
      <div className="mb-6 rounded-3xl border border-border bg-surface p-6">
        <p className="text-xs font-mono text-text-dim uppercase tracking-[0.3em] mb-2">My profile</p>
        <h1 className="text-3xl font-display font-bold text-white">Account details</h1>
        <p className="mt-2 text-sm text-text-secondary max-w-2xl">
          Manage your ThreatWeaver account and review your current role and status.
        </p>
      </div>

      {loading ? (
        <div className="flex-1 rounded-3xl border border-border bg-panel p-6">
          <LoadingOverlay message="Loading profile..." />
        </div>
      ) : error ? (
        <div className="rounded-3xl border border-danger/30 bg-danger/5 p-6 text-sm text-danger">{error}</div>
      ) : user ? (
        <div className="grid gap-6 lg:grid-cols-2">
          <div className="rounded-3xl border border-border bg-panel p-6 space-y-4">
            <div>
              <p className="text-xs font-mono text-text-dim uppercase tracking-[0.3em]">Email</p>
              <p className="mt-2 text-sm text-text-primary break-all">{user.email}</p>
            </div>
            <div>
              <p className="text-xs font-mono text-text-dim uppercase tracking-[0.3em]">Username</p>
              <p className="mt-2 text-sm text-text-primary">{user.username}</p>
            </div>
            <div>
              <p className="text-xs font-mono text-text-dim uppercase tracking-[0.3em]">Role</p>
              <p className="mt-2 text-sm text-text-primary">{user.role}</p>
            </div>
          </div>

          <div className="rounded-3xl border border-border bg-panel p-6 space-y-4">
            <div>
              <p className="text-xs font-mono text-text-dim uppercase tracking-[0.3em]">Account status</p>
              <p className="mt-2 text-sm text-text-primary">{user.is_active ? "Active" : "Disabled"}</p>
            </div>
            <div>
              <p className="text-xs font-mono text-text-dim uppercase tracking-[0.3em]">User ID</p>
              <p className="mt-2 text-sm text-text-primary">{user.id}</p>
            </div>
          </div>
        </div>
      ) : (
        <div className="rounded-3xl border border-border bg-panel p-6 text-sm text-text-dim">Unable to load profile data.</div>
      )}
    </div>
  );
};

export default ProfilePage;
