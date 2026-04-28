import React, { useEffect, useState } from "react";
import { getUsers, UserResponse } from "./api/threatweaverApi";
import LoadingOverlay from "./components/shared/LoadingOverlay";

const AdminPage: React.FC = () => {
  const [users, setUsers] = useState<UserResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadUsers = async () => {
      try {
        const userList = await getUsers();
        setUsers(userList);
      } catch (err: any) {
        setError(err?.response?.data?.detail || err?.message || "Unable to load user list.");
      } finally {
        setLoading(false);
      }
    };

    loadUsers();
  }, []);

  return (
    <div className="flex h-full min-h-0 flex-col overflow-y-auto p-4">
      <div className="mb-6 rounded-3xl border border-border bg-surface p-6">
        <p className="text-xs font-mono text-text-dim uppercase tracking-[0.3em] mb-2">Admin panel</p>
        <h1 className="text-3xl font-display font-bold text-white">User management</h1>
        <p className="mt-2 text-sm text-text-secondary max-w-2xl">
          Review all registered users and their roles. Admin access is required to reach this page.
        </p>
      </div>

      {loading ? (
        <div className="rounded-3xl border border-border bg-panel p-6">
          <LoadingOverlay message="Loading users..." />
        </div>
      ) : error ? (
        <div className="rounded-3xl border border-danger/30 bg-danger/5 p-6 text-sm text-danger">{error}</div>
      ) : (
        <div className="overflow-hidden rounded-3xl border border-border bg-panel">
          <div className="grid grid-cols-5 gap-4 border-b border-border px-6 py-4 text-[10px] uppercase tracking-[0.25em] text-text-dim font-mono">
            <span>ID</span>
            <span className="col-span-2">Username</span>
            <span>Email</span>
            <span>Role</span>
          </div>
          <div className="divide-y divide-border">
            {users.map((user) => (
              <div key={user.id} className="grid grid-cols-5 gap-4 px-6 py-4 text-sm text-text-primary">
                <span>{user.id}</span>
                <span className="col-span-2 truncate">{user.username}</span>
                <span className="truncate">{user.email}</span>
                <span className="capitalize text-accent">{user.role}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminPage;
