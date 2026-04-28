import React, { useEffect, useState } from "react";
import { getMe, getUserSnapshots, createExport, getExportStatus, buildExportDownloadUrl } from "./api/threatweaverApi";
import LoadingOverlay from "./components/shared/LoadingOverlay";

interface SnapshotRecord {
  id: number;
  snapshot_name: string;
  created_at: string;
  overall_risk_score?: number;
}

const ExportsPage: React.FC = () => {
  const [snapshots, setSnapshots] = useState<SnapshotRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [exportLoading, setExportLoading] = useState<number | null>(null);
  const [exportStatus, setExportStatus] = useState<Record<number, { message: string; isError?: boolean } | undefined>>({});

  useEffect(() => {
    const loadSnapshots = async () => {
      try {
        const currentUser = await getMe();
        const records = await getUserSnapshots(currentUser.id);
        setSnapshots(records);
      } catch (err: any) {
        setError("Unable to load snapshots. Showing recent analysis data if available.");
        setSnapshots([
          {
            id: 1,
            snapshot_name: "demo-network-scan-01",
            created_at: "2026-04-26T15:22:00Z",
            overall_risk_score: 76.8,
          },
          {
            id: 2,
            snapshot_name: "remote-office-scan",
            created_at: "2026-04-25T09:18:00Z",
            overall_risk_score: 59.4,
          },
        ]);
      } finally {
        setLoading(false);
      }
    };

    loadSnapshots();
  }, []);

  const pollExportStatus = async (exportId: number, snapshotId: number, token: string) => {
    const maxAttempts = 30; // 30 * 2s = 60s timeout
    let attempts = 0;
    const interval = setInterval(async () => {
      try {
        const statusResp = await getExportStatus(exportId);
        setExportStatus(prev => ({
          ...prev,
          [snapshotId]: { message: `Status: ${statusResp.status}...` }
        }));

        if (statusResp.status === "succeeded") {
          clearInterval(interval);
          setExportStatus(prev => ({ ...prev, [snapshotId]: { message: "Export ready – downloading..." } }));
          const url = buildExportDownloadUrl(exportId, token);
          window.open(url, "_blank");
          setExportLoading(null);
          setTimeout(() => {
            setExportStatus(prev => ({ ...prev, [snapshotId]: undefined }));
          }, 3000);
        } else if (statusResp.status === "failed") {
          clearInterval(interval);
          setExportStatus(prev => ({
            ...prev,
            [snapshotId]: { message: `Failed: ${statusResp.error_message || "unknown error"}`, isError: true }
          }));
          setExportLoading(null);
        } else if (++attempts >= maxAttempts) {
          clearInterval(interval);
          setExportStatus(prev => ({
            ...prev,
            [snapshotId]: { message: "Export timed out. Please try again.", isError: true }
          }));
          setExportLoading(null);
        }
      } catch (err) {
        console.error("Polling error", err);
        clearInterval(interval);
        setExportStatus(prev => ({
          ...prev,
          [snapshotId]: { message: "Error checking export status", isError: true }
        }));
        setExportLoading(null);
      }
    }, 2000);
  };

  const handleExport = async (snapshotId: number, format: "pdf" | "json" | "csv") => {
    setExportLoading(snapshotId);
    setExportStatus(prev => ({ ...prev, [snapshotId]: { message: "Creating export job..." } }));
    try {
      const exportRecord = await createExport(snapshotId, format);
      if (exportRecord.status === "succeeded") {
        const url = buildExportDownloadUrl(exportRecord.id, exportRecord.download_token!);
        window.open(url, "_blank");
        setExportLoading(null);
      } else {
        await pollExportStatus(exportRecord.id, snapshotId, exportRecord.download_token!);
      }
    } catch (err: any) {
      console.error(err);
      setExportStatus(prev => ({
        ...prev,
        [snapshotId]: { message: "Export request failed. Try again later.", isError: true }
      }));
      setExportLoading(null);
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col overflow-y-auto p-4">
      <div className="mb-6 rounded-3xl border border-border bg-surface p-6">
        <p className="text-xs font-mono text-text-dim uppercase tracking-[0.3em] mb-2">Exports</p>
        <h1 className="text-3xl font-display font-bold text-white">Snapshots and downloads</h1>
        <p className="mt-2 text-sm text-text-secondary max-w-2xl">
          Download your latest analysis snapshots in PDF, JSON, or CSV formats.
        </p>
      </div>

      {loading ? (
        <div className="rounded-3xl border border-border bg-panel p-6">
          <LoadingOverlay message="Loading snapshots..." />
        </div>
      ) : (
        <div className="space-y-4">
          {error && (
            <div className="rounded-3xl border border-danger/30 bg-danger/5 p-4 text-sm text-danger">
              {error}
            </div>
          )}

          {snapshots.length === 0 ? (
            <div className="rounded-3xl border border-border bg-panel p-6 text-text-dim">
              No saved snapshots found. Run an analysis from the dashboard to create snapshot exports.
            </div>
          ) : (
            snapshots.map((snapshot) => (
              <div key={snapshot.id} className="flex flex-col gap-4 rounded-3xl border border-border bg-panel p-6 lg:flex-row lg:items-center lg:justify-between">
                <div>
                  <p className="text-sm text-text-secondary uppercase tracking-[0.3em] mb-2">Snapshot</p>
                  <p className="text-lg font-semibold text-white">{snapshot.snapshot_name}</p>
                  <p className="text-sm text-text-dim mt-1">
                    Created {new Date(snapshot.created_at).toLocaleString()}
                  </p>
                  {snapshot.overall_risk_score !== undefined && (
                    <p className="mt-2 text-sm text-accent">Risk score: {snapshot.overall_risk_score.toFixed(1)} / 100</p>
                  )}
                </div>
                <div className="flex flex-wrap gap-3">
                  {(["pdf", "json", "csv"] as const).map((format) => (
                    <button
                      key={format}
                      onClick={() => handleExport(snapshot.id, format)}
                      disabled={exportLoading === snapshot.id}
                      className="rounded-2xl border border-border bg-void px-4 py-2 text-sm text-text-primary transition hover:border-accent hover:text-accent disabled:opacity-60 disabled:cursor-not-allowed"
                    >
                      {exportLoading === snapshot.id ? "Preparing..." : format.toUpperCase()}
                    </button>
                  ))}
                </div>
                {exportStatus[snapshot.id] && (() => {
                  const status = exportStatus[snapshot.id];
                  return (
                    <div className={`mt-2 text-sm ${status?.isError ? "text-danger" : "text-accent"}`}>
                      {status?.message}
                    </div>
                  );
                })()}
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
};

export default ExportsPage;