import React from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { useAppSelector } from "./hooks/redux";
import { createExport, getExportStatus, buildExportDownloadUrl } from "./api/threatweaverApi";
import Sidebar from "./components/sidebar/Sidebar";
import TopBar from "./components/TopBar";
import RightPanel from "./components/panels/RightPanel";
import ToastContainer from "./components/shared/ToastContainer";

const MainLayout: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { result } = useAppSelector((s) => s.analysis);

  const handleExport = async (format: "pdf" | "json" | "csv") => {
    if (!result?.snapshot_id) return;

    try {
      const exportRecord = await createExport(Number(result.snapshot_id), format);
      // Poll until succeeded
      const pollInterval = setInterval(async () => {
        try {
          const status = await getExportStatus(exportRecord.id);
          if (status.status === "succeeded") {
            clearInterval(pollInterval);
            const url = buildExportDownloadUrl(exportRecord.id, status.download_token!);
            window.open(url, "_blank");
          } else if (status.status === "failed") {
            clearInterval(pollInterval);
            console.error("Export failed", status.error_message);
            // Optionally show a toast notification here
          }
        } catch (err) {
          console.error("Polling error", err);
          clearInterval(pollInterval);
        }
      }, 2000);
    } catch (err) {
      console.error(err);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("tw_token");
    localStorage.removeItem("tw_refresh_token");
    navigate("/login");
  };

  return (
    <div className="flex h-screen w-screen flex-col bg-void text-text-primary">
      <TopBar
        onExport={handleExport}
        onLogout={handleLogout}
        showExportControls={Boolean(result?.snapshot_id)}
      />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="flex-1 min-w-0 overflow-hidden bg-void">
          <div className="h-full overflow-hidden" key={location.pathname}>
            <Outlet />
          </div>
        </main>
        <RightPanel />
      </div>
      <ToastContainer />
    </div>
  );
};

export default MainLayout;