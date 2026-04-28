import React, { useState, useCallback } from "react";
import { useAppSelector, useAppDispatch } from "../hooks/redux";
import { setSelectedNode, clearError } from "../features/analysis/analysisSlice";
import { setActivePath } from "../features/paths/pathsSlice";
import { AttackPath } from "../types";
import { downloadExport, getExportDownloadUrl } from "../api/threatweaverApi";
import TopBar from "./TopBar";
// Components
import NetworkGraph from "./graph/NetworkGraph";
import NodeDetail from "./graph/NodeDetail";
import Sidebar from "./sidebar/Sidebar";
import RightPanel from "./panels/RightPanel";
import StatsBar from "./shared/StatsBar";
import LoadingOverlay from "./shared/LoadingOverlay";
import ErrorBanner from "./shared/ErrorBanner";
import ToastContainer from "./shared/ToastContainer";

const Dashboard: React.FC = () => {
  const dispatch = useAppDispatch();
  const { result, loading: analysisLoading, error: analysisError, selectedNode } = useAppSelector(
    (s) => s.analysis
  );
  const { activePath, paths } = useAppSelector((s) => s.paths);
  const [highlightedPath, setHighlightedPath] = useState<string[] | null>(null);

  const handleNodeClick = useCallback(
    (nodeId: string) => {
      dispatch(setSelectedNode(selectedNode === nodeId ? null : nodeId));
    },
    [dispatch, selectedNode]
  );

  const handlePathSelect = useCallback((path: AttackPath) => {
    setHighlightedPath(path.nodes);
    dispatch(setActivePath(path.id));
  }, [dispatch]);

  // Handle Export Logic
  const handleExport = async (format: "pdf" | "json" | "csv") => {
    if (!result?.snapshot_id) return;
    try {
      const { download_token } = await downloadExport(Number(result.snapshot_id), format);
      const url = getExportDownloadUrl(download_token);
      window.open(url, "_blank");
    } catch (err) {
      console.error("Export failed", err);
    }
  };

  const selectedNodeData = result?.nodes.find((n) => n.id === selectedNode);
  const activePathData = activePath ? paths.find((p) => p.id === activePath) : null;

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-void font-body">
      {/* Top Header Section */}
      <TopBar onExport={handleExport} />

      <div className="flex flex-1 overflow-hidden">
        {/* Left Sidebar */}
        <Sidebar />

        {/* Main content */}
        <main className="flex-1 flex flex-col min-w-0 overflow-hidden border-l border-border">
          {/* Stats bar */}
          <StatsBar />

          {/* Error banner */}
          {analysisError && (
            <div className="px-4 pt-3">
              <ErrorBanner message={analysisError} onDismiss={() => dispatch(clearError())} />
            </div>
          )}

          {/* Graph area */}
          <div className="flex-1 relative p-4 overflow-hidden">
            {!result && !analysisLoading && (
              <div className="absolute inset-0 flex flex-col items-center justify-center gap-4 pointer-events-none">
                <div className="text-6xl opacity-10">⬡</div>
                <p className="text-text-dim font-display font-semibold text-lg"> No Network Data </p>
                <p className="text-text-dim font-mono text-xs"> Enter an IP range and run a New Analysis </p>
              </div>
            )}

            {result && (
              <NetworkGraph
                nodes={result.nodes}
                edges={result.edges}
                selectedNode={selectedNode}
                highlightedPath={activePathData?.nodes ?? highlightedPath}
                onNodeClick={handleNodeClick}
              />
            )}

            {analysisLoading && (
              <LoadingOverlay message="Scanning network topology and calculating risk..." />
            )}

            {selectedNodeData && (
              <div className="absolute top-8 right-8 w-72 z-20">
                <NodeDetail node={selectedNodeData} onClose={() => dispatch(setSelectedNode(null))} />
              </div>
            )}
          </div>
        </main>

        {/* Right panel */}
        <RightPanel onPathSelect={handlePathSelect} />
      </div>

      {/* Toasts */}
      <ToastContainer />
    </div>
  );
};

export default Dashboard;