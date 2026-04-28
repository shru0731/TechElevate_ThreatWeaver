import React, { useState, useCallback } from "react";
import { useAppSelector, useAppDispatch } from "../hooks/redux";
import { setSelectedNode, clearError } from "../features/analysis/analysisSlice";
// Components
import NetworkGraph from "./graph/NetworkGraph";
import NodeDetail from "./graph/NodeDetail";
import StatsBar from "./shared/StatsBar";
import LoadingOverlay from "./shared/LoadingOverlay";
import ErrorBanner from "./shared/ErrorBanner";

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

  const selectedNodeData = result?.nodes.find((n) => n.id === selectedNode);
  const activePathData = activePath ? paths.find((p) => p.id === activePath) : null;

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden">
      <StatsBar />

      {analysisError && (
        <div className="px-4 pt-3">
          <ErrorBanner message={analysisError} onDismiss={() => dispatch(clearError())} />
        </div>
      )}

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
    </div>
  );
};

export default Dashboard;