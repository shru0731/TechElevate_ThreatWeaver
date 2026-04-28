import { createSlice, PayloadAction } from "@reduxjs/toolkit";
import { AnalysisResult } from "../../types";

interface AnalysisState {
  result: AnalysisResult | null;
  loading: boolean;
  error: string | null;
  ipRange: string;
  selectedNode: string | null;
  lastScannedAt: string | null;   // new
}

const initialState: AnalysisState = {
  result: null,
  loading: false,
  error: null,
  ipRange: "192.168.1.0/24",
  selectedNode: null,
  lastScannedAt: null,
};

const analysisSlice = createSlice({
  name: "analysis",
  initialState,
  reducers: {
    setIpRange(state, action: PayloadAction<string>) {
      state.ipRange = action.payload;
    },
    setSelectedNode(state, action: PayloadAction<string | null>) {
      state.selectedNode = action.payload;
    },
    clearError(state) {
      state.error = null;
    },
    // --- new reducers ---
    setLoading(state, action: PayloadAction<boolean>) {
      state.loading = action.payload;
    },
    setError(state, action: PayloadAction<string | null>) {
      state.error = action.payload;
    },
    setAnalysisResult(state, action: PayloadAction<AnalysisResult | null>) {
      state.result = action.payload;
    },
    setLastScannedAt(state, action: PayloadAction<string | null>) {
      state.lastScannedAt = action.payload;
    },
  },
});

export const {
  setIpRange,
  setSelectedNode,
  clearError,
  setLoading,
  setError,
  setAnalysisResult,
  setLastScannedAt,
} = analysisSlice.actions;

export default analysisSlice.reducer;