import { createSlice, createAsyncThunk, PayloadAction } from "@reduxjs/toolkit";
import { AttackPath } from "../../types";
import { predictPaths as apiPredictPaths } from "../../api/threatweaverApi";

interface PathsState {
  source: string | null;
  target: string | null;
  paths: AttackPath[];
  activePath: string | null;
  loading: boolean;
  error: string | null;
}

const initialState: PathsState = {
  source: null,
  target: null,
  paths: [],
  activePath: null,
  loading: false,
  error: null,
};

export const predictPathsThunk = createAsyncThunk(
  "paths/predict",
  async (
    args: { snapshotId: number; source: string; target: string },
    { rejectWithValue }
  ) => {
    try {
      const res = await apiPredictPaths({
        snapshot_id: args.snapshotId,
        entry_node: args.source,
        target_node: args.target,
      });
      return res.paths;
    } catch (err: any) {
      return rejectWithValue(err.message);
    }
  }
);

const pathsSlice = createSlice({
  name: "paths",
  initialState,
  reducers: {
    setSourceNode(state, action: PayloadAction<string>) {
      state.source = action.payload;
    },
    setTargetNode(state, action: PayloadAction<string>) {
      state.target = action.payload;
    },
    setActivePath(state, action: PayloadAction<string | null>) {
      state.activePath = action.payload;
    },
    clearPaths(state) {
      state.paths = [];
      state.activePath = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(predictPathsThunk.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(predictPathsThunk.fulfilled, (state, action) => {
        state.loading = false;
        state.paths = action.payload;
      })
      .addCase(predictPathsThunk.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      });
  },
});

export const { setSourceNode, setTargetNode, setActivePath, clearPaths } = pathsSlice.actions;
export default pathsSlice.reducer;