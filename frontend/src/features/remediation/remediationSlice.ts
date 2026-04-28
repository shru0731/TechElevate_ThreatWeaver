import { createSlice, createAsyncThunk, PayloadAction } from "@reduxjs/toolkit";
import { RemediationPlan } from "../../types";
import { requestRemediation, pollRemediationStatus } from "../../api/threatweaverApi";

interface RemediationState {
  plans: Record<string, RemediationPlan>;
  loading: boolean;
  error: string | null;
  activePlanId: string | null;
}

const initialState: RemediationState = {
  plans: {},
  loading: false,
  error: null,
  activePlanId: null,
};

export const fetchRemediation = createAsyncThunk(
  "remediation/fetch",
  async (pathId: string, { rejectWithValue }) => {
    try {
      // 1. Start the remediation job on the backend
      const { task_id } = await requestRemediation(Number(pathId));

      // 2. Poll until the status is 'succeeded'
      let result;
      let status = "pending";
      
      while (status === "pending" || status === "running") {
        await new Promise((resolve) => setTimeout(resolve, 2000)); // Wait 2 seconds
        const pollRes = await pollRemediationStatus(task_id);
        status = pollRes.status;
        if (status === "succeeded") {
          result = pollRes.result;
        } else if (status === "failed") {
          throw new Error(pollRes.error || "LLM Remediation failed");
        }
      }

      return { pathId, plan: result as RemediationPlan };
    } catch (err: any) {
      return rejectWithValue(err.message);
    }
  }
);

const remediationSlice = createSlice({
  name: "remediation",
  initialState,
  reducers: {
    setActivePlan(state, action: PayloadAction<string | null>) {
      state.activePlanId = action.payload;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchRemediation.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchRemediation.fulfilled, (state, action) => {
        state.loading = false;
        state.plans[action.payload.pathId] = action.payload.plan;
        state.activePlanId = action.payload.pathId;
      })
      .addCase(fetchRemediation.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      });
  },
});

export const { setActivePlan } = remediationSlice.actions;
export default remediationSlice.reducer;
