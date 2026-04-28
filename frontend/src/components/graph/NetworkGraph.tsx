import { configureStore } from "@reduxjs/toolkit";
import analysisReducer from "../features/analysis/analysisSlice";
import pathsReducer from "../features/paths/pathsSlice";
import remediationReducer from "../features/remediation/remediationSlice";
import uiReducer from "../features/ui/uiSlice";

export const store = configureStore({
  reducer: {
    analysis: analysisReducer,
    paths: pathsReducer,
    remediation: remediationReducer,
    ui: uiReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredPaths: ["analysis.result.nodes", "analysis.result.edges"],
      },
    }),
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
