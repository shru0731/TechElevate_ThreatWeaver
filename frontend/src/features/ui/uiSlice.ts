import { createSlice, PayloadAction } from "@reduxjs/toolkit";

type ActivePanel = "graph" | "paths" | "remediation" | "alerts";

interface UiState {
  activePanel: ActivePanel;
  sidebarCollapsed: boolean;
  toasts: Toast[];
}

interface Toast {
  id: string;
  message: string;
  type: "success" | "error" | "info" | "warning";
}

const initialState: UiState = {
  activePanel: "graph",
  sidebarCollapsed: false,
  toasts: [],
};

const uiSlice = createSlice({
  name: "ui",
  initialState,
  reducers: {
    setActivePanel(state, action: PayloadAction<ActivePanel>) {
      state.activePanel = action.payload;
    },
    toggleSidebar(state) {
      state.sidebarCollapsed = !state.sidebarCollapsed;
    },
    addToast(state, action: PayloadAction<Omit<Toast, "id">>) {
      state.toasts.push({ ...action.payload, id: Date.now().toString() });
    },
    removeToast(state, action: PayloadAction<string>) {
      state.toasts = state.toasts.filter((t) => t.id !== action.payload);
    },
  },
});

export const { setActivePanel, toggleSidebar, addToast, removeToast } = uiSlice.actions;
export default uiSlice.reducer;
