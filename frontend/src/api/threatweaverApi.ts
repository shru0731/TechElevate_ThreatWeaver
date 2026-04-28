import axios, { AxiosInstance } from "axios";
import {
  GraphNode,
  GraphEdge,
  AttackPath,
  RemediationPlan,
} from "../types";

export interface LoginRequest {
  email: string;
  password: string;
}
export interface RegisterRequest {
  email: string;
  password: string;
  username: string;
}
export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}
export interface UserResponse {
  id: number;
  email: string;
  username: string;
  role: string;
  is_active: boolean;
}

const BASE_URL = process.env.REACT_APP_API_URL || "http://localhost:8000/api/v1";

const apiClient: AxiosInstance = axios.create({
  baseURL: BASE_URL,
  timeout: 60000,
  headers: { "Content-Type": "application/json" },
});

// Auth interceptor
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem("tw_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Import the existing interceptor for error normalization …
// (already defined in original file, keep it)

// ─── Auth (unchanged) ─────────────────────────────────────────
export const login = async (payload: LoginRequest): Promise<TokenResponse> => {
  const { data } = await apiClient.post("/auth/login", {
    email: payload.email,
    password: payload.password,
  });
  return data;
};

export const register = async (payload: RegisterRequest): Promise<UserResponse> => {
  const { data } = await apiClient.post("/auth/register", payload);
  return data;
};

// ─── Live Analysis (PRD §6.1 / §7.2) ─────────────────────────
export interface LiveAnalysisResponse {
  job_id: number;
  status: string;
  dispatch_mode: string;
}

export interface JobStatusResponse {
  id: number;
  status: string;
  result?: any;
  error_message?: string;
}

export const startLiveAnalysis = async (cidr: string, entryNode: string = "internet"): Promise<LiveAnalysisResponse> => {
  const payload = {
    source_type: "nmap_live",
    cidr,
    entry_node: entryNode,
    snapshot_name: `scan_${Date.now()}`,
    enrichment_sources: ["nvd", "cisa_kev", "shodan"],
  };
  const { data } = await apiClient.post("/analysis/analyze-live", payload);
  return data;
};

export const pollJobStatus = async (jobId: number): Promise<JobStatusResponse> => {
  const { data } = await apiClient.get(`/jobs/${jobId}`);
  return data;
};

// ─── Path Prediction ─────────────────────────────────────────
export interface PredictPathsRequest {
  snapshot_id: number;
  entry_node: string;
  target_node?: string;
  max_depth?: number;
  top_n_paths?: number;
}

export const predictPaths = async (payload: PredictPathsRequest) => {
  const { data } = await apiClient.post("/paths/predict", payload);
  return data;
};

// ─── Remediation (for a path) ─────────────────────────────────
export const requestRemediation = async (pathId: number) => {
  const { data } = await apiClient.post(`/remediation/${pathId}`);
  return data;
};

export const pollRemediationStatus = async (taskId: string) => {
  const { data } = await apiClient.get(`/remediation/${taskId}/status`);
  return data;
};

// ─── Exports (PDF / JSON / CSV) ───────────────────────────────
export const downloadExport = async (snapshotId: number, format: "pdf" | "json" | "csv") => {
  const { data } = await apiClient.post("/exports", {
    snapshot_id: snapshotId,
    export_format: format,
  });
  // data contains download_token and job_id; we can then download the file
  return data;
};

export const getExportDownloadUrl = (token: string): string => {
  return `${BASE_URL}/exports/download/${token}`;
};

// Export the client for direct use if needed
export default apiClient;