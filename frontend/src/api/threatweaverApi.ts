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
export interface SnapshotSummary {
  id: number;
  snapshot_name: string;
  created_at: string;
  overall_risk_score?: number;
}

const BASE_URL = process.env.REACT_APP_API_URL || "http://localhost:8000/api/v1";

const apiClient: AxiosInstance = axios.create({
  baseURL: BASE_URL,
  timeout: 300000,
  headers: { "Content-Type": "application/json" },
});

export const extractApiErrorMessage = (err: any, fallback: string): string => {
  const data = err?.response?.data;
  if (!data) return err?.message || fallback;
  if (typeof data.message === "string" && data.message.trim()) return data.message;
  if (typeof data.detail === "string" && data.detail.trim()) return data.detail;
  if (data?.details?.errors?.length) {
    const first = data.details.errors[0];
    return first?.msg || fallback;
  }
  return err?.message || fallback;
};

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem("tw_token");
  if (token && config) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error?.response?.status;
    if (status === 401) {
      localStorage.removeItem("tw_token");
      localStorage.removeItem("tw_refresh_token");
      if (typeof window !== "undefined") {
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  }
);

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

export const getMe = async (): Promise<UserResponse> => {
  const { data } = await apiClient.get("/auth/me");
  return data;
};

export const getUsers = async (): Promise<UserResponse[]> => {
  const { data } = await apiClient.get("/auth/users");
  return data;
};

export const getUserSnapshots = async (userId: number): Promise<SnapshotSummary[]> => {
  const { data } = await apiClient.get(`/analysis/users/${userId}/snapshots`);
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

export interface SnapshotResult {
  snapshot: {
    id: number;
    topology_data: {
      nodes: Array<{
        id: string;
        type: string;
        vuln?: number;
        criticality?: string;
        exposure?: number;
        cves?: string[];
      }>;
      edges: Array<{
        source: string;
        target: string;
        exploitability?: number;
        lateral_movement_probability?: number;
      }>;
    };
    overall_risk_score?: number;
  };
  attack_paths: Array<{
    nodes: string[];
    score?: number;
    likelihood?: number;
    explanation?: string;
  }>;
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

export const getSnapshotResult = async (snapshotId: number): Promise<SnapshotResult> => {
  const { data } = await apiClient.get(`/analysis/snapshots/${snapshotId}`);
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

// ─── Exports (PDF / JSON / CSV) – UPDATED with polling support ──
export interface ExportResponse {
  id: number;
  snapshot_id: number;
  export_format: string;
  status: "queued" | "running" | "succeeded" | "failed";
  download_token: string | null;
  storage_path: string | null;
  job_id: number | null;
  created_at: string;
  completed_at: string | null;
  error_message?: string;
}

export const createExport = async (snapshotId: number, format: "pdf" | "json" | "csv"): Promise<ExportResponse> => {
  const { data } = await apiClient.post("/exports", {
    snapshot_id: snapshotId,
    export_format: format,
  });
  return data;
};

export const getExportStatus = async (exportId: number): Promise<ExportResponse> => {
  const { data } = await apiClient.get(`/exports/${exportId}`);
  return data;
};

export const buildExportDownloadUrl = (exportId: number, token: string): string => {
  return `${BASE_URL}/exports/${exportId}/download?token=${token}`;
};

// Deprecated – kept for backward compatibility
export const downloadExport = async (snapshotId: number, format: "pdf" | "json" | "csv") => {
  return createExport(snapshotId, format);
};

// Export the client for direct use if needed
export default apiClient;