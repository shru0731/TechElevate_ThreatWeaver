// Core graph types
export interface GraphNode {
  id: string;
  label: string;
  ip?: string;
  type: "host" | "router" | "server" | "firewall" | "endpoint";
  risk: number;
  vulnerabilities?: string[];
  os?: string;
  services?: string[];
  // D3 simulation props
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  fx?: number | null;
  fy?: number | null;
}

export interface GraphEdge {
  id: string;
  source: string | GraphNode;
  target: string | GraphNode;
  protocol?: string;
  port?: number;
  weight?: number;
}

export interface AnalysisResult {
  snapshot_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  gnri: number;
}

export interface AttackPath {
  id: string;
  nodes: string[];
  risk: number;
  likelihood: number;
}

export interface RemediationStep {
  action: string;
  category: "immediate" | "short-term" | "long-term";
}

export interface RemediationPlan {
  summary: string;
  recommended_actions: string[];
  confidence: number;
  provider: string;
  priority?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
}

// API Request/Response types
export interface AnalyzeRequest {
  ip_range: string;
}

export interface PredictPathsRequest {
  snapshot_id: string;
  source: string;
  target: string;
}

export interface RemediationRequest {
  path_id: string;
}

// UI State types
export type RiskLevel = "safe" | "low" | "medium" | "high" | "critical";

export function getRiskLevel(score: number): RiskLevel {
  if (score < 30) return "safe";
  if (score < 50) return "low";
  if (score < 60) return "medium";
  if (score < 80) return "high";
  return "critical";
}

export function getRiskColor(score: number): string {
  if (score < 30) return "#30d158";
  if (score < 60) return "#ffd60a";
  if (score < 80) return "#ff9f0a";
  return "#ff2d55";
}
