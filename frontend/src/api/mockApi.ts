import { AnalysisResult, AttackPath, RemediationPlan } from "../types";

const delay = (ms: number) =>
  new Promise((resolve) => setTimeout(resolve, ms));

export const mockAnalyze = async (): Promise<AnalysisResult> => {
  await delay(1800);
  return {
    snapshot_id: `snap_${Date.now()}`,
    gnri: 78.5,
    nodes: [
      { id: "node_1", label: "Gateway", ip: "192.168.1.1", type: "router", risk: 45, services: ["HTTP", "HTTPS"], os: "Cisco IOS" },
      { id: "node_2", label: "WebServer", ip: "192.168.1.10", type: "server", risk: 82, services: ["Apache 2.4", "PHP 7.2"], os: "Ubuntu 20.04", vulnerabilities: ["CVE-2021-41773", "Log4Shell"] },
      { id: "node_3", label: "DB Primary", ip: "192.168.1.20", type: "server", risk: 91, services: ["MySQL 5.7", "Redis"], os: "CentOS 7", vulnerabilities: ["CVE-2022-0778", "SQL Injection"] },
      { id: "node_4", label: "Firewall", ip: "192.168.1.254", type: "firewall", risk: 22, services: ["iptables"], os: "pfSense" },
      { id: "node_5", label: "DevStation", ip: "192.168.1.101", type: "endpoint", risk: 58, services: ["SSH", "VSCode"], os: "macOS 12" },
      { id: "node_6", label: "CI/CD Server", ip: "192.168.1.50", type: "server", risk: 74, services: ["Jenkins 2.3", "Docker"], os: "Ubuntu 22.04", vulnerabilities: ["CVE-2022-22948"] },
      { id: "node_7", label: "LDAP Server", ip: "192.168.1.30", type: "server", risk: 87, services: ["OpenLDAP", "Kerberos"], os: "Debian 11", vulnerabilities: ["Log4Shell", "LDAP Injection"] },
      { id: "node_8", label: "Backup Host", ip: "192.168.1.60", type: "host", risk: 35, services: ["rsync", "NFS"], os: "FreeBSD" },
      { id: "node_9", label: "Admin Console", ip: "192.168.1.200", type: "host", risk: 63, services: ["RDP", "VNC"], os: "Windows Server 2019" },
      { id: "node_10", label: "Monitoring", ip: "192.168.1.70", type: "server", risk: 18, services: ["Prometheus", "Grafana"], os: "Ubuntu 20.04" },
    ],
    edges: [
      { id: "e1", source: "node_4", target: "node_1", protocol: "OSPF" },
      { id: "e2", source: "node_1", target: "node_2", protocol: "HTTP", port: 80 },
      { id: "e3", source: "node_1", target: "node_6", protocol: "HTTPS", port: 443 },
      { id: "e4", source: "node_2", target: "node_3", protocol: "MySQL", port: 3306 },
      { id: "e5", source: "node_2", target: "node_7", protocol: "LDAP", port: 389 },
      { id: "e6", source: "node_6", target: "node_2", protocol: "SSH", port: 22 },
      { id: "e7", source: "node_6", target: "node_3", protocol: "TCP", port: 5432 },
      { id: "e8", source: "node_5", target: "node_6", protocol: "HTTPS", port: 8080 },
      { id: "e9", source: "node_7", target: "node_3", protocol: "TCP" },
      { id: "e10", source: "node_3", target: "node_8", protocol: "rsync" },
      { id: "e11", source: "node_9", target: "node_7", protocol: "LDAP" },
      { id: "e12", source: "node_10", target: "node_2", protocol: "HTTP", port: 9090 },
      { id: "e13", source: "node_10", target: "node_3", protocol: "HTTP" },
    ],
  };
};

export const mockPredictPaths = async (): Promise<{ paths: AttackPath[] }> => {
  await delay(1400);
  return {
    paths: [
      { id: "path_1", nodes: ["node_4", "node_1", "node_2", "node_7", "node_3"], risk: 94.2, likelihood: 0.82 },
      { id: "path_2", nodes: ["node_4", "node_1", "node_6", "node_3"], risk: 88.7, likelihood: 0.71 },
      { id: "path_3", nodes: ["node_5", "node_6", "node_2", "node_3"], risk: 79.3, likelihood: 0.63 },
      { id: "path_4", nodes: ["node_9", "node_7", "node_3"], risk: 91.5, likelihood: 0.78 },
      { id: "path_5", nodes: ["node_4", "node_1", "node_2", "node_3", "node_8"], risk: 72.1, likelihood: 0.55 },
    ],
  };
};

export const mockRemediation = async (
  pathId: string
): Promise<{ plan: RemediationPlan }> => {
  await delay(1200);
  const plans: Record<string, RemediationPlan> = {
    path_1: {
      priority: "CRITICAL",
      summary: "Contain Log4Shell on WebServer and block LDAP externally.",
      recommended_actions: [
        "IMMEDIATE: Patch Log4Shell vulnerability (CVE-2021-44228) on WebServer node_2",
        "IMMEDIATE: Block inbound LDAP traffic on port 389 at perimeter firewall",
        "IMMEDIATE: Rotate all LDAP service account credentials",
        "SHORT-TERM: Upgrade OpenLDAP to latest stable version on node_7",
        "SHORT-TERM: Implement network segmentation between WebServer and LDAP tiers",
        "SHORT-TERM: Enable mutual TLS for LDAP connections",
        "LONG-TERM: Deploy SIEM correlation rules for LDAP anomaly detection",
        "LONG-TERM: Migrate to LDAPS with certificate pinning",
      ],
      confidence: 0.92,
      provider: "mock-llm",
    },
    path_2: {
      priority: "HIGH",
      summary: "Update Jenkins and restrict CI/CD access.",
      recommended_actions: [
        "IMMEDIATE: Update Jenkins to version 2.387.3+ to address CVE-2022-22948",
        "IMMEDIATE: Restrict CI/CD server network access to known IP ranges",
        "SHORT-TERM: Implement database connection pooling with read-only credentials for CI pipelines",
        "SHORT-TERM: Enable audit logging on CI/CD server",
        "LONG-TERM: Adopt secrets management (HashiCorp Vault) for pipeline credentials",
      ],
      confidence: 0.88,
      provider: "mock-llm",
    },
    path_3: {
      priority: "HIGH",
      summary: "Enforce MFA and restrict SSH keys from DevStation.",
      recommended_actions: [
        "IMMEDIATE: Enforce MFA on DevStation VPN access",
        "IMMEDIATE: Revoke overly-permissive SSH keys from node_5 to node_6",
        "SHORT-TERM: Implement jump-host architecture for developer access",
        "LONG-TERM: Zero-trust network access for developer endpoints",
      ],
      confidence: 0.87,
      provider: "mock-llm",
    },
    path_4: {
      priority: "CRITICAL",
      summary: "Isolate Admin Console and disable VNC.",
      recommended_actions: [
        "IMMEDIATE: Isolate Admin Console node_9 from LDAP network segment",
        "IMMEDIATE: Disable VNC on Admin Console and enforce RDP with NLA",
        "IMMEDIATE: Reset all privileged account passwords accessible via Admin Console",
        "SHORT-TERM: Enable Windows Defender Credential Guard on node_9",
        "SHORT-TERM: Patch OpenLDAP LDAP injection vulnerability on node_7",
        "LONG-TERM: Implement PAM solution for privileged access management",
      ],
      confidence: 0.94,
      provider: "mock-llm",
    },
    path_5: {
      priority: "MEDIUM",
      summary: "Encrypt backup data and restrict rsync.",
      recommended_actions: [
        "IMMEDIATE: Encrypt backup data at rest on node_8",
        "SHORT-TERM: Restrict rsync access to dedicated backup user",
        "LONG-TERM: Implement immutable backup strategy with air-gap",
      ],
      confidence: 0.82,
      provider: "mock-llm",
    },
  };
  return { plan: plans[pathId] || plans["path_1"] };
};
