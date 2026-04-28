from fastapi import APIRouter
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse

from app.api.dependencies import get_analysis_service
from app.core.config import get_settings
from app.models.domain import AttackPath
from app.schemas.analysis import AnalysisRequest, PathAnalysisSchema, RemediationRequest, RemediationSchema

router = APIRouter()


def _build_demo_request() -> AnalysisRequest:
    settings = get_settings()
    service = get_analysis_service()
    topology = service._topology_repository.load_topology(settings.demo_topology_path)
    return AnalysisRequest(
        entry_node="PhishingInbox",
        target_node="CoreBankDB",
        max_depth=8,
        top_n_paths=5,
        topology=topology,
    )


@router.get("/demo/story")
def demo_story() -> dict:
    service = get_analysis_service()
    request = _build_demo_request()
    topology, risk_scores, attack_paths = service.run_core_analysis(request)

    return {
        "scenario": {
            "title": "Bank Network Attack Path Demo",
            "story": (
                "An attacker compromises a banking employee via phishing, pivots through the "
                "application tier, and attempts to reach the core banking database."
            ),
            "entry_node": request.entry_node,
            "target_node": request.target_node,
        },
        "topology": topology.model_dump(),
        "risk_scores": risk_scores,
        "attack_paths": [
            PathAnalysisSchema(
                nodes=path.nodes,
                score=path.score,
                likelihood=path.likelihood,
                explanation=path.explanation,
            ).model_dump()
            for path in attack_paths
        ],
    }


@router.post("/demo/remediation", response_model=RemediationSchema)
async def demo_remediation(request: RemediationRequest) -> RemediationSchema:
    service = get_analysis_service()
    attack_paths = [
        AttackPath(
            nodes=path.nodes,
            score=path.score,
            likelihood=path.likelihood,
            explanation=path.explanation,
        )
        for path in request.attack_paths
    ]
    return await run_in_threadpool(service.generate_remediation, attack_paths)


@router.get("/demo/dashboard", response_class=HTMLResponse)
def demo_dashboard() -> str:
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ThreatWeaver Demo Dashboard</title>
  <script src="https://unpkg.com/cytoscape@3.30.2/dist/cytoscape.min.js"></script>
  <style>
    :root {
      --bg: #07111f;
      --panel: rgba(14, 25, 46, 0.94);
      --panel-alt: rgba(10, 18, 34, 0.96);
      --text: #edf3ff;
      --muted: #9bb0d3;
      --accent: #42e0b3;
      --accent-soft: rgba(66, 224, 179, 0.14);
      --warn: #ffb454;
      --line: #29466f;
      --danger: #ff6b6b;
      --gold: #ffd166;
      --safe: #39d98a;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", Tahoma, sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at 12% 8%, rgba(66, 224, 179, 0.20), transparent 22%),
        radial-gradient(circle at 88% 6%, rgba(255, 180, 84, 0.18), transparent 18%),
        linear-gradient(180deg, #07111f, #050a14 58%, #04070d 100%);
    }
    .shell {
      display: grid;
      grid-template-columns: minmax(0, 2.45fr) minmax(360px, 1fr);
      min-height: 100vh;
      gap: 20px;
      padding: 20px;
    }
    .panel {
      background: var(--panel);
      border: 1px solid rgba(152, 171, 200, 0.15);
      border-radius: 22px;
      box-shadow: 0 24px 70px rgba(0, 0, 0, 0.42);
      overflow: hidden;
      backdrop-filter: blur(10px);
    }
    .panel-head {
      padding: 22px 24px 18px;
      border-bottom: 1px solid rgba(152, 171, 200, 0.12);
      background:
        linear-gradient(135deg, rgba(255, 255, 255, 0.04), rgba(255, 255, 255, 0.01)),
        linear-gradient(180deg, rgba(66, 224, 179, 0.05), rgba(255, 255, 255, 0));
    }
    .eyebrow {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 12px;
      padding: 6px 10px;
      border-radius: 999px;
      background: var(--accent-soft);
      color: var(--accent);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    .title {
      margin: 0;
      font-size: 38px;
      font-weight: 800;
      letter-spacing: 0.01em;
    }
    .subtitle {
      margin: 10px 0 0;
      color: var(--muted);
      line-height: 1.65;
      max-width: 72ch;
    }
    .graph-wrap {
      position: relative;
      padding: 14px;
      height: min(78vh, 860px);
    }
    #graph {
      width: 100%;
      height: 100%;
      border-radius: 18px;
      border: 1px solid rgba(152, 171, 200, 0.08);
      background:
        linear-gradient(180deg, rgba(7, 17, 31, 0.92), rgba(9, 18, 36, 0.84)),
        linear-gradient(90deg, transparent 24px, rgba(255,255,255,0.02) 25px),
        linear-gradient(transparent 24px, rgba(255,255,255,0.02) 25px);
      background-size: auto, 26px 26px, 26px 26px;
      opacity: 0;
      transform: translateY(14px) scale(0.985);
      animation: graph-fade-in 0.6s ease forwards;
    }
    .graph-overlay {
      position: absolute;
      top: 28px;
      left: 28px;
      z-index: 2;
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      pointer-events: none;
    }
    .overlay-pill {
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 12px;
      color: var(--muted);
      background: rgba(7, 17, 31, 0.72);
      border: 1px solid rgba(255,255,255,0.05);
      backdrop-filter: blur(8px);
    }
    .graph-message {
      position: absolute;
      inset: 14px;
      display: none;
      align-items: center;
      justify-content: center;
      text-align: center;
      padding: 24px;
      color: var(--muted);
      border-radius: 18px;
      background: rgba(7, 17, 31, 0.78);
      border: 1px dashed rgba(255,255,255,0.12);
      z-index: 1;
    }
    .graph-fallback {
      position: absolute;
      inset: 14px;
      display: none;
      border-radius: 18px;
      overflow: hidden;
      border: 1px solid rgba(152, 171, 200, 0.08);
      background:
        linear-gradient(180deg, rgba(7, 17, 31, 0.92), rgba(9, 18, 36, 0.84)),
        linear-gradient(90deg, transparent 24px, rgba(255,255,255,0.02) 25px),
        linear-gradient(transparent 24px, rgba(255,255,255,0.02) 25px);
      background-size: auto, 26px 26px, 26px 26px;
    }
    .graph-fallback svg {
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      overflow: visible;
    }
    .fallback-node {
      position: absolute;
      transform: translate(-50%, -50%);
      min-width: 132px;
      max-width: 190px;
      padding: 14px 16px;
      border-radius: 18px;
      text-align: center;
      font-size: 12px;
      font-weight: 700;
      line-height: 1.45;
      color: var(--text);
      border: 2px solid rgba(237,243,255,0.42);
      box-shadow: 0 0 0 1px rgba(255,255,255,0.02), 0 18px 34px rgba(0,0,0,0.30);
      z-index: 1;
      cursor: pointer;
    }
    .fallback-node small {
      display: block;
      margin-top: 4px;
      font-size: 11px;
      color: rgba(237, 243, 255, 0.9);
    }
    .fallback-node.highlighted {
      border-color: #42e0b3;
      box-shadow: 0 0 20px rgba(66, 224, 179, 0.42), 0 18px 34px rgba(0,0,0,0.30);
    }
    .edge-tooltip {
      position: absolute;
      z-index: 4;
      display: none;
      min-width: 130px;
      padding: 8px 10px;
      border-radius: 12px;
      background: rgba(5, 11, 22, 0.95);
      border: 1px solid rgba(66, 224, 179, 0.2);
      color: var(--text);
      font-size: 12px;
      box-shadow: 0 18px 40px rgba(0,0,0,0.32);
      pointer-events: none;
    }
    .sidebar {
      display: grid;
      gap: 16px;
      align-content: start;
    }
    .metrics, .card {
      padding: 18px 20px;
      background: var(--panel-alt);
      border: 1px solid rgba(152, 171, 200, 0.12);
      border-radius: 18px;
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.03);
    }
    .metrics {
      display: grid;
      gap: 4px;
    }
    h3 {
      margin: 0 0 14px;
      font-size: 16px;
      font-weight: 750;
    }
    .metric-row, .detail-row {
      display: flex;
      justify-content: space-between;
      margin: 8px 0;
      color: var(--muted);
      gap: 12px;
    }
    .metric-row strong, .detail-row strong {
      color: var(--text);
      text-align: right;
    }
    .path-flow {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
    }
    .path-pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin: 4px 0;
      padding: 9px 12px;
      border-radius: 999px;
      background: linear-gradient(135deg, rgba(66, 224, 179, 0.18), rgba(66, 224, 179, 0.08));
      color: var(--accent);
      font-size: 13px;
      border: 1px solid rgba(66, 224, 179, 0.12);
      box-shadow: 0 0 18px rgba(66, 224, 179, 0.08);
    }
    .score-badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 999px;
      background: rgba(255, 180, 84, 0.12);
      color: var(--warn);
      font-size: 11px;
      vertical-align: middle;
    }
    .path-arrow {
      color: var(--muted);
      font-size: 18px;
      line-height: 1;
      padding: 0 2px;
    }
    .hint {
      margin-top: 10px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.5;
    }
    .score-list {
      display: grid;
      gap: 8px;
      max-height: 250px;
      overflow: auto;
    }
    .score-track {
      position: relative;
      height: 10px;
      background: rgba(255,255,255,0.05);
      border-radius: 999px;
      overflow: hidden;
      margin-top: 6px;
    }
    .score-fill {
      position: absolute;
      inset: 0 auto 0 0;
      border-radius: 999px;
      background: linear-gradient(90deg, #39d98a, #ffd166 58%, #ff6b6b);
    }
    .action {
      margin: 12px 0;
      padding: 10px 12px 10px 14px;
      border-left: 2px solid rgba(66, 224, 179, 0.45);
      background: rgba(255,255,255,0.02);
      border-radius: 0 12px 12px 0;
      color: var(--text);
      line-height: 1.45;
    }
    .tag-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 10px;
    }
    .tag {
      padding: 6px 10px;
      border-radius: 999px;
      background: rgba(66, 224, 179, 0.12);
      border: 1px solid rgba(66, 224, 179, 0.16);
      color: var(--accent);
      font-size: 12px;
    }
    .why-list {
      display: grid;
      gap: 10px;
    }
    .why-item {
      padding: 12px 14px;
      border-radius: 14px;
      background: rgba(255,255,255,0.025);
      border: 1px solid rgba(255,255,255,0.06);
      color: var(--text);
      line-height: 1.5;
    }
    .spinner {
      width: 18px;
      height: 18px;
      border-radius: 50%;
      border: 2px solid rgba(255,255,255,0.14);
      border-top-color: var(--accent);
      animation: spin 0.9s linear infinite;
      display: inline-block;
      vertical-align: middle;
      margin-right: 8px;
    }
    .loading-inline {
      display: inline-flex;
      align-items: center;
    }
    .legend {
      display: flex;
      gap: 14px;
      padding: 0 20px 18px;
      color: var(--muted);
      font-size: 12px;
      flex-wrap: wrap;
    }
    .dot {
      display: inline-block;
      width: 10px;
      height: 10px;
      border-radius: 50%;
      margin-right: 6px;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    @keyframes graph-fade-in {
      to {
        opacity: 1;
        transform: translateY(0) scale(1);
      }
    }
    @media (max-width: 980px) {
      .shell { grid-template-columns: 1fr; }
      .title { font-size: 30px; }
      .graph-wrap { height: 60vh; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <section class="panel">
      <div class="panel-head">
        <div class="eyebrow">AI Cyber Attack Prediction & Remediation</div>
        <h1 class="title">ThreatWeaver Attack Graph</h1>
        <p class="subtitle" id="story">Loading demo scenario...</p>
      </div>
      <div class="graph-wrap">
        <div class="graph-overlay">
          <span class="overlay-pill">Interactive attack graph</span>
          <span class="overlay-pill">Click nodes for risk details</span>
          <span class="overlay-pill">Hover edges for ETP</span>
        </div>
        <div id="graph"></div>
        <div id="graphFallback" class="graph-fallback"></div>
        <div id="graphMessage" class="graph-message"></div>
        <div id="edgeTooltip" class="edge-tooltip"></div>
      </div>
      <div class="legend">
        <span><span class="dot" style="background:#42e0b3"></span>Highlighted attack path</span>
        <span><span class="dot" style="background:#ff6b6b"></span>High-risk asset</span>
        <span><span class="dot" style="background:#39d98a"></span>Lower-risk asset</span>
      </div>
    </section>
    <aside class="sidebar">
      <section class="metrics">
        <div class="metric-row"><span>Scenario</span><strong id="scenarioTitle">Loading</strong></div>
        <div class="metric-row"><span>Entry</span><strong id="entryNode">-</strong></div>
        <div class="metric-row"><span>Target</span><strong id="targetNode">-</strong></div>
        <div class="metric-row"><span>Top Score</span><strong id="topScore">-</strong></div>
        <div class="metric-row"><span>Likelihood</span><strong id="topLikelihood">-</strong></div>
      </section>
      <section class="card">
        <h3>Selected Asset</h3>
        <div class="detail-row"><span>Node</span><strong id="detailNode">-</strong></div>
        <div class="detail-row"><span>Risk Score</span><strong id="detailRisk">-</strong></div>
        <div class="detail-row"><span>CVSS</span><strong id="detailCvss">-</strong></div>
        <div class="detail-row"><span>Criticality</span><strong id="detailCriticality">-</strong></div>
        <div class="detail-row"><span>Exposure</span><strong id="detailExposure">-</strong></div>
        <div class="tag-row" id="detailCves"></div>
      </section>
      <section class="card">
        <h3>Why This Path?</h3>
        <div class="why-list" id="whyPath">
          <div class="why-item">Path reasoning will appear after the graph loads.</div>
        </div>
      </section>
      <section class="card">
        <h3>Predicted Path</h3>
        <div class="path-flow" id="pathNodes"></div>
        <div class="hint">Top-ranked path based on normalized risk and attack likelihood.</div>
      </section>
      <section class="card">
        <h3>Node Risk Scores</h3>
        <div class="score-list" id="riskScores"></div>
      </section>
      <section class="card">
        <h3>AI Remediation</h3>
        <p id="summary"><span class="loading-inline"><span class="spinner"></span>Generating AI insights...</span></p>
        <div id="actions"><div class="action">Rule-based fallback will be used automatically if the LLM is unavailable.</div></div>
      </section>
    </aside>
  </div>
  <script>
    let nodeMap = {};
    let edgeMap = {};

    function showGraphMessage(message) {
      const messageEl = document.getElementById("graphMessage");
      messageEl.textContent = message;
      messageEl.style.display = "flex";
    }

    function riskColor(score) {
      if (score >= 70) return "#ff6b6b";
      if (score >= 35) return "#ffd166";
      return "#39d98a";
    }

    function updateNodeDetails(nodeId, riskScores) {
      const node = nodeMap[nodeId];
      if (!node) return;

      document.getElementById("detailNode").textContent = node.id;
      document.getElementById("detailRisk").textContent = (riskScores[node.id] || 0).toFixed(2);
      document.getElementById("detailCvss").textContent = (node.cvss_max ?? node.vuln ?? 0).toFixed(1);
      document.getElementById("detailCriticality").textContent = node.criticality;
      document.getElementById("detailExposure").textContent = String(node.exposure ?? "-");
      document.getElementById("detailCves").innerHTML = (node.cves && node.cves.length)
        ? node.cves.map((cve) => `<span class="tag">${cve}</span>`).join("")
        : `<span class="tag">No CVEs listed</span>`;
    }

    function updateWhyPath(topPath, riskScores) {
      const pathNodes = topPath.nodes.map((nodeId) => nodeMap[nodeId]).filter(Boolean);
      const pathEdges = topPath.nodes.slice(0, -1)
        .map((nodeId, index) => edgeMap[`${nodeId}->${topPath.nodes[index + 1]}`])
        .filter(Boolean);

      const highestRiskNode = pathNodes.reduce((best, node) => {
        if (!best) return node;
        return (riskScores[node.id] || 0) > (riskScores[best.id] || 0) ? node : best;
      }, null);

      const weakestLink = pathNodes.reduce((best, node) => {
        if (!best) return node;
        return (node.cvss_max ?? node.vuln ?? 0) > (best.cvss_max ?? best.vuln ?? 0) ? node : best;
      }, null);

      const mostExposedEdge = pathEdges.reduce((best, edge) => {
        if (!best) return edge;
        const bestEtp = best.cvss != null
          ? Math.min((best.cvss / 10) * (best.patch_factor ?? 1), 1)
          : Math.min(best.exploitability ?? 1, 1);
        const edgeEtp = edge.cvss != null
          ? Math.min((edge.cvss / 10) * (edge.patch_factor ?? 1), 1)
          : Math.min(edge.exploitability ?? 1, 1);
        return edgeEtp > bestEtp ? edge : best;
      }, null);

      const reasons = [
        highestRiskNode
          ? `Highest risk node: ${highestRiskNode.id} with NRS ${(riskScores[highestRiskNode.id] || 0).toFixed(2)}.`
          : "Highest risk node: unavailable.",
        weakestLink
          ? `Weakest link: ${weakestLink.id} with CVSS ${(weakestLink.cvss_max ?? weakestLink.vuln ?? 0).toFixed(1)}.`
          : "Weakest link: unavailable.",
        mostExposedEdge
          ? `High lateral movement potential on ${mostExposedEdge.source} -> ${mostExposedEdge.target}.`
          : "Lateral movement analysis unavailable.",
        `Model rationale: ${topPath.explanation}.`
      ];

      document.getElementById("whyPath").innerHTML = reasons
        .map((reason) => `<div class="why-item">${reason}</div>`)
        .join("");

      if (highestRiskNode) {
        updateNodeDetails(highestRiskNode.id, riskScores);
      }
    }

    function renderFallbackGraph(topology, riskScores, highlightedEdges, topPath) {
      const fallback = document.getElementById("graphFallback");
      const graph = document.getElementById("graph");
      const positions = {
        PhishingInbox: { x: 12, y: 16 },
        EmployeeLaptop: { x: 30, y: 35 },
        AppServer: { x: 51, y: 38 },
        DomainController: { x: 73, y: 24 },
        CoreBankDB: { x: 85, y: 58 },
        SOCMonitor: { x: 73, y: 78 },
      };

      graph.style.display = "none";
      fallback.style.display = "block";

      const nodesMarkup = topology.nodes.map((node) => {
        const score = riskScores[node.id] || 0;
        const position = positions[node.id] || { x: 50, y: 50 };
        const isHighlighted = topPath.nodes.includes(node.id);
        const className = ["fallback-node", isHighlighted ? "highlighted" : ""].filter(Boolean).join(" ");
        return `
          <div class="${className}" data-node-id="${node.id}" style="left:${position.x}%; top:${position.y}%; background:${riskColor(score)};">
            ${node.id}
            <small>NRS ${score.toFixed(2)}</small>
          </div>
        `;
      }).join("");

      const edgesMarkup = topology.edges.map((edge) => {
        const source = positions[edge.source];
        const target = positions[edge.target];
        if (!source || !target) return "";

        const edgeId = `${edge.source}->${edge.target}`;
        const isHighlighted = highlightedEdges.has(edgeId);
        return `
          <line
            x1="${source.x}%"
            y1="${source.y}%"
            x2="${target.x}%"
            y2="${target.y}%"
            stroke="${isHighlighted ? "#42e0b3" : "rgba(90, 133, 192, 0.62)"}"
            stroke-width="${isHighlighted ? 4.8 : 2.8}"
            stroke-linecap="round"
            marker-end="url(#arrow-${isHighlighted ? "highlighted" : "normal"})"
          />
        `;
      }).join("");

      fallback.innerHTML = `
        <svg viewBox="0 0 100 100" preserveAspectRatio="none">
          <defs>
            <marker id="arrow-normal" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
              <path d="M0,0 L8,4 L0,8 z" fill="rgba(90, 133, 192, 0.78)"></path>
            </marker>
            <marker id="arrow-highlighted" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
              <path d="M0,0 L8,4 L0,8 z" fill="#42e0b3"></path>
            </marker>
          </defs>
          ${edgesMarkup}
        </svg>
        ${nodesMarkup}
      `;

      fallback.querySelectorAll("[data-node-id]").forEach((element) => {
        element.addEventListener("click", () => {
          updateNodeDetails(element.getAttribute("data-node-id"), riskScores);
        });
      });
    }

    function attachGraphInteractions(cy, riskScores) {
      const tooltip = document.getElementById("edgeTooltip");

      cy.on("tap", "node", (evt) => {
        updateNodeDetails(evt.target.id(), riskScores);
      });

      cy.on("mouseover", "edge", (evt) => {
        const edge = evt.target;
        tooltip.innerHTML = `ETP ${(Number(edge.data("etp"))).toFixed(2)}`;
        tooltip.style.display = "block";
      });

      cy.on("mousemove", "edge", (evt) => {
        const position = evt.renderedPosition || evt.position;
        tooltip.style.left = `${position.x + 24}px`;
        tooltip.style.top = `${position.y + 24}px`;
      });

      cy.on("mouseout", "edge", () => {
        tooltip.style.display = "none";
      });
    }

    function renderDashboard(payload) {
      const { scenario, topology, risk_scores: riskScores, attack_paths: attackPaths } = payload;
      const topPath = attackPaths[0];

      if (!topPath) {
        showGraphMessage("No attack path was available for this scenario.");
        throw new Error("No attack paths returned");
      }

      nodeMap = Object.fromEntries(topology.nodes.map((node) => [node.id, node]));
      edgeMap = Object.fromEntries(topology.edges.map((edge) => [`${edge.source}->${edge.target}`, edge]));

      const highlightedEdges = new Set(
        topPath.nodes.slice(0, -1).map((node, index) => `${node}->${topPath.nodes[index + 1]}`)
      );

      document.getElementById("story").textContent = scenario.story;
      document.getElementById("scenarioTitle").textContent = scenario.title;
      document.getElementById("entryNode").textContent = scenario.entry_node;
      document.getElementById("targetNode").textContent = scenario.target_node;
      document.getElementById("topScore").textContent = topPath.score.toFixed(4);
      document.getElementById("topLikelihood").textContent = topPath.likelihood.toFixed(4);

      const nodes = topology.nodes.map((node) => {
        const score = riskScores[node.id] || 0;
        const label = `${node.id}\\nNRS ${score.toFixed(1)}`;
        const size = Math.max(120, 105 + score * 0.9);
        return {
          data: {
            id: node.id,
            label,
            width: size,
            height: Math.max(74, size * 0.64),
            labelWidth: Math.max(94, size - 24),
            risk: score,
            cvss: node.cvss_max ?? node.vuln ?? 0,
            criticality: node.criticality,
            exposure: node.exposure ?? 0,
            cves: node.cves || [],
            highlighted: topPath.nodes.includes(node.id) ? 1 : 0,
            color: riskColor(score),
          }
        };
      });

      const edges = topology.edges.map((edge) => {
        const edgeId = `${edge.source}->${edge.target}`;
        const etp = edge.cvss != null
          ? Math.min((edge.cvss / 10.0) * (edge.patch_factor ?? 1.0), 1.0)
          : Math.min(edge.exploitability ?? 1.0, 1.0);
        const highlighted = highlightedEdges.has(edgeId) ? 1 : 0;
        return {
          data: {
            id: edgeId,
            source: edge.source,
            target: edge.target,
            etp,
            highlighted,
            width: highlighted ? 6.5 + (etp * 3.5) : 2.7 + (etp * 0.8),
            opacity: highlighted ? 1 : 0.48,
          }
        };
      });

      if (window.cytoscape) {
        const cy = cytoscape({
          container: document.getElementById("graph"),
          elements: [...nodes, ...edges],
          layout: {
            name: "breadthfirst",
            directed: true,
            roots: [scenario.entry_node],
            padding: 44,
            spacingFactor: 1.95,
            animate: true,
            animationDuration: 650,
          },
          wheelSensitivity: 0.18,
          minZoom: 0.55,
          maxZoom: 2.25,
          style: [
            {
              selector: "node",
              style: {
                "shape": "round-rectangle",
                "background-color": "data(color)",
                "border-width": 2.5,
                "border-color": (ele) => ele.data("highlighted") ? "#42e0b3" : "rgba(237,243,255,0.34)",
                "width": "data(width)",
                "height": "data(height)",
                "label": "data(label)",
                "text-wrap": "wrap",
                "text-max-width": "data(labelWidth)",
                "text-valign": "center",
                "text-halign": "center",
                "font-size": 12,
                "font-weight": 700,
                "padding": "12px",
                "color": "#081018",
                "overlay-padding": 8,
                "shadow-blur": 28,
                "shadow-color": (ele) => ele.data("highlighted") ? "#42e0b3" : ele.data("color"),
                "shadow-opacity": (ele) => ele.data("highlighted") ? 0.48 : 0.28,
                "shadow-offset-x": 0,
                "shadow-offset-y": 0,
              }
            },
            {
              selector: "edge",
              style: {
                "curve-style": "bezier",
                "line-color": (ele) => ele.data("highlighted") ? "#42e0b3" : "#5a85c0",
                "target-arrow-color": (ele) => ele.data("highlighted") ? "#42e0b3" : "#5a85c0",
                "target-arrow-shape": "triangle",
                "arrow-scale": (ele) => ele.data("highlighted") ? 1.14 : 0.88,
                "width": "data(width)",
                "opacity": "data(opacity)",
                "label": (ele) => ele.data("highlighted") ? `ETP ${Number(ele.data("etp")).toFixed(2)}` : "",
                "font-size": 10,
                "color": "#9bb0d3",
                "text-background-color": "rgba(7,17,31,0.84)",
                "text-background-opacity": 1,
                "text-background-padding": 3,
                "text-rotation": "autorotate",
                "shadow-blur": (ele) => ele.data("highlighted") ? 18 : 8,
                "shadow-color": (ele) => ele.data("highlighted") ? "#42e0b3" : "#5a85c0",
                "shadow-opacity": (ele) => ele.data("highlighted") ? 0.45 : 0.16,
              }
            },
          ],
        });

        cy.fit(cy.elements(), 42);
        cy.zoom(Math.min(cy.maxZoom(), cy.zoom() * 1.2));
        cy.center();
        attachGraphInteractions(cy, riskScores);
      } else {
        renderFallbackGraph(topology, riskScores, highlightedEdges, topPath);
      }

      document.getElementById("pathNodes").innerHTML = topPath.nodes
        .map((node, index) => {
          const score = riskScores[node] || 0;
          const arrow = index < topPath.nodes.length - 1 ? `<span class="path-arrow">&rarr;</span>` : "";
          return `<span class="path-pill">${node}<span class="score-badge">${score.toFixed(1)}</span></span>${arrow}`;
        })
        .join("");

      document.getElementById("riskScores").innerHTML = Object.entries(riskScores)
        .sort((a, b) => b[1] - a[1])
        .map(([node, score]) => `
          <div class="score-item">
            <div class="metric-row"><span>${node}</span><strong>${score.toFixed(2)}</strong></div>
            <div class="score-track"><div class="score-fill" style="width:${Math.max(8, score)}%;"></div></div>
          </div>
        `)
        .join("");

      updateWhyPath(topPath, riskScores);
      return attackPaths;
    }

    function loadDashboard() {
      document.getElementById("summary").innerHTML = '<span class="loading-inline"><span class="spinner"></span>Loading graph...</span>';

      fetch("/api/v1/demo/story")
        .then((response) => {
          if (!response.ok) {
            throw new Error("Story request failed");
          }
          return response.json();
        })
        .then((payload) => {
          const attackPaths = renderDashboard(payload);
          document.getElementById("summary").innerHTML = '<span class="loading-inline"><span class="spinner"></span>Generating AI insights...</span>';

          return fetch("/api/v1/demo/remediation", {
            method: "POST",
            headers: {
              "Content-Type": "application/json"
            },
            body: JSON.stringify({
              attack_paths: attackPaths.length ? [attackPaths[0]] : []
            })
          });
        })
        .then((response) => {
          if (!response.ok) {
            throw new Error("Remediation request failed");
          }
          return response.json();
        })
        .then((remediation) => {
          document.getElementById("summary").textContent = remediation.summary;
          document.getElementById("actions").innerHTML = remediation.recommended_actions
            .map((action) => `<div class="action">${action}</div>`)
            .join("");
        })
        .catch((error) => {
          if (!document.getElementById("pathNodes").innerHTML) {
            showGraphMessage("The graph could not be rendered for this demo right now.");
          }
          document.getElementById("summary").textContent = "Remediation could not be generated right now.";
          document.getElementById("actions").innerHTML = `
            <div class="action">The graph stays available, and rule-based fallback remediation can still be returned by the backend.</div>
          `;
          console.error(error);
        });
    }

    loadDashboard();
  </script>
</body>
</html>
"""
