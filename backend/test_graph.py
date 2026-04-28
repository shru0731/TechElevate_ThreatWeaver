from app.services.analysis_service import AnalysisService
from app.repositories.topology_repository import TopologyRepository
from app.services.graph_engine import GraphEngine
from app.services.risk_engine import RiskEngine
from app.services.attack_engine import AttackEngine
from app.services.llm_module import LLMModule
from app.schemas.analysis import AnalysisRequest


def main():
    # Initialize dependencies
    repo = TopologyRepository()
    analysis_service = AnalysisService(
        topology_repository=repo,
        graph_engine=GraphEngine(),
        risk_engine=RiskEngine(),
        attack_engine=AttackEngine(),
        llm_module=LLMModule(),
    )

    # Minimal request – entry node "A"
    request = AnalysisRequest(entry_node="A")

    # Run core analysis (graph, risk, paths)
    topology, risk_scores, attack_paths = analysis_service.run_core_analysis(request)

    print("\nAll Attack Paths:")
    for path in attack_paths:
        print(f"Path nodes: {path.nodes}, score: {path.score:.2f}, likelihood: {path.likelihood:.2f}")

    if attack_paths:
        best_path = attack_paths[0]
        print("\nBest Attack Path:")
        print(best_path.nodes)
        total_risk = sum(risk_scores.get(node, 0) for node in best_path.nodes)
        print("\nPath Risk (sum of node risks):")
        print(total_risk)

        # Generate remediation using the service (fallback rule‑based if no remote LLM)
        remediation = analysis_service.generate_remediation([best_path])
        print("\nAI Remediation:\n")
        print(remediation.summary)
        for action in remediation.recommended_actions:
            print("-", action)
    else:
        print("No attack paths found.")


if __name__ == "__main__":
    main()