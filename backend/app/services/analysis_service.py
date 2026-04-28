import logging
import time

from app.core.metrics import metrics_registry
from app.models.domain import AttackPath
from app.repositories.topology_repository import TopologyRepository
from app.schemas.analysis import (
    AnalysisRequest,
    AnalysisResponse,
    PathAnalysisSchema,
    RemediationSchema,
    TopologySchema,
)
from app.services.attack_engine import AttackEngine
from app.services.graph_engine import GraphEngine
from app.services.llm_module import LLMModule
from app.services.risk_engine import RiskEngine


logger = logging.getLogger(__name__)


class AnalysisService:
    """Coordinates the full ThreatWeaver prediction and remediation workflow."""

    def __init__(
        self,
        topology_repository: TopologyRepository,
        graph_engine: GraphEngine,
        risk_engine: RiskEngine,
        attack_engine: AttackEngine,
        llm_module: LLMModule,
    ) -> None:
        self._topology_repository = topology_repository
        self._graph_engine = graph_engine
        self._risk_engine = risk_engine
        self._attack_engine = attack_engine
        self._llm_module = llm_module

    def run_core_analysis(
        self,
        request: AnalysisRequest,
    ) -> tuple[TopologySchema, dict[str, float], list[AttackPath], float]:
        started_at = time.perf_counter()
        topology = request.topology or self._topology_repository.load_default_topology()

        graph_started_at = time.perf_counter()
        graph = self._graph_engine.build_graph(topology)
        graph_time_ms = (time.perf_counter() - graph_started_at) * 1000
        metrics_registry.record_timing("analysis.graph_build_ms", graph_time_ms)

        risk_started_at = time.perf_counter()
        risk_scores = self._risk_engine.calculate_risk_scores(graph)
        gnri = self._risk_engine.compute_gnri(graph)
        risk_time_ms = (time.perf_counter() - risk_started_at) * 1000
        metrics_registry.record_timing("analysis.risk_scoring_ms", risk_time_ms)

        paths_started_at = time.perf_counter()
        attack_paths = self._attack_engine.find_attack_paths(
            graph=graph,
            risk_scores=risk_scores,
            entry_node=request.entry_node,
            target_node=request.target_node,
            max_depth=request.max_depth,
            top_n_paths=request.top_n_paths,
        )
        paths_time_ms = (time.perf_counter() - paths_started_at) * 1000
        total_time_ms = (time.perf_counter() - started_at) * 1000
        metrics_registry.record_timing("analysis.attack_path_ms", paths_time_ms)
        metrics_registry.record_timing("analysis.total_ms", total_time_ms)
        logger.info(
            "Core analysis completed",
            extra={
                "graph_ms": round(graph_time_ms, 2),
                "risk_ms": round(risk_time_ms, 2),
                "path_ms": round(paths_time_ms, 2),
                "total_ms": round(total_time_ms, 2),
            },
        )

        return topology, risk_scores, attack_paths, gnri

    def generate_remediation(self, attack_paths: list[AttackPath]) -> RemediationSchema:
        llm_started_at = time.perf_counter()
        remediation = self._llm_module.generate_remediation(attack_paths)
        llm_time_ms = (time.perf_counter() - llm_started_at) * 1000
        metrics_registry.record_timing("analysis.remediation_ms", llm_time_ms)
        logger.info("Remediation generated", extra={"llm_ms": round(llm_time_ms, 2), "provider": remediation.provider})
        return RemediationSchema(
            summary=remediation.summary,
            recommended_actions=remediation.recommended_actions,
            confidence=remediation.confidence,
            provider=remediation.provider,
        )

    def run_analysis(self, request: AnalysisRequest) -> AnalysisResponse:
        _, risk_scores, attack_paths, _ = self.run_core_analysis(request)
        remediation = self.generate_remediation(attack_paths)

        return AnalysisResponse(
            risk_scores=risk_scores,
            attack_paths=[
                PathAnalysisSchema(
                    nodes=path.nodes,
                    score=path.score,
                    likelihood=path.likelihood,
                    explanation=path.explanation,
                )
                for path in attack_paths
            ],
            remediation=remediation,
        )