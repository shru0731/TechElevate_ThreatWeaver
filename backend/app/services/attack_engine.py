import math
import networkx as nx

from app.models.domain import AttackPath


class AttackEngine:
    """Enumerates and ranks likely attacker traversal paths using prioritized DFS.

    Implements PRD §5.3 / §9.1 / §9.3:
      - Depth-limited DFS (max 8 hops by default).
      - Ranking: alpha=0.6 (structural risk), beta=0.4 (likelihood).
      - Per-hop CVE annotations in the returned AttackPath objects.
    """

    RANKING_ALPHA = 0.6
    RANKING_BETA = 0.4
    _MAX_DISCOVERED_PATHS = 200

    def __init__(self, max_hop_depth: int = 8) -> None:
        self._max_hop_depth = max_hop_depth

    def find_attack_paths(
        self,
        graph: nx.DiGraph,
        risk_scores: dict[str, float],
        entry_node: str,
        target_node: str | None = None,
        max_depth: int = 5,
        top_n_paths: int = 3,
    ) -> list[AttackPath]:
        if entry_node not in graph:
            raise ValueError(f"Entry node '{entry_node}' does not exist in the topology.")

        effective_max_depth = min(max_depth, self._max_hop_depth)
        effective_top_n = min(top_n_paths, 5)

        self._hydrate_node_risk_attributes(graph, risk_scores)
        self._precompute_cve_list(graph)

        ranked_paths: list[AttackPath] = []
        traversal_stats = {"discovered_paths": 0}
        max_node_risk = max(
            (float(graph.nodes[node_id].get("nrs", 0.0)) for node_id in graph.nodes), default=0.0
        )
        max_edge_etp = max(
            (
                float(
                    graph.edges[source, target].get(
                        "etp",
                        graph.edges[source, target].get("lateral_movement_probability", 1.0),
                    )
                )
                for source, target in graph.edges
            ),
            default=1.0,
        )

        self._dfs_paths(
            graph=graph,
            current_node=entry_node,
            target_node=target_node,
            current_path=[entry_node],
            visited={entry_node},
            hop_details=[],
            depth_remaining=effective_max_depth,
            cumulative_risk=float(graph.nodes[entry_node].get("nrs", 0.0)),
            log_likelihood=0.0,
            ranked_paths=ranked_paths,
            top_n_paths=effective_top_n,
            traversal_stats=traversal_stats,
            max_node_risk=max_node_risk,
            max_edge_etp=max_edge_etp,
        )

        ranked_paths.sort(key=lambda item: (item.score, item.likelihood, -len(item.nodes)), reverse=True)
        return ranked_paths[:effective_top_n]

    # ------------------------------------------------------------------
    # DFS traversal
    # ------------------------------------------------------------------
    def _dfs_paths(
        self,
        graph: nx.DiGraph,
        current_node: str,
        target_node: str | None,
        current_path: list[str],
        visited: set[str],
        hop_details: list[dict],
        depth_remaining: int,
        cumulative_risk: float,
        log_likelihood: float,
        ranked_paths: list[AttackPath],
        top_n_paths: int,
        traversal_stats: dict[str, int],
        max_node_risk: float,
        max_edge_etp: float,
    ) -> None:
        if depth_remaining == 0 or traversal_stats["discovered_paths"] >= self._MAX_DISCOVERED_PATHS:
            return

        candidate_threshold = self._current_score_threshold(ranked_paths, top_n_paths)
        if self._should_prune(
            current_path=current_path,
            depth_remaining=depth_remaining,
            cumulative_risk=cumulative_risk,
            candidate_threshold=candidate_threshold,
            max_node_risk=max_node_risk,
            max_edge_etp=max_edge_etp,
        ):
            return

        prioritized_neighbors = sorted(
            graph.successors(current_node),
            key=lambda neighbor: float(graph.nodes[neighbor].get("nrs", 0.0)),
            reverse=True,
        )

        for neighbor in prioritized_neighbors:
            if traversal_stats["discovered_paths"] >= self._MAX_DISCOVERED_PATHS:
                return
            if neighbor in visited:
                continue

            edge_data = graph.get_edge_data(current_node, neighbor, default={})
            edge_etp = float(edge_data.get("etp", edge_data.get("lateral_movement_probability", 1.0)))
            next_log_likelihood = log_likelihood + math.log(max(edge_etp, 1e-6))
            next_cumulative_risk = cumulative_risk + (
                float(graph.nodes[neighbor].get("nrs", 0.0)) * edge_etp
            )

            next_path = current_path + [neighbor]
            next_visited = visited | {neighbor}

            # Build hop detail for this edge
            hop = {
                "from": current_node,
                "to": neighbor,
                "cves": edge_data.get("cves", self._get_node_cves(graph, neighbor)),
                "etp": round(edge_etp, 4),
                "edge_cvss": edge_data.get("cvss"),
            }
            next_hop_details = hop_details + [hop]

            if target_node is None:
                criticality_value = self._get_criticality_value(graph, neighbor)
                is_terminal = graph.out_degree(neighbor) == 0 or criticality_value >= 7
                if is_terminal:
                    self._record_path(
                        next_path, next_hop_details, next_cumulative_risk, next_log_likelihood,
                        ranked_paths, top_n_paths,
                    )
                    traversal_stats["discovered_paths"] += 1
            elif neighbor == target_node:
                self._record_path(
                    next_path, next_hop_details, next_cumulative_risk, next_log_likelihood,
                    ranked_paths, top_n_paths,
                )
                traversal_stats["discovered_paths"] += 1
                if len(ranked_paths) >= top_n_paths:
                    continue

            if target_node is None or neighbor != target_node:
                self._dfs_paths(
                    graph=graph,
                    current_node=neighbor,
                    target_node=target_node,
                    current_path=next_path,
                    visited=next_visited,
                    hop_details=next_hop_details,
                    depth_remaining=depth_remaining - 1,
                    cumulative_risk=next_cumulative_risk,
                    log_likelihood=next_log_likelihood,
                    ranked_paths=ranked_paths,
                    top_n_paths=top_n_paths,
                    traversal_stats=traversal_stats,
                    max_node_risk=max_node_risk,
                    max_edge_etp=max_edge_etp,
                )

    # ------------------------------------------------------------------
    # Record a discovered path
    # ------------------------------------------------------------------
    def _record_path(
        self,
        path: list[str],
        hop_details: list[dict],
        cumulative_risk: float,
        log_likelihood: float,
        ranked_paths: list[AttackPath],
        top_n_paths: int,
    ) -> None:
        likelihood = math.exp(log_likelihood)
        normalized_risk = self._normalize_risk(cumulative_risk, path)
        normalized_likelihood = self._normalize_likelihood(likelihood, path)
        score = round(
            (self.RANKING_ALPHA * normalized_risk) + (self.RANKING_BETA * normalized_likelihood), 4
        )

        ranked_paths.append(
            AttackPath(
                nodes=path,
                score=score,
                likelihood=round(likelihood, 4),
                hop_details=hop_details,
                explanation=(
                    f"Path risk={round(cumulative_risk,2)}, "
                    f"norm_risk={round(normalized_risk,4)}, "
                    f"likelihood={round(likelihood,4)}, "
                    f"norm_likelihood={round(normalized_likelihood,4)}"
                ),
            )
        )
        ranked_paths.sort(key=lambda item: (item.score, item.likelihood, -len(item.nodes)), reverse=True)
        if len(ranked_paths) > top_n_paths:
            del ranked_paths[top_n_paths:]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _hydrate_node_risk_attributes(self, graph: nx.DiGraph, risk_scores: dict[str, float]) -> None:
        for node_id in graph.nodes:
            if "nrs" not in graph.nodes[node_id]:
                graph.nodes[node_id]["nrs"] = float(risk_scores.get(node_id, 0.0))

    def _precompute_cve_list(self, graph: nx.DiGraph) -> None:
        """Pre-populate each edge's 'cves' list from the target node's cves."""
        for u, v in graph.edges:
            if "cves" not in graph.edges[u, v]:
                graph.edges[u, v]["cves"] = graph.nodes[v].get("cves", [])

    def _get_node_cves(self, graph: nx.DiGraph, node: str) -> list:
        return graph.nodes[node].get("cves", [])

    def _current_score_threshold(self, ranked_paths: list[AttackPath], top_n_paths: int) -> float | None:
        if len(ranked_paths) < top_n_paths:
            return None
        return min(path.score for path in ranked_paths)

    def _should_prune(
        self,
        current_path: list[str],
        depth_remaining: int,
        cumulative_risk: float,
        candidate_threshold: float | None,
        max_node_risk: float,
        max_edge_etp: float,
    ) -> bool:
        if candidate_threshold is None:
            return False
        optimistic_steps = max(depth_remaining, 0)
        optimistic_length = len(current_path) + optimistic_steps
        optimistic_risk = cumulative_risk + (optimistic_steps * max_node_risk * max_edge_etp)
        optimistic_normalized_risk = min(optimistic_risk / (max(optimistic_length, 1) * 100.0), 1.0)
        optimistic_score = (self.RANKING_ALPHA * optimistic_normalized_risk) + self.RANKING_BETA
        return optimistic_score <= candidate_threshold

    def _normalize_risk(self, cumulative_risk: float, path: list[str]) -> float:
        max_possible_risk = max(len(path), 1) * 100.0
        return min(cumulative_risk / max_possible_risk, 1.0)

    def _normalize_likelihood(self, likelihood: float, path: list[str]) -> float:
        return likelihood ** (1 / max(len(path) - 1, 1))

    def _get_criticality_value(self, graph: nx.DiGraph, node: str) -> float:
        criticality = graph.nodes[node].get("criticality", 0)
        if isinstance(criticality, str):
            return {"LOW": 1, "MEDIUM": 4, "HIGH": 7, "CRITICAL": 10}.get(criticality.upper(), 0)
        return float(criticality)