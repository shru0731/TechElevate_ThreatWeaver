import math

import networkx as nx


# PRD §9.2 constants
CRITICALITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
}
CISA_MULTIPLIER = 1.3


class RiskEngine:
    """Computes PRD-aligned node and edge risk metrics for the attack graph."""

    def calculate_risk_scores(self, graph: nx.DiGraph) -> dict[str, float]:
        risk_scores: dict[str, float] = {}

        for node_id in graph.nodes:
            risk_scores[node_id] = self.compute_nrs(graph, node_id)

        for source, target, _ in graph.edges(data=True):
            self.compute_etp(graph, source, target)

        return risk_scores

    def compute_nrs(self, graph: nx.DiGraph, node: str) -> float:
        """
        Node Risk Score per PRD §9.2:
        NRS = CVSS_max * criticality_weight * cisa_multiplier * log(1 + in_degree)
        """
        node_attrs = graph.nodes[node]

        cvss_max = self._resolve_cvss_max(node_attrs)
        cvss_max = min(max(cvss_max, 0.0), 10.0)

        crit_weight = self._resolve_criticality_weight_int(node_attrs)

        cisa_mult = CISA_MULTIPLIER if node_attrs.get("exploit_in_wild") or self._has_cisa_kev(node_attrs) else 1.0

        in_degree = max(1, graph.in_degree(node))

        raw_nrs = cvss_max * crit_weight * cisa_mult * math.log1p(in_degree)
        nrs = min(round(raw_nrs, 2), 100.0)

        graph.nodes[node]["nrs"] = nrs
        return nrs

    def compute_etp(self, graph: nx.DiGraph, source: str, target: str) -> float:
        """
        Edge Transition Probability per PRD §9.2:
        ETP = (CVSS / 10) * patch_factor * auth_penalty
        """
        edge_data = graph.edges[source, target]
        cvss = edge_data.get("cvss")
        if cvss is None:
            exploit = edge_data.get("exploitability", 0.0)
            cvss = float(exploit) * 10.0
        cvss = min(max(float(cvss), 0.0), 10.0)

        patch_factor = edge_data.get("patch_factor", 1.0)
        patch_factor = min(max(float(patch_factor), 0.0), 1.0)

        auth_penalty = 0.7 if edge_data.get("requires_auth", False) else 1.0

        etp = min((cvss / 10.0) * patch_factor * auth_penalty, 1.0)
        graph.edges[source, target]["etp"] = round(etp, 4)
        return etp

    def compute_gnri(self, graph: nx.DiGraph) -> float:
        """
        Global Network Risk Index per PRD §9.2:
        Average NRS of all CRITICAL and HIGH nodes.
        If none exist, fall back to a weighted average based on criticality
        weights across all nodes.
        """
        critical_nodes = [
            node for node, attrs in graph.nodes(data=True)
            if attrs.get("criticality") in ("CRITICAL", "HIGH")
        ]
        if critical_nodes:
            total_nrs = sum(graph.nodes[node].get("nrs", 0.0) for node in critical_nodes)
            gnri = total_nrs / len(critical_nodes)
        else:
            total_weight = 0.0
            weighted_sum = 0.0
            for node, attrs in graph.nodes(data=True):
                nrs = attrs.get("nrs", 0.0)
                crit = attrs.get("criticality", "LOW")
                weight = CRITICALITY_WEIGHTS.get(crit, 1)
                weighted_sum += nrs * weight
                total_weight += weight
            gnri = weighted_sum / total_weight if total_weight > 0 else 0.0
        return round(gnri, 2)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _resolve_cvss_max(self, attrs: dict) -> float:
        return float(attrs.get("cvss_max", attrs.get("cvss", attrs.get("vuln", 0.0))))

    def _resolve_criticality_weight_int(self, attrs: dict) -> int:
        crit = attrs.get("criticality", "LOW")
        if isinstance(crit, str):
            return CRITICALITY_WEIGHTS.get(crit.upper(), CRITICALITY_WEIGHTS["LOW"])
        return int(crit)

    def _has_cisa_kev(self, attrs: dict) -> bool:
        for vd in attrs.get("vulnerability_details", []):
            if getattr(vd, "exploit_in_wild", False) or getattr(vd, "cisa_kev", False):
                return True
        return False