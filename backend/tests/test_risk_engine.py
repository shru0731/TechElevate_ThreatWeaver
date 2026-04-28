import math
import networkx as nx
import pytest
from app.services.risk_engine import RiskEngine, CRITICALITY_WEIGHTS, CISA_MULTIPLIER


def test_criticality_weights_are_prd_values():
    assert CRITICALITY_WEIGHTS == {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}


def test_cisa_multiplier_is_1_3():
    assert CISA_MULTIPLIER == 1.3


class TestNRS:
    def test_low_risk_node(self):
        G = nx.DiGraph()
        G.add_node("n1", vuln=5.0, criticality="LOW", exploit_in_wild=False)
        engine = RiskEngine()
        nrs = engine.compute_nrs(G, "n1")
        # NRS = 5.0 * 1 * 1.0 * ln(1 + 1) = 5 * ln2 ≈ 3.47
        expected = round(5.0 * 1 * math.log(2), 2)
        assert nrs == pytest.approx(expected, abs=0.01)

    def test_critical_node_with_cisa_kev(self):
        G = nx.DiGraph()
        G.add_node("n1", vuln=9.8, criticality="CRITICAL", exploit_in_wild=True)
        engine = RiskEngine()
        nrs = engine.compute_nrs(G, "n1")
        expected = round(9.8 * 10 * CISA_MULTIPLIER * math.log(2), 2)
        assert nrs == pytest.approx(min(expected, 100), abs=0.01)

    def test_nrs_capped_at_100(self):
        G = nx.DiGraph()
        G.add_node("n1", vuln=10.0, criticality="CRITICAL", exploit_in_wild=True)
        G.add_node("n2")
        G.add_edge("n2", "n1")
        engine = RiskEngine()
        nrs = engine.compute_nrs(G, "n1")
        assert 0 <= nrs <= 100


class TestETP:
    def test_basic_edge_unpatched(self):
        G = nx.DiGraph()
        G.add_node("a")
        G.add_node("b")
        G.add_edge("a", "b", cvss=7.5, patch_factor=1.0, requires_auth=False)
        engine = RiskEngine()
        etp = engine.compute_etp(G, "a", "b")
        assert etp == pytest.approx(0.75, abs=0.001)

    def test_patched_edge(self):
        G = nx.DiGraph()
        G.add_node("a")
        G.add_node("b")
        G.add_edge("a", "b", cvss=9.0, patch_factor=0.1, requires_auth=False)
        engine = RiskEngine()
        etp = engine.compute_etp(G, "a", "b")
        assert etp == pytest.approx(0.09, abs=0.001)

    def test_auth_penalty(self):
        G = nx.DiGraph()
        G.add_node("a")
        G.add_node("b")
        G.add_edge("a", "b", cvss=8.0, patch_factor=1.0, requires_auth=True)
        engine = RiskEngine()
        etp = engine.compute_etp(G, "a", "b")
        assert etp == pytest.approx(0.56, abs=0.001)


class TestGNRI:
    def test_gnri_computation(self):
        """GNRI = average NRS of CRITICAL and HIGH nodes."""
        G = nx.DiGraph()
        G.add_node("web", criticality="HIGH", nrs=90.0)
        G.add_node("db", criticality="CRITICAL", nrs=80.0)
        G.add_node("app", criticality="MEDIUM", nrs=50.0)
        G.add_node("laptop", criticality="LOW", nrs=10.0)
        engine = RiskEngine()
        gnri = engine.compute_gnri(G)
        assert gnri == 85.0

    def test_gnri_fallback(self):
        """If no CRITICAL/HIGH nodes, weighted average of all nodes."""
        G = nx.DiGraph()
        G.add_node("a", criticality="MEDIUM", nrs=50.0)
        G.add_node("b", criticality="MEDIUM", nrs=60.0)
        G.add_node("c", criticality="LOW", nrs=10.0)
        engine = RiskEngine()
        gnri = engine.compute_gnri(G)
        # weights MEDIUM=4, LOW=1; weighted_sum = 50*4 + 60*4 + 10*1 = 450; total_weight=9; 450/9=50
        assert gnri == pytest.approx(50.0)