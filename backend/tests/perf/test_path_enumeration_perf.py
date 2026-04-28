import networkx as nx
from app.services.attack_engine import AttackEngine


def test_enumeration_performance_500_nodes(benchmark):
    """500-node graph with short side‑paths to make enumeration realistic."""
    G = nx.DiGraph()
    for i in range(500):
        G.add_node(str(i), nrs=float(i % 10), cves=[], criticality="LOW")
    # Main linear path for connectivity
    for i in range(499):
        G.add_edge(str(i), str(i + 1), etp=0.5, cves=[])
    # Add short cross edges to create many reachable paths within depth 8
    for i in range(0, 500):
        for j in range(1, 5):
            if i + j < 500 and i + j != i + 1:
                G.add_edge(str(i), str(i + j), etp=0.3, cves=[])

    engine = AttackEngine(max_hop_depth=8)
    risk_scores = {node: 5.0 for node in G.nodes}

    result = benchmark(
        engine.find_attack_paths,
        graph=G,
        risk_scores=risk_scores,
        entry_node="0",
        target_node="10",
        max_depth=8,
        top_n_paths=5,
    )
    assert len(result) > 0
    assert len(result) <= 5