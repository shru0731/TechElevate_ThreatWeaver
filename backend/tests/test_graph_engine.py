import networkx as nx

from app.schemas.analysis import EdgeSchema, NodeSchema, TopologySchema
from app.services.graph_engine import GraphEngine


def test_graph_engine_preserves_directed_edges_and_attributes() -> None:
    topology = TopologySchema(
        nodes=[
            NodeSchema(id="internet", type="external", vuln=1.0, criticality="LOW", exposure=1.0, cves=[]),
            NodeSchema(id="app", type="host", vuln=6.0, criticality="HIGH", exposure=4.0, cves=["CVE-2024-1111"]),
            NodeSchema(id="db", type="host", vuln=8.0, criticality="CRITICAL", exposure=3.0, cves=[]),
        ],
        edges=[
            EdgeSchema(source="internet", target="app", exploitability=0.4, lateral_movement_probability=0.5),
            EdgeSchema(source="app", target="db", exploitability=0.8, lateral_movement_probability=0.7),
        ],
    )

    graph = GraphEngine().build_graph(topology)

    assert graph.has_edge("internet", "app")
    assert graph.has_edge("app", "db")
    assert not graph.has_edge("db", "app")
    assert list(graph.successors("internet")) == ["app"]
    assert set(graph.successors("app")) == {"db"}
    assert graph["internet"]["app"]["exploitability"] == 0.4
    assert graph["app"]["db"]["lateral_movement_probability"] == 0.7


def test_round_trip_serialization():
    """Verify that serialize/deserialize preserves all node and edge attributes."""
    G = nx.DiGraph()
    G.add_node("web",
               ip="192.168.1.1",
               services=[{"port": 443, "protocol": "tcp", "service": "https", "version": "Apache 2.4"}],
               cve_list=["CVE-2024-1234"],
               nrs=78.5)
    G.add_node("db", ip="192.168.1.2", cve_list=[], criticality="HIGH")
    G.add_edge("web", "db", etp=0.75, exploit_in_wild=True, protocol="HTTP")

    engine = GraphEngine()
    serialized = engine.serialize(G)
    G2 = engine.deserialize(serialized)

    # Nodes existence
    assert set(G.nodes) == set(G2.nodes)

    # Node attributes equality (including nested structures)
    assert G.nodes["web"]["services"] == G2.nodes["web"]["services"]
    assert G.nodes["web"]["nrs"] == 78.5
    assert G.nodes["db"]["criticality"] == "HIGH"

    # Edge existence and attributes
    assert G.has_edge("web", "db")
    assert G2.has_edge("web", "db")
    assert G.edges[("web", "db")]["etp"] == G2.edges[("web", "db")]["etp"]
    assert G.edges[("web", "db")]["exploit_in_wild"] == G2.edges[("web", "db")]["exploit_in_wild"]