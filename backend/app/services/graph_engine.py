import networkx as nx

from app.models.domain import AssetNode
from app.schemas.analysis import TopologySchema


class GraphEngine:
    """Constructs a directed attack graph from normalized topology input."""

    def build_graph(self, topology: TopologySchema) -> nx.DiGraph:
        graph = nx.DiGraph()

        for node in topology.nodes:
            asset = AssetNode(
                node_id=node.id,
                asset_type=node.type,
                vulnerability_score=node.vuln,
                criticality=node.criticality,
                exposure=node.exposure,
                cves=node.cves,
            )
            graph.add_node(
                asset.node_id,
                type=asset.asset_type,
                vuln=asset.vulnerability_score,
                criticality=asset.criticality,
                exposure=asset.exposure,
                cves=asset.cves,
                exploit_in_wild=node.exploit_in_wild if hasattr(node, 'exploit_in_wild') else False,
            )

        for edge in topology.edges:
            graph.add_edge(
                edge.source,
                edge.target,
                exploitability=edge.exploitability or edge.etp or 0.5,
                lateral_movement_probability=edge.lateral_movement_probability or 0.5,
            )

        return graph

    @staticmethod
    def serialize(graph: nx.DiGraph) -> dict:
        """Convert a NetworkX DiGraph to a JSON-serializable dict preserving all attributes."""
        return nx.node_link_data(graph, edges="edges")

    @staticmethod
    def deserialize(data: dict) -> nx.DiGraph:
        """Reconstruct a NetworkX DiGraph from a dict produced by serialize()."""
        return nx.node_link_graph(data, directed=True, edges="edges")