from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.models.snapshot import NetworkSnapshot
from app.schemas.analysis import TopologySchema
from app.security import require_viewer_or_above
from app.services.graph_engine import GraphEngine
from app.services.risk_engine import RiskEngine

router = APIRouter()


@router.get(
    "/{snapshot_id}",
    response_model=dict,
    status_code=status.HTTP_200_OK,
)
def get_graph(
    snapshot_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_viewer_or_above),
) -> dict:
    """Return full graph JSON (nodes + edges with NRS/ETP) for a snapshot."""
    snapshot = db.get(NetworkSnapshot, snapshot_id)
    if not snapshot:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Snapshot not found")

    topology = TopologySchema.model_validate(snapshot.topology_data)
    engine = GraphEngine()
    graph = engine.build_graph(topology)

    RiskEngine().calculate_risk_scores(graph)

    nodes = []
    for node in topology.nodes:
        node_dict = node.model_dump()
        node_dict["nrs"] = float(graph.nodes[node.id].get("nrs", 0.0))
        nodes.append(node_dict)

    edges = []
    for edge in topology.edges:
        edge_dict = edge.model_dump()
        edge_dict["etp"] = float(graph.edges[edge.source, edge.target].get("etp", 0.0))
        edges.append(edge_dict)

    return {"nodes": nodes, "edges": edges}
