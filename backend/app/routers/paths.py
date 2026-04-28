from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.models.snapshot import NetworkSnapshot
from app.schemas.analysis import TopologySchema
from app.security import require_analyst_or_admin
from app.services.attack_engine import AttackEngine
from app.services.graph_engine import GraphEngine
from app.services.risk_engine import RiskEngine
from app.core.config import get_settings

router = APIRouter()


@router.post(
    "/predict",
    response_model=dict,
    status_code=status.HTTP_200_OK,
)
def predict_attack_paths(
    request: dict,  # {"snapshot_id": int, "entry_node": str, "target_node": str | None, "max_depth": int, "top_n_paths": int}
    db: Session = Depends(get_db),
    current_user=Depends(require_analyst_or_admin),
) -> dict:
    """Predict and rank attack paths from entry to target."""
    snapshot_id = request.get("snapshot_id")
    entry_node = request.get("entry_node")
    target_node = request.get("target_node")
    max_depth = request.get("max_depth", 5)
    top_n_paths = request.get("top_n_paths", 3)

    if not snapshot_id or not entry_node:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="snapshot_id and entry_node are required",
        )

    snapshot = db.get(NetworkSnapshot, snapshot_id)
    if not snapshot:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Snapshot not found")

    topology = TopologySchema.model_validate(snapshot.topology_data)

    graph = GraphEngine().build_graph(topology)
    risk_scores = RiskEngine().calculate_risk_scores(graph)

    paths = AttackEngine(max_hop_depth=get_settings().max_hop_depth).find_attack_paths(
        graph=graph,
        risk_scores=risk_scores,
        entry_node=entry_node,
        target_node=target_node,
        max_depth=max_depth,
        top_n_paths=top_n_paths,
    )

    return {
        "snapshot_id": snapshot_id,
        "entry_node": entry_node,
        "target_node": target_node,
        "paths": [
            {
                "nodes": path.nodes,
                "score": path.score,
                "likelihood": path.likelihood,
                "explanation": path.explanation,
            }
            for path in paths
        ],
        "count": len(paths),
    }
