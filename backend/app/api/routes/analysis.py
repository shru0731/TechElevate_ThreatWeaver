from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_analysis_service, get_db, get_job_service, get_persistence_service
from app.models.user import User
from app.security import require_analyst_or_admin, require_viewer_or_above
from app.schemas.analysis import (
    AnalysisRequest,
    AnalysisResponse,
    AttackPathRecordSchema,
    PathAnalysisSchema,
    PersistedAnalysisResponse,
    SnapshotResultSchema,
    SnapshotSchema,
    UserSnapshotSchema,
)
from app.schemas.ingestion import IngestionRequest
from app.schemas.jobs import JobAcceptedResponse
from app.services.analysis_service import AnalysisService
from app.services.audit_service import record_audit_event
from app.services.job_service import JobService
from app.services.persistence_service import PersistenceService

router = APIRouter()


@router.post("/predict", response_model=AnalysisResponse, status_code=status.HTTP_200_OK)
def predict_attack_path(
    request: AnalysisRequest,
    analysis_service: AnalysisService = Depends(get_analysis_service),
    current_user: User = Depends(require_analyst_or_admin),
) -> AnalysisResponse:
    try:
        return analysis_service.run_analysis(request)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error


@router.post("/analyze", response_model=PersistedAnalysisResponse, status_code=status.HTTP_201_CREATED)
def analyze_and_persist(
    request: AnalysisRequest,
    db: Session = Depends(get_db),
    analysis_service: AnalysisService = Depends(get_analysis_service),
    persistence_service: PersistenceService = Depends(get_persistence_service),
    current_user: User = Depends(require_analyst_or_admin),
) -> PersistedAnalysisResponse:
    try:
        topology, risk_scores, attack_paths = analysis_service.run_core_analysis(request)
        remediation = analysis_service.generate_remediation(attack_paths)
        persistence_request = request.model_copy(update={"topology": topology, "user_id": current_user.id})
        snapshot = persistence_service.create_snapshot(db, persistence_request)
        remediation_dict = {
            "summary": remediation.summary,
            "recommended_actions": remediation.recommended_actions,
            "confidence": remediation.confidence,
            "provider": remediation.provider,
        }
        records = persistence_service.save_analysis(
            db=db,
            snapshot_id=snapshot.id,
            attack_paths=attack_paths,
            risk_scores=risk_scores,
            target_node=request.target_node,
            remediation_data=remediation_dict,
        )
        record_audit_event(
            db,
            actor_user_id=current_user.id,
            action_type="analysis.create",
            entity_type="snapshot",
            entity_id=str(snapshot.id),
            details={"attack_record_count": len(records)},
        )
        db.commit()
        db.refresh(snapshot)
        for record in records:
            db.refresh(record)
        return PersistedAnalysisResponse(
            snapshot_id=snapshot.id,
            attack_record_ids=[record.id for record in records],
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
    except ValueError as error:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error
    except Exception:
        db.rollback()
        raise


@router.get("/snapshots/{snapshot_id}", response_model=SnapshotResultSchema)
def get_snapshot_results(
    snapshot_id: int,
    db: Session = Depends(get_db),
    persistence_service: PersistenceService = Depends(get_persistence_service),
    current_user: User = Depends(require_viewer_or_above),
) -> SnapshotResultSchema:
    snapshot = persistence_service.get_snapshot_results(db, snapshot_id)
    if snapshot is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Snapshot not found")

    return SnapshotResultSchema(
        snapshot=SnapshotSchema(
            id=snapshot.id,
            name=snapshot.name,
            source_type=snapshot.source_type,
            topology_data=snapshot.topology_data,
            risk_scores=snapshot.risk_scores or {},
            overall_risk_score=snapshot.overall_risk_score,
            created_by_user_id=snapshot.created_by_user_id,
            created_at=snapshot.created_at.isoformat() if snapshot.created_at else None,
        ),
        attack_paths=[
            AttackPathRecordSchema(
                id=record.id,
                snapshot_id=record.snapshot_id,
                path_data=record.path_data or {},
                risk_score=record.risk_score,
                entry_node=record.entry_node,
                target_node=record.target_node,
                nodes=record.nodes or [],
                score=record.score,
                likelihood=record.likelihood,
                explanation=record.explanation,
                created_at=record.created_at.isoformat() if record.created_at else None,
            )
            for record in snapshot.attack_paths
        ],
    )


@router.get("/users/{user_id}/snapshots", response_model=list[UserSnapshotSchema])
def get_user_snapshots(
    user_id: int,
    db: Session = Depends(get_db),
    persistence_service: PersistenceService = Depends(get_persistence_service),
    current_user: User = Depends(require_viewer_or_above),
) -> list[UserSnapshotSchema]:
    snapshots = persistence_service.get_user_snapshots(db, user_id)
    return [
        UserSnapshotSchema(
            id=snapshot.id,
            name=snapshot.name,
            source_type=snapshot.source_type,
            risk_scores=snapshot.risk_scores or {},
            overall_risk_score=snapshot.overall_risk_score,
            attack_path_count=len(snapshot.attack_paths),
            created_at=snapshot.created_at.isoformat() if snapshot.created_at else None,
        )
        for snapshot in snapshots
    ]


@router.post("/analyze-live", response_model=JobAcceptedResponse, status_code=status.HTTP_202_ACCEPTED)
def analyze_live(
    payload: IngestionRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    job_service: JobService = Depends(get_job_service),
    current_user: User = Depends(require_analyst_or_admin),
) -> JobAcceptedResponse:
    job = job_service.create_job(
        db,
        job_type="live_analysis",
        payload=payload.model_dump(),
        created_by_user_id=current_user.id,
    )
    db.commit()
    dispatch_mode = job_service.dispatch_job(job.id, background_tasks=background_tasks)
    return JobAcceptedResponse(job_id=job.id, status=job.status, message="Live analysis job queued", dispatch_mode=dispatch_mode)
