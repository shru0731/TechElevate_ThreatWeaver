from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.core.config import get_settings
from app.models.attack_path import AttackPathRecord
from app.models.remediation_plan import RemediationPlan
from app.models.domain import AttackPath
from app.schemas.remediation import (
    RemediationPlanResponse,
    RemediationTaskQueuedResponse,
    RemediationTaskStatusResponse,
)
from app.security import require_analyst_or_admin, require_viewer_or_above
from app.services.llm_module import LLMModule
from app.services.persistence_service import PersistenceService
from app.tasks.tasks import generate_remediation_task

router = APIRouter()


@router.post(
    "/generate",
    response_model=RemediationTaskQueuedResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def generate_remediation(
    request: dict,  # {"attack_path_id": int, "path_data": dict}
    db: Session = Depends(get_db),
    current_user=Depends(require_analyst_or_admin),
) -> RemediationTaskQueuedResponse:
    """Dispatch Celery task to generate AI remediation for an attack path."""
    from app.tasks.celery_app import celery_app

    attack_path_id = request.get("attack_path_id")
    path_data = request.get("path_data")

    if not attack_path_id or not path_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="attack_path_id and path_data are required",
        )

    if celery_app is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Celery runtime is unavailable for remediation generation",
        )

    task = generate_remediation_task.delay(attack_path_id, path_data)

    return RemediationTaskQueuedResponse(
        task_id=task.id,
        status="queued",
        attack_path_id=attack_path_id,
    )


@router.post(
    "/{path_id}",
    response_model=RemediationTaskQueuedResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def generate_remediation_for_path(
    path_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_analyst_or_admin),
) -> RemediationTaskQueuedResponse:
    """
    PRD §5.4 / §7.3 – Generate remediation plan for a specific attack path
    by its database ID. The plan is produced asynchronously via Celery when configured,
    or synchronously in background mode when Celery is unavailable.
    """
    from app.tasks.celery_app import celery_app

    settings = get_settings()
    record = db.get(AttackPathRecord, path_id)
    if record is None or record.nodes is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attack path record not found",
        )

    path_data = {
        "nodes": record.nodes,
        "score": record.score,
        "likelihood": record.likelihood,
        "explanation": record.explanation,
        "hops": (record.path_data or {}).get("hops", []),
    }

    if settings.task_queue_mode == "background" or celery_app is None:
        attack_path = AttackPath(
            nodes=path_data["nodes"],
            score=float(path_data["score"] or 0.0),
            likelihood=float(path_data["likelihood"] or 0.0),
            explanation=str(path_data["explanation"] or ""),
        )
        plan = LLMModule().generate_remediation([attack_path])
        persistence = PersistenceService()
        persistence.persist_attack_path_remediation(
            db=db,
            attack_path_record=record,
            attack_path=attack_path,
            remediation_data={
                "summary": plan.summary,
                "recommended_actions": plan.recommended_actions,
                "confidence": plan.confidence,
                "provider": plan.provider,
            },
        )
        db.commit()
        return RemediationTaskQueuedResponse(
            task_id=f"sync-{path_id}",
            status="completed",
            attack_path_id=path_id,
        )

    task = generate_remediation_task.delay(path_id, path_data)

    return RemediationTaskQueuedResponse(
        task_id=task.id,
        status="queued",
        attack_path_id=path_id,
    )


@router.get(
    "/{task_id}/status",
    response_model=RemediationTaskStatusResponse,
    status_code=status.HTTP_200_OK,
)
def get_remediation_status(
    task_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_viewer_or_above),
) -> RemediationTaskStatusResponse:
    """Poll task status for remediation generation."""
    from app.tasks.celery_app import celery_app

    if task_id.startswith("sync-"):
        try:
            attack_path_id = int(task_id.split("-", 1)[1])
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid sync task id")

        plan = (
            db.query(RemediationPlan)
            .filter(RemediationPlan.attack_path_id == attack_path_id)
            .order_by(RemediationPlan.id.desc())
            .first()
        )

        if plan is None:
            return RemediationTaskStatusResponse(task_id=task_id, status="PENDING")

        return RemediationTaskStatusResponse(
            task_id=task_id,
            status="SUCCESS",
            result={
                "summary": plan.summary,
                "recommended_actions": plan.action_items or [],
                "confidence": plan.confidence,
                "provider": plan.provider,
            },
        )

    if celery_app is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Celery runtime is unavailable for remediation status checks",
        )

    task_result = celery_app.AsyncResult(task_id)

    response = RemediationTaskStatusResponse(task_id=task_id, status=task_result.state)

    if task_result.state == "SUCCESS":
        response.result = task_result.result
    elif task_result.state == "FAILURE":
        response.error = str(task_result.info)

    return response


@router.get(
    "/plan/{remediation_id}",
    response_model=RemediationPlanResponse,
    status_code=status.HTTP_200_OK,
)
def get_remediation_plan(
    remediation_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_viewer_or_above),
) -> RemediationPlanResponse:
    """Retrieve a persisted remediation plan by ID."""
    plan = db.get(RemediationPlan, remediation_id)
    if not plan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remediation plan not found")

    return RemediationPlanResponse.model_validate(plan, from_attributes=True)