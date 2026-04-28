from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, get_job_service
from app.models import User
from app.schemas.jobs import JobAcceptedResponse, JobStatusResponse, RemediationJobRequest
from app.security import require_analyst_or_admin, require_viewer_or_above
from app.services.job_service import JobService

router = APIRouter()


@router.get("/{job_id}", response_model=JobStatusResponse)
def get_job_status(
    job_id: int,
    db: Session = Depends(get_db),
    job_service: JobService = Depends(get_job_service),
    current_user: User = Depends(require_viewer_or_above),
) -> JobStatusResponse:
    job = job_service.get_job(db, job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    queue_mode = None
    dispatched_at = None
    if job.payload:
        queue_mode = job.payload.get("queue_mode")
        dispatched_at = job.payload.get("dispatched_at")
    return JobStatusResponse.model_validate(
        {
            "id": job.id,
            "job_type": job.job_type,
            "status": job.status,
            "queue_mode": queue_mode,
            "payload": job.payload,
            "result": job.result,
            "error_message": job.error_message,
            "created_by_user_id": job.created_by_user_id,
            "created_at": job.created_at,
            "started_at": job.started_at,
            "finished_at": job.finished_at,
            "dispatched_at": dispatched_at,
        }
    )


@router.post("/remediation", response_model=JobAcceptedResponse, status_code=status.HTTP_202_ACCEPTED)
def create_remediation_job(
    payload: RemediationJobRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    job_service: JobService = Depends(get_job_service),
    current_user: User = Depends(require_analyst_or_admin),
) -> JobAcceptedResponse:
    job = job_service.create_job(
        db,
        job_type="remediation_generation",
        payload=payload.model_dump(),
        created_by_user_id=current_user.id,
    )
    db.commit()
    dispatch_mode = job_service.dispatch_job(job.id, background_tasks=background_tasks)
    return JobAcceptedResponse(job_id=job.id, status=job.status, message="Remediation job queued", dispatch_mode=dispatch_mode)
