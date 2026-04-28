from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, get_job_service
from app.models import User
from app.schemas.jobs import JobAcceptedResponse
from app.schemas.ingestion import IngestionRequest
from app.security import require_analyst_or_admin
from app.services.job_service import JobService

router = APIRouter()


@router.post("/jobs", response_model=JobAcceptedResponse, status_code=status.HTTP_202_ACCEPTED)
def create_ingestion_job(
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
