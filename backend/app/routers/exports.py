from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, get_job_service
from app.models import ExportRecord, User
from app.schemas.exports import ExportRequest, ExportResponse
from app.security import require_analyst_or_admin, require_viewer_or_above
from app.services.job_service import JobService

router = APIRouter()


def _to_response(export_record: ExportRecord) -> ExportResponse:
    job_id = None
    metadata = None
    error_message = None
    if export_record.request_payload:
        job_id = export_record.request_payload.get("job_id")
        metadata = export_record.request_payload.get("artifact")
        error_message = export_record.request_payload.get("error_message")
    return ExportResponse(
        id=export_record.id,
        snapshot_id=export_record.snapshot_id,
        created_by_user_id=export_record.created_by_user_id,
        export_format=export_record.export_format,
        status=export_record.status,
        storage_path=export_record.storage_path,
        download_token=export_record.download_token,
        created_at=export_record.created_at,
        completed_at=export_record.completed_at,
        job_id=job_id,
        metadata=metadata,
        error_message=error_message,
    )


@router.post("", response_model=ExportResponse, status_code=status.HTTP_202_ACCEPTED)
def create_export(
    payload: ExportRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    job_service: JobService = Depends(get_job_service),
    current_user: User = Depends(require_analyst_or_admin),
) -> ExportResponse:
    job, export_record = job_service.create_export_job(
        db,
        snapshot_id=payload.snapshot_id,
        export_format=payload.export_format,
        created_by_user_id=current_user.id,
    )
    db.commit()
    job_service.dispatch_job(job.id, background_tasks=background_tasks)
    return _to_response(export_record)


@router.get("/{export_id}", response_model=ExportResponse)
def get_export(
    export_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer_or_above),
) -> ExportResponse:
    export_record = db.get(ExportRecord, export_id)
    if export_record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Export not found")
    return _to_response(export_record)


@router.get("/{export_id}/download")
def download_export(
    export_id: int,
    token: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer_or_above),
) -> FileResponse:
    export_record = db.get(ExportRecord, export_id)
    if export_record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Export not found")
    if export_record.download_token != token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid download token")
    if export_record.status != "succeeded" or not export_record.storage_path:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Export is not ready")
    file_path = Path(export_record.storage_path)
    if not file_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Export artifact not found")
    media_type = {
        "json": "application/json",
        "csv": "text/csv",
        "pdf": "application/pdf",
    }.get(export_record.export_format, "application/octet-stream")
    return FileResponse(path=file_path, media_type=media_type, filename=file_path.name)
