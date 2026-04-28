from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, get_job_service, get_monitor_event_bus_dependency, get_monitor_service
from app.models import User
from app.schemas.monitoring import (
    MonitorCreate,
    MonitorLatestResultResponse,
    MonitorResponse,
    MonitorRunAcceptedResponse,
    MonitorRunResponse,
    MonitorUpdate,
)
from app.security import decode_access_token, require_analyst_or_admin, require_viewer_or_above
from app.services.job_service import JobService
from app.services.monitor_event_bus import MonitorEventBus
from app.services.monitor_service import MonitorService

router = APIRouter()


def _require_monitor(
    db: Session,
    monitor_service: MonitorService,
    monitor_id: int,
    current_user: User,
):
    monitor = monitor_service.get_monitor(db, monitor_id, current_user=current_user)
    if monitor is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Monitor not found")
    return monitor


@router.post("", response_model=MonitorResponse, status_code=status.HTTP_201_CREATED)
def create_monitor(
    payload: MonitorCreate,
    db: Session = Depends(get_db),
    monitor_service: MonitorService = Depends(get_monitor_service),
    current_user: User = Depends(require_analyst_or_admin),
) -> MonitorResponse:
    monitor = monitor_service.create_monitor(db, payload, user_id=current_user.id)
    db.commit()
    db.refresh(monitor)
    return monitor_service.to_response(monitor)


@router.get("", response_model=list[MonitorResponse])
def list_monitors(
    db: Session = Depends(get_db),
    monitor_service: MonitorService = Depends(get_monitor_service),
    current_user: User = Depends(require_viewer_or_above),
) -> list[MonitorResponse]:
    return [monitor_service.to_response(monitor) for monitor in monitor_service.list_monitors(db, current_user=current_user)]


@router.get("/{monitor_id}", response_model=MonitorResponse)
def get_monitor(
    monitor_id: int,
    db: Session = Depends(get_db),
    monitor_service: MonitorService = Depends(get_monitor_service),
    current_user: User = Depends(require_viewer_or_above),
) -> MonitorResponse:
    monitor = _require_monitor(db, monitor_service, monitor_id, current_user)
    return monitor_service.to_response(monitor)


@router.patch("/{monitor_id}", response_model=MonitorResponse)
def update_monitor(
    monitor_id: int,
    payload: MonitorUpdate,
    db: Session = Depends(get_db),
    monitor_service: MonitorService = Depends(get_monitor_service),
    current_user: User = Depends(require_analyst_or_admin),
) -> MonitorResponse:
    monitor = _require_monitor(db, monitor_service, monitor_id, current_user)
    monitor_service.update_monitor(db, monitor, payload)
    db.commit()
    db.refresh(monitor)
    return monitor_service.to_response(monitor)


@router.post("/{monitor_id}/run", response_model=MonitorRunAcceptedResponse, status_code=status.HTTP_202_ACCEPTED)
def run_monitor(
    monitor_id: int,
    background_tasks: BackgroundTasks,
    monitor_service: MonitorService = Depends(get_monitor_service),
    job_service: JobService = Depends(get_job_service),
    current_user: User = Depends(require_analyst_or_admin),
) -> MonitorRunAcceptedResponse:
    try:
        return monitor_service.queue_monitor_run(
            monitor_id=monitor_id,
            current_user=current_user,
            trigger_type="manual",
            job_service=job_service,
            background_tasks=background_tasks,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post("/{monitor_id}/pause", response_model=MonitorResponse)
def pause_monitor(
    monitor_id: int,
    db: Session = Depends(get_db),
    monitor_service: MonitorService = Depends(get_monitor_service),
    current_user: User = Depends(require_analyst_or_admin),
) -> MonitorResponse:
    monitor = _require_monitor(db, monitor_service, monitor_id, current_user)
    monitor_service.pause_monitor(db, monitor)
    db.commit()
    db.refresh(monitor)
    return monitor_service.to_response(monitor)


@router.post("/{monitor_id}/resume", response_model=MonitorResponse)
def resume_monitor(
    monitor_id: int,
    db: Session = Depends(get_db),
    monitor_service: MonitorService = Depends(get_monitor_service),
    current_user: User = Depends(require_analyst_or_admin),
) -> MonitorResponse:
    monitor = _require_monitor(db, monitor_service, monitor_id, current_user)
    monitor_service.resume_monitor(db, monitor)
    db.commit()
    db.refresh(monitor)
    return monitor_service.to_response(monitor)


@router.get("/{monitor_id}/runs", response_model=list[MonitorRunResponse])
def list_monitor_runs(
    monitor_id: int,
    db: Session = Depends(get_db),
    monitor_service: MonitorService = Depends(get_monitor_service),
    current_user: User = Depends(require_viewer_or_above),
) -> list[MonitorRunResponse]:
    monitor = _require_monitor(db, monitor_service, monitor_id, current_user)
    return [monitor_service.run_to_response(run) for run in monitor_service.get_runs(db, monitor)]


@router.get("/{monitor_id}/latest", response_model=MonitorLatestResultResponse)
def get_monitor_latest(
    monitor_id: int,
    db: Session = Depends(get_db),
    monitor_service: MonitorService = Depends(get_monitor_service),
    current_user: User = Depends(require_viewer_or_above),
) -> MonitorLatestResultResponse:
    monitor = _require_monitor(db, monitor_service, monitor_id, current_user)
    latest = monitor_service.get_latest_result(db, monitor)
    if latest is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Monitor has no runs yet")
    return latest


def _authenticate_websocket_user(db: Session, token: str) -> User:
    payload = decode_access_token(token)
    email = payload.get("sub")
    if email is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return user


@router.websocket("/ws")
async def monitors_websocket(
    websocket: WebSocket,
    token: str = Query(...),
    monitor_id: int | None = Query(default=None),
    event_bus: MonitorEventBus = Depends(get_monitor_event_bus_dependency),
    monitor_service: MonitorService = Depends(get_monitor_service),
) -> None:
    db = monitor_service._session_factory()
    try:
        user = _authenticate_websocket_user(db, token)
    except HTTPException:
        await websocket.close(code=4401)
        db.close()
        return

    await websocket.accept()
    queue = await event_bus.subscribe(user_id=user.id, role=user.role, monitor_id=monitor_id)
    try:
        while True:
            event = await queue.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        await event_bus.unsubscribe(queue)
    finally:
        try:
            db.close()
        except Exception:
            pass
