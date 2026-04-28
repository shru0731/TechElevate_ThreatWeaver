import time

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, get_job_service, get_llm_module, get_monitor_scheduler_dependency
from app.core.config import get_settings
from app.core.metrics import metrics_registry
from app.services.llm_module import LLMModule
from app.services.job_service import JobService
from app.services.monitor_scheduler import MonitorScheduler
from app.schemas.common import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def health_check(request: Request) -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok",
        service="threatweaver-backend",
        version=settings.app_version,
        request_id=getattr(request.state, "request_id", None),
    )


@router.get("/ready", response_model=HealthResponse)
def readiness_check(
    request: Request,
    db: Session = Depends(get_db),
    llm_module: LLMModule = Depends(get_llm_module),
    job_service: JobService = Depends(get_job_service),
    monitor_scheduler: MonitorScheduler = Depends(get_monitor_scheduler_dependency),
) -> HealthResponse:
    db_started_at = time.perf_counter()
    db.execute(text("SELECT 1"))
    db_latency_ms = (time.perf_counter() - db_started_at) * 1000
    metrics_registry.record_timing("db.readiness_ms", db_latency_ms)
    queue_status = job_service.get_queue_status()
    scheduler_status = monitor_scheduler.status()
    overall_status = "ok"
    if queue_status.get("status") == "degraded":
        overall_status = "degraded"
    if scheduler_status.get("status") == "degraded":
        overall_status = "degraded"
    checks = {
        "database": {"status": "ok", "latency_ms": round(db_latency_ms, 2)},
        "llm": {"status": "ok", **llm_module.get_status()},
        "queue": queue_status,
        "scheduler": scheduler_status,
        "metrics": metrics_registry.snapshot(),
    }
    return HealthResponse(
        status=overall_status,
        service="threatweaver-backend",
        version=get_settings().app_version,
        request_id=getattr(request.state, "request_id", None),
        checks=checks,
    )


@router.get("/llm/status")
def llm_status(llm_module: LLMModule = Depends(get_llm_module)) -> dict[str, str | bool]:
    return llm_module.get_status()


@router.get("/test-db")
def test_db(db: Session = Depends(get_db)) -> dict[str, str]:
    db.execute(text("SELECT 1"))
    return {"status": "DB connected"}
