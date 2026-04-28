from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.metrics import metrics_registry
from app.core.resilience import retry_operation
from app.database import SessionLocal
from app.models import AttackPathRecord, BackgroundJob, ExportRecord, Monitor, MonitorRun, NetworkSnapshot
from app.repositories.topology_repository import TopologyRepository
from app.schemas.analysis import AnalysisRequest, PathAnalysisSchema
from app.schemas.ingestion import IngestionRequest
from app.services.analysis_service import AnalysisService
from app.services.attack_engine import AttackEngine
from app.services.audit_service import record_audit_event
from app.services.export_service import ExportService
from app.services.graph_engine import GraphEngine
from app.services.ingestion_service import IngestionService
from app.services.llm_module import LLMModule
from app.services.monitor_service import MonitorService
from app.services.ingestion.nmap_scanner import NmapScanner
from app.services.ingestion.nvd_client import NvdClient
from app.services.persistence_service import PersistenceService
from app.services.risk_engine import RiskEngine
from app.services.ingestion.shodan_enricher import ShodanEnricher
from app.services.ingestion.cisa_kev_client import CISAKEVClient
from app.tasks.celery_app import celery_app


logger = logging.getLogger(__name__)


class JobService:
    def __init__(
        self,
        session_factory: Callable[[], Session] = SessionLocal,
        nvd_client: NvdClient | None = None,
    ) -> None:
        self._settings = get_settings()
        self._session_factory = session_factory
        try:
            nmap_scanner = NmapScanner(self._settings)
        except Exception:
            logger.warning("NmapScanner is unavailable during JobService initialization", exc_info=True)
            nmap_scanner = None
        self._ingestion_service = IngestionService(
            nvd_client=nvd_client or NvdClient(self._settings),
            nmap_scanner=nmap_scanner,
            shodan_enricher=ShodanEnricher(self._settings),
            cisa_kev_client=CISAKEVClient(),
        )
        self._export_service = ExportService(self._settings.export_storage_dir)
        self._persistence_service = PersistenceService()
        self._monitor_service = MonitorService(session_factory=session_factory)

    def _build_analysis_service(self) -> AnalysisService:
        return AnalysisService(
            topology_repository=TopologyRepository(),
            graph_engine=GraphEngine(),
            risk_engine=RiskEngine(),
            attack_engine=AttackEngine(max_hop_depth=self._settings.max_hop_depth),
            llm_module=LLMModule(),
        )

    def create_job(
        self,
        db: Session,
        *,
        job_type: str,
        payload: dict,
        created_by_user_id: int | None = None,
    ) -> BackgroundJob:
        job = BackgroundJob(
            created_by_user_id=created_by_user_id,
            job_type=job_type,
            status="queued",
            payload=payload,
        )
        db.add(job)
        db.flush()
        return job

    def get_job(self, db: Session, job_id: int) -> BackgroundJob | None:
        return db.get(BackgroundJob, job_id)

    def _get_celery_task(self):
        if celery_app is None:
            return None
        from app.tasks.tasks import process_job_task

        return process_job_task

    def get_queue_status(self) -> dict[str, object]:
        configured_for_celery = self._settings.task_queue_mode == "celery"
        celery_task = self._get_celery_task() if configured_for_celery else None
        celery_available = configured_for_celery and celery_app is not None and celery_task is not None
        queue_status = "ok"
        reason = None
        if configured_for_celery and not celery_available:
            queue_status = "degraded"
            reason = "Celery mode configured but Celery runtime is unavailable"
        return {
            "mode": self._settings.task_queue_mode,
            "redis_url": self._settings.redis_url,
            "status": queue_status,
            "reason": reason,
            "celery_enabled": celery_available,
            "worker_runtime": "celery" if celery_app is not None else "background",
        }

    def dispatch_job(self, job_id: int, *, background_tasks=None) -> str:
        db = self._session_factory()
        try:
            job = db.get(BackgroundJob, job_id)
            if job is None:
                raise ValueError("Job not found")

            dispatched_at = datetime.now(timezone.utc)
            payload = dict(job.payload or {})
            payload["queue_mode"] = self._settings.task_queue_mode
            payload["dispatched_at"] = dispatched_at.isoformat()
            job.payload = payload
            db.commit()
        finally:
            db.close()

        dispatched_at = datetime.now(timezone.utc)
        metrics_registry.increment("jobs.dispatched")

        celery_task = self._get_celery_task() if self._settings.task_queue_mode == "celery" else None
        if self._settings.task_queue_mode == "celery" and celery_app is not None and celery_task is not None:
            celery_task.delay(job_id)
            return "celery"

        if background_tasks is not None:
            background_tasks.add_task(self.process_job, job_id)
            return "background"

        if self._settings.task_queue_mode == "background":
            thread = threading.Thread(target=self.process_job, args=(job_id,), daemon=True)
            thread.start()
            return "background"

        self.process_job(job_id)
        return "inline"

    def process_job(self, job_id: int) -> None:
        db = self._session_factory()
        try:
            job = db.get(BackgroundJob, job_id)
            if job is None:
                return

            job.status = "running"
            job.started_at = datetime.now(timezone.utc)
            if job.created_at is not None:
                queued_ms = (job.started_at - self._ensure_aware(job.created_at)).total_seconds() * 1000
                metrics_registry.record_timing("jobs.queue_wait_ms", queued_ms)
            db.commit()

            if job.job_type == "live_analysis":
                result = self._run_live_analysis(db, job)
            elif job.job_type == "monitor_execution":
                result = self._run_monitor_execution(db, job)
            elif job.job_type == "remediation_generation":
                result = self._run_remediation_job(db, job)
            elif job.job_type == "export_generation":
                result = self._run_export_job(db, job)
            else:
                raise ValueError(f"Unsupported job type '{job.job_type}'")

            job.status = "succeeded"
            job.result = result
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
            metrics_registry.increment(f"jobs.{job.job_type}.succeeded")
            finished_at = self._ensure_aware(job.finished_at)
            started_at = self._ensure_aware(job.started_at) if job.started_at else None
            metrics_registry.record_timing(
                f"jobs.{job.job_type}.duration_ms",
                (finished_at - started_at).total_seconds() * 1000 if started_at else 0.0,
            )
        except Exception as exc:
            logger.exception("Job execution failed", exc_info=exc)
            metrics_registry.increment("jobs.failed")
            db.rollback()
            job = db.get(BackgroundJob, job_id)
            if job is not None:
                job.status = "failed"
                job.error_message = str(exc)
                job.finished_at = datetime.now(timezone.utc)
                if job.job_type == "export_generation":
                    export_id = int((job.payload or {}).get("export_id", 0) or 0)
                    if export_id:
                        self._export_service.mark_export_failed(db, export_id, str(exc))
                if job.job_type == "monitor_execution":
                    self._mark_monitor_run_failed(db, job, str(exc))
                db.commit()
        finally:
            db.close()

    def _ensure_aware(self, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    def _run_live_analysis(self, db: Session, job: BackgroundJob) -> dict:
        request = IngestionRequest.model_validate(job.payload)
        result, _snapshot = self._execute_analysis_request(db, request, created_by_user_id=job.created_by_user_id)
        record_audit_event(
            db,
            actor_user_id=job.created_by_user_id,
            action_type="ingestion.live_analysis",
            entity_type="job",
            entity_id=str(job.id),
            details={"snapshot_id": result["snapshot_id"], "warning_count": len(result["warnings"])},
        )
        db.flush()
        return result

    def _run_monitor_execution(self, db: Session, job: BackgroundJob) -> dict:
        payload = job.payload or {}
        monitor_id = int(payload["monitor_id"])
        monitor_run_id = int(payload["monitor_run_id"])
        monitor = db.get(Monitor, monitor_id)
        monitor_run = db.get(MonitorRun, monitor_run_id)
        if monitor is None or monitor_run is None:
            raise ValueError("Monitor execution target not found")

        monitor_run.status = "running"
        monitor_run.started_at = datetime.now(timezone.utc)
        db.flush()
        self._monitor_service.publish_event(
            {
                "type": "monitor.run.running",
                "monitor_id": monitor.id,
                "run_id": monitor_run.id,
                "status": "running",
                "owner_user_id": monitor.created_by_user_id,
                "payload": {"job_id": job.id},
            }
        )

        request = IngestionRequest.model_validate(monitor.config)
        if not request.snapshot_name:
            request = request.model_copy(
                update={"snapshot_name": f"{monitor.name}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"}
            )

        result, snapshot = self._execute_analysis_request(db, request, created_by_user_id=monitor.created_by_user_id)
        previous_snapshot = self._monitor_service.get_previous_successful_snapshot(
            db,
            monitor.id,
            exclude_run_id=monitor_run.id,
        )
        diff_summary = self._monitor_service.build_diff_summary(previous_snapshot, snapshot)
        monitor_run.status = "succeeded"
        monitor_run.snapshot_id = snapshot.id
        monitor_run.diff_summary = diff_summary
        monitor_run.finished_at = datetime.now(timezone.utc)
        monitor.last_success_at = monitor_run.finished_at
        monitor.last_error_message = None
        db.flush()

        self._monitor_service.publish_event(
            {
                "type": "monitor.run.succeeded",
                "monitor_id": monitor.id,
                "run_id": monitor_run.id,
                "status": "succeeded",
                "owner_user_id": monitor.created_by_user_id,
                "payload": {"job_id": job.id, "snapshot_id": snapshot.id, "diff_summary": diff_summary},
            }
        )
        return {
            "monitor_id": monitor.id,
            "monitor_run_id": monitor_run.id,
            "snapshot_id": snapshot.id,
            "diff_summary": diff_summary,
            "warnings": result["warnings"],
            "source_type": result["source_type"],
        }

    def _execute_analysis_request(
        self,
        db: Session,
        request: IngestionRequest,
        *,
        created_by_user_id: int | None,
    ) -> tuple[dict, NetworkSnapshot]:
        ingestion_started_at = datetime.now(timezone.utc)
        ingestion_result = retry_operation(
            lambda: self._ingestion_service.build_topology(request),
            retries=self._settings.external_max_retries,
            delay_seconds=0.1,
            retryable_exceptions=(ValueError,),
        )
        metrics_registry.record_timing(
            "jobs.live_analysis.ingestion_ms",
            (datetime.now(timezone.utc) - ingestion_started_at).total_seconds() * 1000,
        )

        analysis_service = self._build_analysis_service()
        analysis_request = AnalysisRequest(
            user_id=created_by_user_id,
            snapshot_name=request.snapshot_name,
            entry_node=request.entry_node,
            target_node=request.target_node,
            max_depth=request.max_depth,
            top_n_paths=request.top_n_paths,
            topology=ingestion_result.topology,
        )
        topology, risk_scores, attack_paths, gnri = analysis_service.run_core_analysis(analysis_request)
        remediation = analysis_service.generate_remediation(attack_paths)
        snapshot = self._persistence_service.create_snapshot(db, analysis_request.model_copy(update={"topology": topology}))
        snapshot.overall_risk_score = gnri
        records = self._persistence_service.save_analysis(
            db=db,
            snapshot_id=snapshot.id,
            attack_paths=attack_paths,
            risk_scores=risk_scores,
            target_node=request.target_node,
            remediation_data=remediation.model_dump(),
        )
        return (
            {
                "snapshot_id": snapshot.id,
                "attack_record_ids": [record.id for record in records],
                "risk_scores": risk_scores,
                "attack_paths": [
                    PathAnalysisSchema(
                        nodes=path.nodes,
                        score=path.score,
                        likelihood=path.likelihood,
                        explanation=path.explanation,
                    ).model_dump()
                    for path in attack_paths
                ],
                "remediation": remediation.model_dump(),
                "warnings": ingestion_result.warnings,
                "source_type": ingestion_result.source_type,
            },
            snapshot,
        )

    def _mark_monitor_run_failed(self, db: Session, job: BackgroundJob, error_message: str) -> None:
        payload = job.payload or {}
        monitor_run_id = int(payload.get("monitor_run_id", 0) or 0)
        monitor_id = int(payload.get("monitor_id", 0) or 0)
        if not monitor_run_id or not monitor_id:
            return
        monitor_run = db.get(MonitorRun, monitor_run_id)
        monitor = db.get(Monitor, monitor_id)
        if monitor_run is not None:
            monitor_run.status = "failed"
            monitor_run.error_message = error_message
            monitor_run.finished_at = datetime.now(timezone.utc)
        if monitor is not None:
            monitor.last_failure_at = datetime.now(timezone.utc)
            monitor.last_error_message = error_message
            self._monitor_service.publish_event(
                {
                    "type": "monitor.run.failed",
                    "monitor_id": monitor.id,
                    "run_id": monitor_run.id if monitor_run is not None else None,
                    "status": "failed",
                    "owner_user_id": monitor.created_by_user_id,
                    "payload": {"job_id": job.id, "error_message": error_message},
                }
            )

    def _run_remediation_job(self, db: Session, job: BackgroundJob) -> dict:
        snapshot_id = int(job.payload["snapshot_id"])
        attack_path_ids = list(job.payload.get("attack_path_ids") or [])
        snapshot = db.get(NetworkSnapshot, snapshot_id)
        if snapshot is None:
            raise ValueError("Snapshot not found")

        query = db.query(AttackPathRecord).filter(AttackPathRecord.snapshot_id == snapshot_id)
        if attack_path_ids:
            query = query.filter(AttackPathRecord.id.in_(attack_path_ids))
        records = query.order_by(AttackPathRecord.score.desc()).all()
        attack_paths = [
            type(
                "AttackPathProxy",
                (),
                {
                    "nodes": record.nodes or [],
                    "score": record.score or 0.0,
                    "likelihood": record.likelihood or 0.0,
                    "explanation": record.explanation or "",
                },
            )()
            for record in records
        ]
        remediation = self._build_analysis_service().generate_remediation(attack_paths)
        record_audit_event(
            db,
            actor_user_id=job.created_by_user_id,
            action_type="analysis.remediation_job",
            entity_type="snapshot",
            entity_id=str(snapshot_id),
            details={"attack_path_count": len(records)},
        )
        db.flush()
        return {
            "snapshot_id": snapshot_id,
            "attack_path_ids": [record.id for record in records],
            "remediation": remediation.model_dump(),
        }

    def _run_export_job(self, db: Session, job: BackgroundJob) -> dict:
        export_id = int(job.payload["export_id"])
        export_started_at = datetime.now(timezone.utc)
        export_record = self._export_service.generate_export(db, export_id)
        db.flush()
        metrics_registry.record_timing(
            "jobs.export_generation.export_ms",
            (datetime.now(timezone.utc) - export_started_at).total_seconds() * 1000,
        )
        record_audit_event(
            db,
            actor_user_id=job.created_by_user_id,
            action_type="export.generate",
            entity_type="export",
            entity_id=str(export_record.id),
            details={"snapshot_id": export_record.snapshot_id, "format": export_record.export_format},
        )
        return {
            "export_id": export_record.id,
            "snapshot_id": export_record.snapshot_id,
            "download_token": export_record.download_token,
            "storage_path": export_record.storage_path,
        }

    def create_export_job(
        self,
        db: Session,
        *,
        snapshot_id: int,
        export_format: str,
        created_by_user_id: int | None,
    ) -> tuple[BackgroundJob, ExportRecord]:
        job = self.create_job(
            db,
            job_type="export_generation",
            payload={"snapshot_id": snapshot_id, "export_format": export_format},
            created_by_user_id=created_by_user_id,
        )
        export_record = self._export_service.create_export_record(
            db,
            snapshot_id=snapshot_id,
            export_format=export_format,
            created_by_user_id=created_by_user_id,
            job_id=job.id,
        )
        job.payload = {"snapshot_id": snapshot_id, "export_format": export_format, "export_id": export_record.id}
        db.flush()
        return job, export_record