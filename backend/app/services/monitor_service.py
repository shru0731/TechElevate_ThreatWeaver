from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.config import get_settings
from app.database import SessionLocal
from app.models import BackgroundJob, Monitor, MonitorRun, NetworkSnapshot, User
from app.schemas.analysis import SnapshotSchema
from app.schemas.ingestion import IngestionRequest
from app.schemas.monitoring import (
    MonitorCreate,
    MonitorLatestResultResponse,
    MonitorResponse,
    MonitorRunAcceptedResponse,
    MonitorRunResponse,
    MonitorUpdate,
)
from app.services.monitor_event_bus import MonitorEventBus, get_monitor_event_bus


class MonitorService:
    def __init__(
        self,
        session_factory: Callable[[], Session] = SessionLocal,
        event_bus: MonitorEventBus | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._settings = get_settings()
        self._event_bus = event_bus or get_monitor_event_bus()

    def create_monitor(self, db: Session, payload: MonitorCreate, *, user_id: int) -> Monitor:
        monitor = Monitor(
            created_by_user_id=user_id,
            name=payload.name,
            description=payload.description,
            source_type=payload.config.source_type,
            config=payload.config.model_dump(mode="json"),
            interval_seconds=payload.interval_seconds,
            is_enabled=True,
            next_run_at=datetime.now(timezone.utc) + timedelta(seconds=payload.interval_seconds),
        )
        db.add(monitor)
        db.flush()
        return monitor

    def list_monitors(self, db: Session, *, current_user: User) -> list[Monitor]:
        statement = select(Monitor).options(selectinload(Monitor.runs)).order_by(Monitor.created_at.desc())
        if current_user.role != "admin":
            statement = statement.where(Monitor.created_by_user_id == current_user.id)
        return list(db.scalars(statement).all())

    def get_monitor(self, db: Session, monitor_id: int, *, current_user: User) -> Monitor | None:
        statement = select(Monitor).options(selectinload(Monitor.runs)).where(Monitor.id == monitor_id)
        monitor = db.scalar(statement)
        if monitor is None:
            return None
        if current_user.role != "admin" and monitor.created_by_user_id != current_user.id:
            return None
        return monitor

    def update_monitor(self, db: Session, monitor: Monitor, payload: MonitorUpdate) -> Monitor:
        if payload.name is not None:
            monitor.name = payload.name
        if payload.description is not None:
            monitor.description = payload.description
        if payload.interval_seconds is not None:
            monitor.interval_seconds = payload.interval_seconds
            if monitor.is_enabled:
                monitor.next_run_at = datetime.now(timezone.utc) + timedelta(seconds=payload.interval_seconds)
        if payload.config is not None:
            monitor.source_type = payload.config.source_type
            monitor.config = payload.config.model_dump(mode="json")
        if payload.is_enabled is not None:
            monitor.is_enabled = payload.is_enabled
            monitor.next_run_at = (
                datetime.now(timezone.utc) + timedelta(seconds=monitor.interval_seconds)
                if monitor.is_enabled
                else None
            )
        db.flush()
        return monitor

    def pause_monitor(self, db: Session, monitor: Monitor) -> Monitor:
        monitor.is_enabled = False
        monitor.next_run_at = None
        db.flush()
        return monitor

    def resume_monitor(self, db: Session, monitor: Monitor) -> Monitor:
        monitor.is_enabled = True
        monitor.next_run_at = datetime.now(timezone.utc) + timedelta(seconds=monitor.interval_seconds)
        db.flush()
        return monitor

    def get_runs(self, db: Session, monitor: Monitor) -> list[MonitorRun]:
        statement = (
            select(MonitorRun)
            .where(MonitorRun.monitor_id == monitor.id)
            .order_by(MonitorRun.created_at.desc())
        )
        return list(db.scalars(statement).all())

    def get_latest_result(self, db: Session, monitor: Monitor) -> MonitorLatestResultResponse | None:
        statement = (
            select(MonitorRun)
            .options(selectinload(MonitorRun.snapshot))
            .where(MonitorRun.monitor_id == monitor.id)
            .order_by(MonitorRun.created_at.desc())
        )
        latest_run = db.scalar(statement)
        if latest_run is None:
            return None
        snapshot = latest_run.snapshot
        return MonitorLatestResultResponse(
            monitor=self.to_response(monitor),
            latest_run=self.run_to_response(latest_run),
            snapshot=self._snapshot_to_schema(snapshot) if snapshot is not None else None,
        )

    def queue_monitor_run(
        self,
        *,
        monitor_id: int,
        current_user: User | None,
        trigger_type: str,
        job_service,
        background_tasks=None,
    ) -> MonitorRunAcceptedResponse:
        db = self._session_factory()
        try:
            monitor = db.get(Monitor, monitor_id)
            if monitor is None:
                raise ValueError("Monitor not found")
            if current_user is not None and current_user.role != "admin" and monitor.created_by_user_id != current_user.id:
                raise ValueError("Monitor not found")

            active_run = self._get_active_run(db, monitor.id)
            if active_run is not None:
                return MonitorRunAcceptedResponse(
                    monitor_id=monitor.id,
                    run_id=active_run.id,
                    job_id=active_run.job_id,
                    status=active_run.status,
                    dispatch_mode=None,
                )

            run = MonitorRun(
                monitor_id=monitor.id,
                status="queued",
                trigger_type=trigger_type,
            )
            db.add(run)
            db.flush()

            job = job_service.create_job(
                db,
                job_type="monitor_execution",
                payload={"monitor_id": monitor.id, "monitor_run_id": run.id, "trigger_type": trigger_type},
                created_by_user_id=monitor.created_by_user_id,
            )
            run.job_id = job.id
            monitor.last_run_at = datetime.now(timezone.utc)
            if monitor.is_enabled:
                monitor.next_run_at = monitor.last_run_at + timedelta(seconds=monitor.interval_seconds)
            db.commit()

            dispatch_mode = job_service.dispatch_job(job.id, background_tasks=background_tasks)
            self.publish_event(
                {
                    "type": "monitor.run.queued",
                    "monitor_id": monitor.id,
                    "run_id": run.id,
                    "status": "queued",
                    "owner_user_id": monitor.created_by_user_id,
                    "payload": {"job_id": job.id, "trigger_type": trigger_type},
                }
            )
            return MonitorRunAcceptedResponse(
                monitor_id=monitor.id,
                run_id=run.id,
                job_id=job.id,
                status=run.status,
                dispatch_mode=dispatch_mode,
            )
        finally:
            db.close()

    def poll_due_monitors(self, job_service) -> list[int]:
        if not self._settings.monitor_scheduler_enabled:
            return []

        now = datetime.now(timezone.utc)
        db = self._session_factory()
        queued_ids: list[int] = []
        try:
            statement = (
                select(Monitor)
                .where(Monitor.is_enabled.is_(True))
                .where(Monitor.next_run_at.is_not(None))
                .where(Monitor.next_run_at <= now)
                .order_by(Monitor.next_run_at.asc())
            )
            monitors = list(db.scalars(statement).all())
            for monitor in monitors:
                if self._get_active_run(db, monitor.id) is not None:
                    continue
                accepted = self.queue_monitor_run(
                    monitor_id=monitor.id,
                    current_user=None,
                    trigger_type="scheduled",
                    job_service=job_service,
                    background_tasks=None,
                )
                queued_ids.append(accepted.run_id)
        finally:
            db.close()
        return queued_ids

    def get_scheduler_status(self) -> dict[str, Any]:
        if not self._settings.monitor_scheduler_enabled:
            return {"status": "disabled", "mode": self._settings.task_queue_mode}
        if self._settings.task_queue_mode == "celery":
            return {
                "status": "degraded",
                "mode": "celery",
                "reason": "External scheduler process is required when TASK_QUEUE_MODE=celery",
            }
        return {"status": "ok", "mode": "background"}

    def publish_event(self, event: dict[str, Any]) -> None:
        try:
            import asyncio

            loop = asyncio.get_running_loop()
            loop.create_task(self._event_bus.publish(event))
        except RuntimeError:
            self._event_bus.publish_sync(event)

    def to_response(self, monitor: Monitor) -> MonitorResponse:
        return MonitorResponse(
            id=monitor.id,
            name=monitor.name,
            description=monitor.description,
            source_type=monitor.source_type,
            interval_seconds=monitor.interval_seconds,
            is_enabled=monitor.is_enabled,
            config=IngestionRequest.model_validate(monitor.config),
            created_by_user_id=monitor.created_by_user_id,
            last_run_at=monitor.last_run_at,
            last_success_at=monitor.last_success_at,
            last_failure_at=monitor.last_failure_at,
            next_run_at=monitor.next_run_at,
            last_error_message=monitor.last_error_message,
            created_at=monitor.created_at,
            updated_at=monitor.updated_at,
        )

    def run_to_response(self, run: MonitorRun) -> MonitorRunResponse:
        return MonitorRunResponse(
            id=run.id,
            monitor_id=run.monitor_id,
            job_id=run.job_id,
            snapshot_id=run.snapshot_id,
            status=run.status,
            trigger_type=run.trigger_type,
            diff_summary=run.diff_summary,
            error_message=run.error_message,
            created_at=run.created_at,
            started_at=run.started_at,
            finished_at=run.finished_at,
        )

    def build_diff_summary(
        self,
        previous_snapshot: NetworkSnapshot | None,
        current_snapshot: NetworkSnapshot,
    ) -> dict[str, Any]:
        previous_topology = previous_snapshot.topology_data if previous_snapshot is not None else {}
        current_topology = current_snapshot.topology_data or {}

        previous_nodes = {node["id"]: node for node in previous_topology.get("nodes", [])}
        current_nodes = {node["id"]: node for node in current_topology.get("nodes", [])}
        previous_edges = {(edge["source"], edge["target"]) for edge in previous_topology.get("edges", [])}
        current_edges = {(edge["source"], edge["target"]) for edge in current_topology.get("edges", [])}

        changed_nodes: list[dict[str, Any]] = []
        new_cves: list[dict[str, Any]] = []
        for node_id in sorted(set(previous_nodes) & set(current_nodes)):
            previous_node = previous_nodes[node_id]
            current_node = current_nodes[node_id]
            node_changes: dict[str, Any] = {"node_id": node_id}
            for field in ("vuln", "exposure", "criticality"):
                if previous_node.get(field) != current_node.get(field):
                    node_changes[field] = {"before": previous_node.get(field), "after": current_node.get(field)}
            previous_cves = set(previous_node.get("cves", []))
            current_cves = set(current_node.get("cves", []))
            added_cves = sorted(current_cves - previous_cves)
            if added_cves:
                new_cves.append({"node_id": node_id, "cves": added_cves})
            if len(node_changes) > 1:
                changed_nodes.append(node_changes)

        previous_risk = previous_snapshot.overall_risk_score if previous_snapshot is not None else None
        current_risk = current_snapshot.overall_risk_score
        risk_delta = (current_risk or 0.0) - (previous_risk or 0.0)
        risk_delta_exceeded = abs(risk_delta) >= self._settings.monitor_diff_risk_delta_threshold

        return {
            "previous_snapshot_id": previous_snapshot.id if previous_snapshot is not None else None,
            "current_snapshot_id": current_snapshot.id,
            "new_nodes": sorted(set(current_nodes) - set(previous_nodes)),
            "removed_nodes": sorted(set(previous_nodes) - set(current_nodes)),
            "new_edges": [{"source": source, "target": target} for source, target in sorted(current_edges - previous_edges)],
            "removed_edges": [{"source": source, "target": target} for source, target in sorted(previous_edges - current_edges)],
            "changed_nodes": changed_nodes,
            "new_cves": new_cves,
            "risk_delta": risk_delta,
            "risk_delta_exceeded_threshold": risk_delta_exceeded,
            "material_changes": bool(
                (set(current_nodes) - set(previous_nodes))
                or (set(previous_nodes) - set(current_nodes))
                or (current_edges - previous_edges)
                or (previous_edges - current_edges)
                or changed_nodes
                or new_cves
                or risk_delta_exceeded
            ),
        }

    def get_previous_successful_snapshot(self, db: Session, monitor_id: int, *, exclude_run_id: int | None = None) -> NetworkSnapshot | None:
        statement = (
            select(MonitorRun)
            .options(selectinload(MonitorRun.snapshot))
            .where(MonitorRun.monitor_id == monitor_id)
            .where(MonitorRun.status == "succeeded")
            .order_by(MonitorRun.finished_at.desc(), MonitorRun.created_at.desc())
        )
        runs = list(db.scalars(statement).all())
        for run in runs:
            if exclude_run_id is not None and run.id == exclude_run_id:
                continue
            if run.snapshot is not None:
                return run.snapshot
        return None

    def _get_active_run(self, db: Session, monitor_id: int) -> MonitorRun | None:
        statement = (
            select(MonitorRun)
            .where(MonitorRun.monitor_id == monitor_id)
            .where(MonitorRun.status.in_(("queued", "running")))
            .order_by(MonitorRun.created_at.desc())
        )
        return db.scalar(statement)

    def _snapshot_to_schema(self, snapshot: NetworkSnapshot) -> SnapshotSchema:
        return SnapshotSchema(
            id=snapshot.id,
            name=snapshot.name,
            source_type=snapshot.source_type,
            topology_data=snapshot.topology_data,
            risk_scores=snapshot.risk_scores or {},
            overall_risk_score=snapshot.overall_risk_score,
            created_by_user_id=snapshot.created_by_user_id,
            created_at=snapshot.created_at.isoformat() if snapshot.created_at else None,
        )
