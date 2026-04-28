from __future__ import annotations

import asyncio
import logging
from typing import Callable

from app.core.config import get_settings
from app.services.job_service import JobService
from app.services.monitor_service import MonitorService

logger = logging.getLogger(__name__)


class MonitorScheduler:
    def __init__(
        self,
        monitor_service: MonitorService | None = None,
        job_service_factory: Callable[[], JobService] | None = None,
    ) -> None:
        self._settings = get_settings()
        self._monitor_service = monitor_service or MonitorService()
        self._job_service_factory = job_service_factory or JobService
        self._task: asyncio.Task[None] | None = None
        self._running = False

    async def start(self) -> None:
        if self._running or not self._settings.monitor_scheduler_enabled:
            return
        if self._settings.task_queue_mode != "background":
            logger.warning("Monitor scheduler startup skipped because background mode is not active")
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop())

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    def status(self) -> dict[str, object]:
        base_status = self._monitor_service.get_scheduler_status()
        base_status["running"] = self._running
        return base_status

    async def _run_loop(self) -> None:
        logger.warning("Monitor scheduler is running in-process; use a dedicated scheduler for multi-instance deployments")
        while self._running:
            try:
                self._monitor_service.poll_due_monitors(self._job_service_factory())
            except Exception:
                logger.exception("Monitor scheduler poll failed")
            await asyncio.sleep(self._settings.monitor_scheduler_poll_seconds)


_monitor_scheduler = MonitorScheduler()


def get_monitor_scheduler() -> MonitorScheduler:
    return _monitor_scheduler
