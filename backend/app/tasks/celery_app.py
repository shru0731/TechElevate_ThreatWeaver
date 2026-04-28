from __future__ import annotations

try:
    from celery import Celery
except ImportError:  # pragma: no cover - optional in local dev
    Celery = None  # type: ignore[assignment]

from app.core.config import get_settings


settings = get_settings()

celery_app = None
if Celery is not None:  # pragma: no branch
    celery_app = Celery(
        "threatweaver",
        broker=settings.redis_url,
        backend=settings.redis_url,
    )
    celery_app.conf.task_default_queue = "threatweaver"
    celery_app.conf.imports = ("app.tasks.tasks",)
