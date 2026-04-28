# backend/app/tasks/tasks.py

from app.tasks.celery_app import celery_app
from app.tasks.remediation_tasks import generate_remediation_task

__all__ = ["generate_remediation_task", "process_job_task"]


def _process_job_task_impl(self, job_id: int) -> dict:
    """Generic Celery task to process any job by ID."""
    from app.services.job_service import JobService

    job_service = JobService()
    try:
        job_service.process_job(job_id)
        return {"status": "completed", "job_id": job_id}
    except Exception as exc:
        raise self.retry(exc=exc, countdown=5 * (self.request.retries + 1))


if celery_app is not None:
    process_job_task = celery_app.task(
        bind=True,
        max_retries=3,
        name="process_job_task",
    )(_process_job_task_impl)
else:
    def process_job_task(*args, **kwargs):  # type: ignore[no-redef]
        raise RuntimeError("Celery runtime is unavailable")

    def _process_delay_unavailable(*args, **kwargs):
        raise RuntimeError("Celery runtime is unavailable")

    process_job_task.delay = _process_delay_unavailable  # type: ignore[attr-defined]
