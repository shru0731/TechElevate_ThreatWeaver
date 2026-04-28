from app.database import SessionLocal
from app.models.attack_path import AttackPathRecord
from app.models.domain import AttackPath
from app.services.llm_module import LLMModule
from app.services.persistence_service import PersistenceService
from app.tasks.celery_app import celery_app

def _generate_remediation_task_impl(self, attack_path_id: int, path_data: dict) -> dict:
    """Async task to call LLM and persist remediation plans."""
    db = SessionLocal()
    try:
        attack_path_record = db.get(AttackPathRecord, attack_path_id)
        if attack_path_record is None:
            raise ValueError(f"Attack path record {attack_path_id} not found")

        attack_path = AttackPath(
            nodes=path_data.get("nodes", []),
            score=float(path_data.get("score", 0.0)),
            likelihood=float(path_data.get("likelihood", 0.0)),
            explanation=str(path_data.get("explanation", "")),
        )

        plan = LLMModule().generate_remediation([attack_path])
        persistence = PersistenceService()
        remediation_ids = persistence.persist_attack_path_remediation(
            db=db,
            attack_path_record=attack_path_record,
            attack_path=attack_path,
            remediation_data={
                "summary": plan.summary,
                "recommended_actions": plan.recommended_actions,
                "confidence": plan.confidence,
                "provider": plan.provider,
            },
        )
        db.commit()

        return {
            "status": "completed",
            "attack_path_id": attack_path_id,
            "plan": {
                "summary": plan.summary,
                "recommended_actions": plan.recommended_actions,
                "confidence": plan.confidence,
                "provider": plan.provider,
            },
            "remediation_ids": remediation_ids,
        }
    except Exception as exc:
        db.rollback()
        raise self.retry(exc=exc, countdown=5 * (self.request.retries + 1))
    finally:
        db.close()


if celery_app is not None:
    generate_remediation_task = celery_app.task(
        bind=True,
        max_retries=3,
        name="generate_remediation_task",
    )(_generate_remediation_task_impl)
else:
    def generate_remediation_task(*args, **kwargs):  # type: ignore[no-redef]
        raise RuntimeError("Celery runtime is unavailable")

    def _remediation_delay_unavailable(*args, **kwargs):
        raise RuntimeError("Celery runtime is unavailable")

    generate_remediation_task.delay = _remediation_delay_unavailable  # type: ignore[attr-defined]
