from app.models.domain import AttackPath
from app.services.llm_module import LLMModule


def get_llm_module() -> LLMModule:
    return LLMModule()


def generate_remediation(best_path, best_risk):
    if not best_path:
        return "No viable attack path found."

    remediation = get_llm_module().generate_remediation(
        [
            AttackPath(
                nodes=list(best_path),
                score=float(best_risk),
                likelihood=0.5,
                explanation="Legacy compatibility remediation request.",
            )
        ]
    )
    return "\n".join([remediation.summary, *remediation.recommended_actions])
