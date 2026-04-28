import json
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

from app.core.config import get_settings
from app.core.resilience import retry_operation
from app.models.domain import AttackPath, RemediationPlan
from openai import OpenAI

try:
    import google.generativeai as genai
except ImportError:
    genai = None

import jsonschema

logger = logging.getLogger(__name__)

# PRD §9.4 – exact JSON schema for LLM responses
REMEDIATION_RESPONSE_SCHEMA = {
    "type": "object",
    "required": ["summary", "actions", "confidence"],
    "properties": {
        "summary": {"type": "string", "maxLength": 280},
        "actions": {
            "type": "array",
            "minItems": 3,
            "maxItems": 6,
            "items": {
                "type": "object",
                "required": ["priority", "node", "step"],
                "properties": {
                    "priority": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                    "node": {"type": "string"},
                    "step": {"type": "string"},
                    "command": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    },
    "additionalProperties": False,
}


class LLMModule:
    """Encapsulates LLM-backed and fallback remediation generation.

    Implements PRD §6.4 / §9.4 with strict JSON contract enforcement.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._gemini_model = None
        self._groq_client = None

        if (
            self._settings.enable_remote_llm
            and self._settings.llm_provider.lower() == "gemini"
            and self._settings.gemini_api_key
            and genai is not None
        ):
            genai.configure(api_key=self._settings.gemini_api_key)
            self._gemini_model = genai.GenerativeModel(self._settings.gemini_model)
        elif (
            self._settings.enable_remote_llm
            and self._settings.llm_provider.lower() == "groq"
            and self._settings.groq_api_key
        ):
            self._groq_client = OpenAI(
                api_key=self._settings.groq_api_key,
                base_url=self._settings.groq_base_url,
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def generate_remediation(self, attack_paths: list[AttackPath]) -> RemediationPlan:
        if not attack_paths:
            return RemediationPlan(
                summary="No viable attack paths were identified for remediation.",
                recommended_actions=[
                    "Validate topology completeness and confirm the selected entry point."
                ],
                confidence=0.95,
                provider="rule-based",
            )

        # Try LLM first
        llm_result = None
        if self._gemini_model is not None:
            llm_result = self._try_llm(self._generate_gemini, attack_paths)
        elif self._groq_client is not None:
            llm_result = self._try_llm(self._generate_groq, attack_paths)

        if llm_result is not None:
            return llm_result

        # Fallback to NVD‑informed / rule‑based
        return self._build_fallback_remediation(attack_paths)

    def get_status(self) -> dict[str, str | bool]:
        # ... unchanged ...
        if self._groq_client is not None:
            return {
                "provider": "groq",
                "model": self._settings.groq_model,
                "mode": "remote",
                "remote_enabled": True,
                "active": True,
            }
        if self._gemini_model is not None:
            return {
                "provider": "gemini",
                "model": self._settings.gemini_model,
                "mode": "remote",
                "remote_enabled": True,
                "active": True,
            }
        return {
            "provider": "fallback",
            "model": "fallback-rule-engine",
            "mode": "fallback",
            "remote_enabled": self._settings.enable_remote_llm,
            "active": True,
        }

    # ------------------------------------------------------------------
    # LLM attempts
    # ------------------------------------------------------------------
    def _try_llm(self, llm_func, attack_paths: list[AttackPath]) -> RemediationPlan | None:
        try:
            return llm_func(attack_paths)
        except Exception:
            logger.warning("LLM call failed, falling back", exc_info=True)
        return None

    def _generate_gemini(self, attack_paths: list[AttackPath]) -> RemediationPlan | None:
        highest_risk_path = attack_paths[0]
        prompt = self._build_json_prompt(highest_risk_path)

        try:
            def invoke():
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(
                        self._gemini_model.generate_content,
                        prompt,
                        request_options={"timeout": self._settings.llm_request_timeout_seconds},
                    )
                    return future.result(timeout=self._settings.llm_request_timeout_seconds + 1)

            response = retry_operation(invoke, retries=self._settings.external_max_retries, delay_seconds=0.1)
            response_text = getattr(response, "text", "") or ""
        except Exception:
            return None

        return self._parse_and_validate(response_text, "gemini:" + self._settings.gemini_model)

    def _generate_groq(self, attack_paths: list[AttackPath]) -> RemediationPlan | None:
        highest_risk_path = attack_paths[0]
        prompt = self._build_json_prompt(highest_risk_path)

        try:
            def invoke():
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(
                        self._groq_client.chat.completions.create,
                        model=self._settings.groq_model,
                        messages=[
                            {"role": "system", "content": "You are a senior cybersecurity remediation analyst. Return valid JSON only."},
                            {"role": "user", "content": prompt},
                        ],
                        temperature=0.1,
                        response_format={"type": "json_object"},
                    )
                    return future.result(timeout=self._settings.llm_request_timeout_seconds + 1)

            response = retry_operation(invoke, retries=self._settings.external_max_retries, delay_seconds=0.1)
            choices = getattr(response, "choices", None) or []
            if not choices:
                return None
            response_text = getattr(choices[0].message, "content", "") or ""
        except Exception:
            return None

        return self._parse_and_validate(response_text, "groq:" + self._settings.groq_model)

    # ------------------------------------------------------------------
    # Prompt building
    # ------------------------------------------------------------------
    def _build_json_prompt(self, path: AttackPath) -> str:
        context = {
            "attack_path_nodes": path.nodes,
            "risk_score": getattr(path, "score", 0.0),
            "likelihood": getattr(path, "likelihood", 0.0),
            "hops": getattr(path, "hop_details", []),
        }
        instructions = {
            "task": "Generate a remediation plan for the highest-risk attack path.",
            "response_schema": REMEDIATION_RESPONSE_SCHEMA,
            "rules": [
                "Return ONLY the JSON object. No extra text.",
                "Include 3-6 actions, each with a priority, node, step, and optionally a command.",
                "Base actions on the provided CVE and hop information.",
                "Be specific: mention CVEs, hostnames, or IPs where possible.",
            ],
        }
        payload = {
            "system": "You are a senior cybersecurity architect. Return ONLY valid raw JSON. No markdown, no backticks, no preamble.",
            "context": context,
            "instructions": instructions,
        }
        return json.dumps(payload, indent=2)

    # ------------------------------------------------------------------
    # Response handling
    # ------------------------------------------------------------------
    def _parse_and_validate(self, raw_text: str, provider: str) -> RemediationPlan | None:
        if not raw_text.strip():
            return None
        # Try direct parse
        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError:
            # Sometimes the LLM wraps JSON in markdown
            start = raw_text.find("{")
            end = raw_text.rfind("}") + 1
            if start != -1 and end != 0:
                try:
                    data = json.loads(raw_text[start:end])
                except json.JSONDecodeError:
                    return None
            else:
                return None

        # Validate against PRD schema
        try:
            jsonschema.validate(instance=data, schema=REMEDIATION_RESPONSE_SCHEMA)
        except jsonschema.ValidationError:
            logger.warning("LLM response failed JSON schema validation")
            return None

        # Convert to RemediationPlan
        actions = []
        for act in data["actions"]:
            action_text = f"[{act['priority']}] {act['node']}: {act['step']}"
            if act.get("command"):
                action_text += f" (Command: {act['command']})"
            actions.append(action_text)

        return RemediationPlan(
            summary=data["summary"],
            recommended_actions=actions,
            confidence=data["confidence"],
            provider=provider,
        )

    # ------------------------------------------------------------------
    # Fallback
    # ------------------------------------------------------------------
    def _build_fallback_remediation(self, attack_paths: list[AttackPath]) -> RemediationPlan:
        highest_risk_path = attack_paths[0]
        # Try to extract CVE information from hop_details to give NVD‑templated advice
        cve_summary = ""
        hop_list = getattr(highest_risk_path, "hop_details", [])
        for hop in hop_list:
           if isinstance(hop, dict) and hop.get("cves"):
                cve_summary = f"Focus on CVEs: {', '.join(hop['cves'])} on node {hop.get('to', '')}. "
                break
        summary = (
            f"Remediate the highest-risk attack path: {' → '.join(highest_risk_path.nodes)}. "
            f"{cve_summary}Prioritize containment, patching, and segmentation."
        )
        return RemediationPlan(
            summary=summary.strip(),
            recommended_actions=[
                "Patch all CVEs identified on the attacker’s pivot nodes per NVD advisories.",
                "Isolate the entry point (internet‑facing asset) and rotate credentials.",
                "Restrict lateral movement between affected network segments via firewall rules.",
                "Deploy detection rules for the observed attack techniques.",
            ],
            confidence=0.81,
            provider="fallback-rule-engine",
        )