from __future__ import annotations

import logging
from collections.abc import Iterable

import httpx

from app.core.config import Settings
from app.core.resilience import retry_operation
from app.schemas.analysis import EnrichedVulnerabilitySchema


logger = logging.getLogger(__name__)


class NvdClient:
    """Thin client for the NVD CVE 2.0 API."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def is_enabled(self) -> bool:
        return bool(self._settings.nvd_enabled and self._settings.nvd_api_key)

    def fetch_cves(self, cve_ids: Iterable[str]) -> tuple[dict[str, EnrichedVulnerabilitySchema], list[str]]:
        unique_cves = sorted({cve_id.strip().upper() for cve_id in cve_ids if cve_id and cve_id.strip()})
        if not unique_cves:
            return {}, []

        if not self._settings.nvd_enabled:
            return {}, ["NVD enrichment is disabled by configuration"]

        if not self._settings.nvd_api_key:
            return {}, ["NVD enrichment skipped because NVD_API_KEY is not configured"]

        results: dict[str, EnrichedVulnerabilitySchema] = {}
        warnings: list[str] = []

        for cve_id in unique_cves:
            try:
                record = retry_operation(
                    lambda cve_id=cve_id: self._fetch_single_cve(cve_id),
                    retries=self._settings.external_max_retries,
                    delay_seconds=0.1,
                    retryable_exceptions=(httpx.HTTPError,),
                )
            except httpx.HTTPError as exc:
                logger.warning("Failed to fetch NVD record", extra={"cve_id": cve_id, "error": str(exc)})
                warnings.append(f"NVD lookup failed for {cve_id}")
                continue

            if record is None:
                warnings.append(f"NVD record was not found for {cve_id}")
                continue

            results[cve_id] = record

        return results, warnings

    def _fetch_single_cve(self, cve_id: str) -> EnrichedVulnerabilitySchema | None:
        headers = {"apiKey": self._settings.nvd_api_key or ""}
        params = {"cveId": cve_id}
        with httpx.Client(timeout=self._settings.external_request_timeout_seconds) as client:
            response = client.get(self._settings.nvd_base_url, headers=headers, params=params)
            response.raise_for_status()
            payload = response.json()
        return self._extract_vulnerability(payload, cve_id)

    def _extract_vulnerability(self, payload: dict, requested_cve_id: str) -> EnrichedVulnerabilitySchema | None:
        vulnerabilities = payload.get("vulnerabilities") or []
        if not vulnerabilities:
            return None

        cve_payload = (vulnerabilities[0] or {}).get("cve") or {}
        cve_id = cve_payload.get("id") or requested_cve_id
        description = self._select_description(cve_payload.get("descriptions") or [])
        metrics = cve_payload.get("metrics") or {}
        cvss_score, severity, attack_vector, attack_complexity = self._select_cvss_metrics(metrics)

        return EnrichedVulnerabilitySchema(
            cve_id=cve_id,
            name=cve_id,
            description=description,
            cvss_score=cvss_score,
            severity=severity,
            attack_vector=attack_vector,
            attack_complexity=attack_complexity,
            published_date=cve_payload.get("published"),
        )

    def _select_description(self, descriptions: list[dict]) -> str | None:
        for entry in descriptions:
            if (entry or {}).get("lang") == "en" and entry.get("value"):
                return entry["value"]
        for entry in descriptions:
            if (entry or {}).get("value"):
                return entry["value"]
        return None

    def _select_cvss_metrics(self, metrics: dict) -> tuple[float, str, str | None, str | None]:
        metric_sets = [
            metrics.get("cvssMetricV31") or [],
            metrics.get("cvssMetricV30") or [],
            metrics.get("cvssMetricV2") or [],
        ]

        for metric_list in metric_sets:
            if not metric_list:
                continue
            metric = metric_list[0] or {}
            cvss_data = metric.get("cvssData") or {}
            score = float(cvss_data.get("baseScore") or 0.0)
            severity = (
                cvss_data.get("baseSeverity")
                or metric.get("baseSeverity")
                or "UNKNOWN"
            )
            attack_vector = cvss_data.get("attackVector")
            attack_complexity = cvss_data.get("attackComplexity")
            return score, str(severity).upper(), attack_vector, attack_complexity

        return 0.0, "UNKNOWN", None, None
