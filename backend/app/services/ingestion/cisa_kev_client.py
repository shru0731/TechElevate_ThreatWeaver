from __future__ import annotations

import logging
from typing import Any

import httpx

from app.core.config import get_settings
from app.core.resilience import retry_operation

logger = logging.getLogger(__name__)


class CISAKEVClient:
    """Client for CISA Known Exploited Vulnerabilities (KEV) catalog."""

    def __init__(self, settings: Any = None) -> None:
        self._settings = settings or get_settings()
        self._kev_set: set[str] = set()  # In-memory cache of KEV CVE IDs

    async def refresh(self) -> None:
        """Download and cache the full CISA KEV catalog asynchronously."""
        if not self._settings.cisa_kev_enabled:
            logger.info("CISA KEV enrichment is disabled")
            return

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await retry_operation(
                    lambda: client.get(self._settings.cisa_kev_url),
                    retries=self._settings.external_max_retries,
                    delay_seconds=0.1,
                    retryable_exceptions=(httpx.HTTPError,),
                )
                response.raise_for_status()
                data = response.json()
                self._kev_set = {v["cveID"] for v in data.get("vulnerabilities", [])}
                logger.info(f"Cached {len(self._kev_set)} KEV CVEs")
        except Exception as exc:
            logger.error(f"Failed to refresh CISA KEV catalog: {exc}")
            raise

    def is_kev(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog."""
        return cve_id.upper() in self._kev_set

    def enrich_vulnerabilities(self, vulnerabilities: list[dict]) -> list[dict]:
        """Add 'cisa_kev' and 'exploit_in_wild' flags to vulnerability dicts."""
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id", "").upper()
            vuln["cisa_kev"] = self.is_kev(cve_id)
            if vuln["cisa_kev"]:
                vuln["exploit_in_wild"] = True
        return vulnerabilities

    def is_enabled(self) -> bool:
        """Return whether CISA KEV enrichment is currently enabled."""
        return bool(self._settings.cisa_kev_enabled)
