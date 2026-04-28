"""Real Shodan enrichment client.

This module implements :class:`ShodanEnricher` which requests information
from the Shodan API and enriches nodes in a topology.

The client is dependency‑injected via ``app.api.dependencies`` and
used by :class:`IngestionService` to replace the previous stub.
"""

from __future__ import annotations

import re
import typing as _t

import httpx

from app.core.config import get_settings
from app.core.resilience import retry_operation
from app.schemas.analysis import TopologySchema, NodeSchema


_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


class ShodanEnricher:
    """Enrich nodes via the real Shodan API.

    The enrichment applies to nodes whose :pyattr:`NodeSchema.id` matches an
    IPv4 address.  For each such node we query the Shodan host endpoint and
    increase the :pyattr:`NodeSchema.exposure` based on the number of
    open ports reported.  The method returns a new :class:`TopologySchema`
    instance and a list of warnings for nodes that could not be enriched.
    """

    def __init__(self, settings: _t.Optional[object] = None):
        self._settings = settings or get_settings()
        self._api_key = self._settings.shodan_api_key
        self._base_url = getattr(self._settings, "shodan_base_url", "https://api.shodan.io")

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------
    def is_enabled(self) -> bool:
        return bool(self._settings.shodan_enabled) and bool(self._api_key)

    def enrich_nodes(
        self, topology: TopologySchema
    ) -> tuple[TopologySchema, list[str]]:
        """Enrich nodes with Shodan data.

        Returns a tuple of an updated topology and a list of warnings.
        """
        if not self.is_enabled():
            return topology, ["Shodan enrichment disabled"]

        updated_nodes: list[NodeSchema] = []
        warnings: list[str] = []

        for node in topology.nodes:
            # The Shodan API operates on raw IP addresses.
            if not _IPV4.match(node.id):
                # Skip nodes that are not IPs – keep original.
                updated_nodes.append(node)
                continue

            def _fetch_ip(ip: str) -> dict:
                url = f"{self._base_url}/shodan/host/{ip}?key={self._api_key}"
                response = httpx.get(url, timeout=self._settings.external_request_timeout_seconds)
                response.raise_for_status()
                return response.json()

            try:
                data = retry_operation(
                    lambda: _fetch_ip(node.id),
                    retries=self._settings.external_max_retries,
                    delay_seconds=1.0,
                )
            except Exception as exc:  # pragma: no cover – network errors
                warnings.append(f"Failed to enrich node {node.id}: {exc}")
                updated_nodes.append(node)
                continue

            ports = data.get("ports", [])
            if not isinstance(ports, list):
                ports = []
            # Simple rule: exposure += min(0.5, 0.1 * len(ports))
            added_exposure = min(0.5, 0.1 * len(ports))
            new_exposure = min(10.0, node.exposure + added_exposure)
            updated = node.model_copy(deep=True)
            updated.exposure = new_exposure
            updated_nodes.append(updated)

        return TopologySchema(nodes=updated_nodes, edges=topology.edges), warnings
