from __future__ import annotations

import logging
from dataclasses import dataclass, field

from app.core.metrics import metrics_registry
from app.schemas.analysis import NodeSchema, TopologySchema
from app.schemas.ingestion import IngestionRequest
from app.services.ingestion.cisa_kev_client import CISAKEVClient
from app.services.ingestion.nmap_scanner import NmapScanner
from app.services.ingestion.nvd_client import NvdClient
from app.services.ingestion.shodan_enricher import ShodanEnricher

logger = logging.getLogger(__name__)


@dataclass
class IngestionResult:
    topology: TopologySchema
    warnings: list[str] = field(default_factory=list)
    source_type: str = "topology"


class IngestionService:
    def __init__(
        self,
        nvd_client: NvdClient | None = None,
        nmap_scanner: NmapScanner | None = None,
        shodan_enricher: ShodanEnricher | None = None,
        cisa_kev_client: CISAKEVClient | None = None,
    ) -> None:
        self._nvd_client = nvd_client
        self._nmap_scanner = nmap_scanner
        self._shodan_enricher = shodan_enricher
        self._cisa_kev_client = cisa_kev_client or CISAKEVClient()

    def build_topology(self, request: IngestionRequest) -> IngestionResult:
        if request.source_type == "topology" and request.topology is not None:
            topology = request.topology
            warnings: list[str] = []
        elif request.source_type == "nmap_live":
            if self._nmap_scanner is None:
                raise ValueError("NmapScanner is not configured for live scanning")
            topology, warnings = self._nmap_scanner.scan(
                cidr=request.cidr or "",
                args=None,
            )
        else:
            if self._nmap_scanner:
                topology, warnings = self._nmap_scanner.parse_xml(request.nmap_xml or "")
            else:
                raise ValueError("NmapScanner is not configured for XML parsing")

        for source in request.enrichment_sources:
            topology, enrichment_warnings = self._apply_enrichment(source, topology)
            warnings.extend(enrichment_warnings)

        metrics_registry.increment("ingestion.requests")
        return IngestionResult(topology=topology, warnings=warnings, source_type=request.source_type)

    def _apply_enrichment(self, source: str, topology: TopologySchema) -> tuple[TopologySchema, list[str]]:
        if source == "nvd":
            return self._apply_nvd_enrichment(topology)

        if source == "shodan" and self._shodan_enricher and self._shodan_enricher.is_enabled():
            return self._shodan_enricher.enrich_nodes(topology)

        warnings: list[str] = []
        updated_nodes: list[NodeSchema] = []

        if source == "cisa_kev" and self._cisa_kev_client and self._cisa_kev_client.is_enabled():
            for node in topology.nodes:
                updated = node.model_copy(deep=True)
                if updated.cves:
                    vuln_payloads = [{"cve_id": cve_id} for cve_id in updated.cves]
                    enriched = self._cisa_kev_client.enrich_vulnerabilities(vuln_payloads)
                    if any(v.get("cisa_kev") for v in enriched):
                        updated.exploit_in_wild = True
                updated_nodes.append(updated)
            warnings.append("cisa_kev enrichment applied")
            return TopologySchema(nodes=updated_nodes, edges=topology.edges), warnings

        for node in topology.nodes:
            updated = node.model_copy(deep=True)
            if source == "shodan" and node.id != "internet":
                updated.exposure = min(10.0, updated.exposure + 0.5)
            elif source == "cisa_kev" and updated.cves:
                updated.exploit_in_wild = True
            elif source not in {"nvd", "cisa_kev", "shodan"}:
                warnings.append(f"Unsupported enrichment source '{source}' was ignored")
            updated_nodes.append(updated)

        if source in {"cisa_kev", "shodan"}:
            warnings.append(f"{source} enrichment ran in local fallback mode")
        return TopologySchema(nodes=updated_nodes, edges=topology.edges), warnings

    def _apply_nvd_enrichment(self, topology: TopologySchema) -> tuple[TopologySchema, list[str]]:
        if self._nvd_client is None:
            return topology, ["NVD enrichment client is not configured; local values were retained"]

        cve_ids = [cve_id for node in topology.nodes for cve_id in node.cves]
        if not cve_ids:
            return topology, []

        nvd_records, warnings = self._nvd_client.fetch_cves(cve_ids)
        updated_nodes: list[NodeSchema] = []

        for node in topology.nodes:
            updated = node.model_copy(deep=True)
            details = [
                nvd_records[normalized_cve]
                for cve_id in updated.cves
                if (normalized_cve := cve_id.strip().upper()) in nvd_records
            ]
            if details:
                updated.vulnerability_details = details
                max_cvss = max(detail.cvss_score for detail in details)
                updated.cvss_max = max(updated.cvss_max or 0.0, max_cvss)
                updated.vuln = max(updated.vuln, max_cvss)
            updated_nodes.append(updated)

        return TopologySchema(nodes=updated_nodes, edges=topology.edges), warnings
