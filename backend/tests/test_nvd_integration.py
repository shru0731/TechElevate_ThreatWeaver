from __future__ import annotations

import httpx

from app.core.config import get_settings
from app.schemas.analysis import NodeSchema, TopologySchema
from app.services.ingestion_service import IngestionService
from app.services.ingestion.nvd_client import NvdClient
from app.services.ingestion.shodan_enricher import ShodanEnricher


def test_nvd_client_maps_cvss_v31_payload():
    client = NvdClient(get_settings())
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "published": "2024-01-02T03:04:05.000",
                    "descriptions": [
                        {"lang": "es", "value": "Descripcion"},
                        {"lang": "en", "value": "English description"},
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                    "attackVector": "NETWORK",
                                    "attackComplexity": "LOW",
                                }
                            }
                        ]
                    },
                }
            }
        ]
    }

    record = client._extract_vulnerability(payload, "CVE-2024-1234")

    assert record is not None
    assert record.cve_id == "CVE-2024-1234"
    assert record.description == "English description"
    assert record.cvss_score == 9.8
    assert record.severity == "CRITICAL"
    assert record.attack_vector == "NETWORK"
    assert record.attack_complexity == "LOW"
    assert record.published_date is not None


def test_nvd_client_handles_missing_cvss():
    client = NvdClient(get_settings())
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-9999",
                    "descriptions": [{"lang": "en", "value": "No metrics available"}],
                    "metrics": {},
                }
            }
        ]
    }

    record = client._extract_vulnerability(payload, "CVE-2024-9999")

    assert record is not None
    assert record.cvss_score == 0.0
    assert record.severity == "UNKNOWN"
    assert record.attack_vector is None


def test_nvd_client_returns_warning_for_unknown_cve(monkeypatch):
    settings = get_settings()
    settings.nvd_enabled = True
    settings.nvd_api_key = "test-key"
    client = NvdClient(settings)

    monkeypatch.setattr(client, "_fetch_single_cve", lambda cve_id: None)

    records, warnings = client.fetch_cves(["CVE-2024-4040"])

    assert records == {}
    assert warnings == ["NVD record was not found for CVE-2024-4040"]


def test_ingestion_service_enriches_nodes_with_nvd_details():
    settings = get_settings()
    settings.nvd_enabled = True
    settings.nvd_api_key = "test-key"
    client = NvdClient(settings)
    service = IngestionService(nvd_client=client)

    monkeypatch_payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-1111",
                    "descriptions": [{"lang": "en", "value": "Remote code execution"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 8.7, "baseSeverity": "HIGH", "attackVector": "NETWORK"}}
                        ]
                    },
                }
            }
        ]
    }

    service._nvd_client._fetch_single_cve = lambda cve_id: client._extract_vulnerability(monkeypatch_payload, cve_id)

    topology = TopologySchema(
        nodes=[
            NodeSchema(id="web", type="host", vuln=4.0, criticality="HIGH", cves=["CVE-2024-1111"]),
            NodeSchema(id="db", type="host", vuln=5.0, criticality="CRITICAL", cves=[]),
        ],
        edges=[],
    )

    enriched, warnings = service._apply_nvd_enrichment(topology)

    assert warnings == []
    web = next(node for node in enriched.nodes if node.id == "web")
    assert web.cvss_max == 8.7
    assert web.vuln == 8.7
    assert len(web.vulnerability_details) == 1
    assert web.vulnerability_details[0].description == "Remote code execution"
    db = next(node for node in enriched.nodes if node.id == "db")
    assert db.vulnerability_details == []


def test_ingestion_service_keeps_local_values_on_nvd_failure(monkeypatch):
    settings = get_settings()
    settings.nvd_enabled = True
    settings.nvd_api_key = "test-key"
    client = NvdClient(settings)
    service = IngestionService(nvd_client=client)

    def raise_http_error(cve_id: str):
        request = httpx.Request("GET", "https://example.test")
        raise httpx.ConnectError("boom", request=request)

    monkeypatch.setattr(client, "_fetch_single_cve", raise_http_error)

    topology = TopologySchema(
        nodes=[NodeSchema(id="web", type="host", vuln=4.0, criticality="HIGH", cves=["CVE-2024-1111"])],
        edges=[],
    )

    enriched, warnings = service._apply_nvd_enrichment(topology)

    assert enriched.nodes[0].vuln == 4.0
    assert enriched.nodes[0].cvss_max is None
    assert warnings == ["NVD lookup failed for CVE-2024-1111"]


def test_ingestion_service_applies_nvd_and_shodan_enrichment(monkeypatch):
    settings = get_settings()
    settings.nvd_enabled = True
    settings.nvd_api_key = "test-key"
    settings.shodan_enabled = True
    settings.shodan_api_key = "shodan-key"

    client = NvdClient(settings)
    shodan = ShodanEnricher(settings)
    service = IngestionService(nvd_client=client, shodan_enricher=shodan)

    nvd_payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-1111",
                    "descriptions": [{"lang": "en", "value": "Remote code execution"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 8.7, "baseSeverity": "HIGH", "attackVector": "NETWORK"}}
                        ]
                    },
                }
            }
        ]
    }

    monkeypatch.setattr(client, "_fetch_single_cve", lambda cve_id: client._extract_vulnerability(nvd_payload, cve_id))
    monkeypatch.setattr(
        "app.services.ingestion.shodan_enricher.httpx.get",
        lambda url, timeout: type(
            "Resp",
            (),
            {
                "json": staticmethod(lambda: {"ports": [22, 80, 443]}),
                "raise_for_status": staticmethod(lambda: None),
            },
        )(),
    )

    topology = TopologySchema(
        nodes=[NodeSchema(id="8.8.8.8", type="host", vuln=4.0, exposure=1.0, criticality="HIGH", cves=["CVE-2024-1111"])],
        edges=[],
    )

    enriched, warnings = service._apply_enrichment("nvd", topology)
    enriched, shodan_warnings = service._apply_enrichment("shodan", enriched)
    warnings.extend(shodan_warnings)

    assert warnings == []
    node = enriched.nodes[0]
    assert node.cvss_max == 8.7
    assert node.vuln == 8.7
    assert len(node.vulnerability_details) == 1
    assert abs(node.exposure - 1.3) < 1e-6
