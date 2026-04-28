import pytest
import httpx
from app.services.ingestion.shodan_enricher import ShodanEnricher
from app.schemas.analysis import TopologySchema, NodeSchema
from app.core.config import Settings

class MockResponse:
    def __init__(self, json_data, status_code=200):
        self._json = json_data
        self.status_code = status_code
    def json(self):
        return self._json
    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPError(f"Status {self.status_code}")

# Test enabled enrichment

def test_shodan_enricher_enabled(monkeypatch):
    settings = Settings(shodan_enabled=True, shodan_api_key="dummy")
    enricher = ShodanEnricher(settings)

    node = NodeSchema(id="8.8.8.8", type="host", vuln=1.0, exposure=1.0)
    topology = TopologySchema(nodes=[node], edges=[])

    def mock_get(url, timeout):
        return MockResponse({"ports": [53, 80]})

    monkeypatch.setattr("httpx.get", mock_get)

    new_topology, warnings = enricher.enrich_nodes(topology)
    updated_node = new_topology.nodes[0]

    assert len(warnings) == 0
    assert abs(updated_node.exposure - 1.2) < 1e-6

# Test disabled enrichment

def test_shodan_enricher_disabled():
    settings = Settings(shodan_enabled=False, shodan_api_key="dummy")
    enricher = ShodanEnricher(settings)
    node = NodeSchema(id="8.8.8.8", type="host", vuln=1.0, exposure=1.0)
    topology = TopologySchema(nodes=[node], edges=[])
    new_topo, warnings = enricher.enrich_nodes(topology)
    assert len(warnings) == 1
    assert "Shodan enrichment disabled" in warnings[0]
    assert new_topo.nodes[0].exposure == 1.0

# Test HTTP error handling

def test_shodan_enricher_http_error(monkeypatch):
    settings = Settings(shodan_enabled=True, shodan_api_key="dummy")
    enricher = ShodanEnricher(settings)
    node = NodeSchema(id="8.8.8.8", type="host", vuln=1.0, exposure=1.0)
    topology = TopologySchema(nodes=[node], edges=[])

    def mock_get(url, timeout):
        raise httpx.HTTPError("Network error")

    monkeypatch.setattr("httpx.get", mock_get)

    new_topology, warnings = enricher.enrich_nodes(topology)
    assert len(warnings) == 1
    assert "Failed to enrich node 8.8.8.8" in warnings[0]
    assert new_topology.nodes[0].exposure == 1.0
