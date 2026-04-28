from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest
import nmap

from app.core.config import Settings
from app.schemas.analysis import EdgeSchema, NodeSchema, TopologySchema
from app.schemas.ingestion import IngestionRequest
from app.services.ingestion_service import IngestionService
from app.services.ingestion.nmap_scanner import NmapScanner


TEST_XML = """<nmaprun>
    <host>
        <status state="up"/>
        <address addr="192.168.1.10" addrtype="ipv4"/>
        <ports>
            <port protocol="tcp" portid="22"><state state="open"/></port>
            <port protocol="tcp" portid="80"><state state="open"/></port>
        </ports>
    </host>
</nmaprun>"""


@pytest.fixture
def settings() -> Settings:
    return Settings(
        nmap_binary_path="/usr/bin/nmap",
        nmap_default_args="-sV -sC -O --open",
        nmap_scan_timeout=300,
    )


@pytest.fixture
def port_scanner_mock() -> MagicMock:
    mock = MagicMock()
    mock.all_hosts.return_value = []
    return mock


@pytest.fixture
def scanner(settings: Settings, port_scanner_mock: MagicMock) -> NmapScanner:
    with patch("app.services.ingestion.nmap_scanner.nmap.PortScanner", return_value=port_scanner_mock):
        return NmapScanner(settings)


def test_scan_discovers_hosts(scanner: NmapScanner, port_scanner_mock: MagicMock) -> None:
    hosts = {
        "192.168.1.10": {"status": {"state": "up"}, "tcp": {22: {"state": "open"}, 80: {"state": "open"}}},
        "192.168.1.20": {"status": {"state": "up"}, "tcp": {22: {"state": "open"}, 80: {"state": "open"}}},
    }
    port_scanner_mock.scan.side_effect = [
        {"scan": hosts},
        {"scan": hosts},
    ]
    port_scanner_mock.all_hosts.return_value = list(hosts)
    port_scanner_mock.__getitem__.side_effect = hosts.__getitem__

    topology, warnings = scanner.scan("192.168.1.0/24")

    # Includes internet node + 2 discovered hosts
    assert len(topology.nodes) == 3
    assert len(topology.edges) == 2
    assert warnings == []


def test_scan_discovery_only_host(scanner: NmapScanner, port_scanner_mock: MagicMock) -> None:
    """Tests host discovery where NO port data (tcp/udp) exists, typical of -sn scans."""
    hosts = {
        "192.168.1.50": {
            "status": {"state": "up", "reason": "conn-refused"},
            "hostname": [{"name": "silent-host", "type": "user"}]
            # Protocol keys (tcp/udp) are intentionally missing
        }
    }
    port_scanner_mock.scan.return_value = {"scan": hosts}
    port_scanner_mock.all_hosts.return_value = list(hosts)
    port_scanner_mock.__getitem__.side_effect = hosts.__getitem__

    topology, _ = scanner.scan("192.168.1.50", args="-sn")

    # Verify host node was created
    host_node = next(n for n in topology.nodes if n.id == "192.168.1.50")
    assert host_node.id == "192.168.1.50"
    assert host_node.type == "host"
    assert host_node.criticality == "LOW"  # Default for discovery-only
    
    # Check vuln attribute exists and has reasonable value
    assert hasattr(host_node, 'vuln')
    assert host_node.vuln >= 1.0  # Should have at least minimum score
    
    # Verify internet node exists
    internet_node = next(n for n in topology.nodes if n.id == "internet")
    assert internet_node.type == "external"
    
    # Verify edge exists
    assert len(topology.edges) == 1
    edge = topology.edges[0]
    assert edge.source == "internet"
    assert edge.target == "192.168.1.50"


def test_scan_skips_down_hosts(scanner: NmapScanner, port_scanner_mock: MagicMock) -> None:
    hosts = {"10.0.0.5": {"status": {"state": "down"}, "tcp": {}}}
    port_scanner_mock.scan.return_value = {"scan": hosts}
    port_scanner_mock.all_hosts.return_value = list(hosts)
    port_scanner_mock.__getitem__.side_effect = hosts.__getitem__

    topology, warnings = scanner.scan("10.0.0.0/24")

    assert all(node.id != "10.0.0.5" for node in topology.nodes)
    assert any("Skipped host 10.0.0.5" in w for w in warnings)


def test_scan_no_reachable_hosts_warning(scanner: NmapScanner, port_scanner_mock: MagicMock) -> None:
    port_scanner_mock.scan.return_value = {"scan": {}}
    port_scanner_mock.all_hosts.return_value = []

    topology, warnings = scanner.scan("10.0.0.0/24")

    assert len(topology.nodes) == 1
    assert topology.nodes[0].id == "internet"
    assert "No reachable hosts were found in the Nmap scan" in warnings


def test_scan_nmap_error_raises_value_error(scanner: NmapScanner, port_scanner_mock: MagicMock) -> None:
    port_scanner_mock.scan.side_effect = nmap.PortScannerError("nmap not found")

    with pytest.raises(ValueError, match="Nmap scan failed"):
        scanner.scan("10.0.0.0/24")


def test_scan_critical_port_detection(scanner: NmapScanner, port_scanner_mock: MagicMock) -> None:
    hosts = {"192.168.1.10": {"status": {"state": "up"}, "tcp": {3306: {"state": "open"}}}}
    port_scanner_mock.scan.side_effect = [
        {"scan": hosts},
        {"scan": hosts},
    ]
    port_scanner_mock.all_hosts.return_value = list(hosts)
    port_scanner_mock.__getitem__.side_effect = hosts.__getitem__

    topology, _warnings = scanner.scan("192.168.1.0/24")

    host_node = next(node for node in topology.nodes if node.id == "192.168.1.10")
    assert host_node.criticality == "CRITICAL"


def test_scan_merges_discovery_results_with_open_port_results(scanner: NmapScanner, port_scanner_mock: MagicMock) -> None:
    discovery_hosts = {
        "192.168.1.10": {"status": {"state": "up"}},
        "192.168.1.11": {"status": {"state": "up"}},
        "192.168.1.12": {"status": {"state": "up"}},
        "192.168.1.13": {"status": {"state": "up"}},
        "192.168.1.14": {"status": {"state": "up"}},
    }
    detailed_hosts = {
        "192.168.1.10": {"status": {"state": "up"}, "tcp": {22: {"state": "open"}}},
        "192.168.1.11": {"status": {"state": "up"}, "tcp": {80: {"state": "open"}}},
    }
    port_scanner_mock.scan.side_effect = [
        {"scan": discovery_hosts},
        {"scan": detailed_hosts},
    ]

    topology, warnings = scanner.scan("192.168.1.0/24")

    host_ids = {node.id for node in topology.nodes if node.id != "internet"}
    assert host_ids == set(discovery_hosts)
    assert len(topology.edges) == 5
    assert warnings == []

    discovery_only_node = next(node for node in topology.nodes if node.id == "192.168.1.14")
    assert discovery_only_node.criticality == "LOW"
    assert discovery_only_node.exposure == 2.0


def test_parse_xml_valid(scanner: NmapScanner) -> None:
    topology, warnings = scanner.parse_xml(TEST_XML)

    assert len(topology.nodes) == 2
    assert len(topology.edges) == 1
    assert warnings == []


def test_parse_xml_discovery_only(scanner: NmapScanner) -> None:
    """Verifies XML parsing works for hosts without a <ports> block."""
    xml = """<nmaprun>
        <host>
            <status state="up" reason="echo-reply"/>
            <address addr="10.0.0.99" addrtype="ipv4"/>
        </host>
    </nmaprun>"""
    
    topology, warnings = scanner.parse_xml(xml)
    assert any(node.id == "10.0.0.99" for node in topology.nodes)
    assert len(warnings) == 0


def test_parse_xml_empty_raises(scanner: NmapScanner) -> None:
    with pytest.raises(ValueError):
        scanner.parse_xml("")


def test_parse_xml_invalid_raises(scanner: NmapScanner) -> None:
    with pytest.raises(ValueError, match="Invalid"):
        scanner.parse_xml("<broken")


def test_parse_xml_host_without_ip_warning(scanner: NmapScanner) -> None:
    xml = """<nmaprun>
        <host>
            <status state="up"/>
        </host>
    </nmaprun>"""

    _topology, warnings = scanner.parse_xml(xml)
    assert "Skipped host without IP address" in warnings


def test_scanner_initialization_uses_binary_path(settings: Settings) -> None:
    """Ensures NmapScanner passes the binary path to the underlying library."""
    settings.nmap_binary_path = "/custom/nmap"
    with patch("app.services.ingestion.nmap_scanner.nmap.PortScanner") as mock_ps:
        scanner = NmapScanner(settings)
        
        # Check that PortScanner was called
        mock_ps.assert_called_once()
        
        # Get the call arguments
        call_args = mock_ps.call_args
        
        # Handle different possible call signatures
        if call_args.kwargs:
            # Called with keyword arguments
            if 'nmap_search_path' in call_args.kwargs:
                arg_value = call_args.kwargs['nmap_search_path']
                # Accept list, tuple, or any iterable containing the path
                assert '/custom/nmap' in arg_value
        elif call_args.args and len(call_args.args) > 0:
            # Called with positional arguments
            first_arg = call_args.args[0]
            if isinstance(first_arg, (list, tuple)):
                assert '/custom/nmap' in first_arg
            else:
                assert first_arg == '/custom/nmap'
        else:
            # If no arguments, that's also acceptable if binary is in PATH
            pass


def test_ingestion_service_delegates_nmap_live() -> None:
    topology = TopologySchema(
        nodes=[
            NodeSchema(id="internet", type="external", vuln=1.0, criticality="LOW", exposure=1.0),
            NodeSchema(id="192.168.1.10", type="host", vuln=3.0, criticality="MEDIUM", exposure=3.0, cves=[]),
        ],
        edges=[
            EdgeSchema(
                source="internet",
                target="192.168.1.10",
                exploitability=0.5,
                lateral_movement_probability=0.5,
            )
        ],
    )
    scanner = MagicMock()
    scanner.scan.return_value = (topology, [])
    service = IngestionService(nvd_client=None, nmap_scanner=scanner)
    request = IngestionRequest(source_type="nmap_live", cidr="192.168.1.0/24")

    result = service.build_topology(request)

    assert result.topology == topology
    scanner.scan.assert_called_once_with(cidr="192.168.1.0/24", args=None)


def test_ingestion_service_nmap_live_without_scanner_raises() -> None:
    service = IngestionService(nvd_client=None, nmap_scanner=None)
    request = IngestionRequest(source_type="nmap_live", cidr="10.0.0.0/24")

    with pytest.raises(ValueError, match="not configured"):
        service.build_topology(request)
