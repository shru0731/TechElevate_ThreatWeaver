from __future__ import annotations

import logging
import xml.etree.ElementTree as ET

import nmap

from app.core.config import Settings
from app.schemas.analysis import EdgeSchema, NodeSchema, TopologySchema


logger = logging.getLogger(__name__)


class NmapScanner:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._binary_path = settings.nmap_binary_path
        self._default_args = settings.nmap_default_args
        self._nm = nmap.PortScanner(nmap_search_path=(self._binary_path,))
        logger.debug("NmapScanner initialized with binary path %s", self._binary_path)

    def scan(self, cidr: str, args: str | None = None) -> tuple[TopologySchema, list[str]]:
        args = args or self._default_args
        warnings: list[str] = []

        discovery_hosts = self._run_scan(cidr, "-sn")
        discovered_ips = sorted(
            ip for ip, host_data in discovery_hosts.items() if host_data.get("status", {}).get("state") == "up"
        )
        warnings.extend(
            f"Skipped host {ip}: could not parse"
            for ip, host_data in sorted(discovery_hosts.items())
            if host_data.get("status", {}).get("state") != "up"
        )

        nodes = [
            NodeSchema(
                id="internet",
                type="external",
                vuln=1.0,
                criticality="LOW",
                exposure=1.0,
                cves=[],
            )
        ]
        edges: list[EdgeSchema] = []

        if not discovered_ips:
            warnings.append("No reachable hosts were found in the Nmap scan")
            logger.info(
                "Nmap scan completed",
                extra={"node_count": len(nodes), "edge_count": len(edges)},
            )
            return TopologySchema(nodes=nodes, edges=edges), warnings

        detail_hosts = discovery_hosts
        if args.strip() != "-sn":
            try:
                detail_hosts = self._run_scan(" ".join(discovered_ips), args)
            except ValueError as exc:
                logger.warning("Falling back to discovery-only results after detailed scan failure: %s", exc)
                warnings.append(f"Detailed Nmap scan failed; using discovery-only results: {exc}")

        for ip in discovered_ips:
            parsed = self._parse_host(ip, detail_hosts.get(ip) or discovery_hosts.get(ip, {}))
            if parsed is None:
                warnings.append(f"Skipped host {ip}: could not parse")
                continue

            node, edge = parsed
            nodes.append(node)
            edges.append(edge)

        logger.info(
            "Nmap scan completed",
            extra={"node_count": len(nodes), "edge_count": len(edges)},
        )
        return TopologySchema(nodes=nodes, edges=edges), warnings

    def _run_scan(self, hosts: str, arguments: str) -> dict[str, dict]:
        try:
            result = self._nm.scan(hosts=hosts, arguments=arguments)
        except nmap.PortScannerError as exc:
            logger.exception("Nmap scan failed")
            raise ValueError(f"Nmap scan failed: {exc}") from exc
        except Exception as exc:
            logger.exception("Unexpected error during Nmap scan")
            raise ValueError(f"Unexpected error during Nmap scan: {exc}") from exc

        if isinstance(result, dict):
            scan_data = result.get("scan", {})
            if isinstance(scan_data, dict):
                return {
                    str(ip): host_data
                    for ip, host_data in scan_data.items()
                    if isinstance(host_data, dict)
                }

        return {
            ip: self._nm[ip]
            for ip in self._nm.all_hosts()
        }

    def _parse_host(self, ip: str, host_data: dict) -> tuple[NodeSchema, EdgeSchema] | None:
        # ✅ Accept host if it's UP (works for both -sn and -sV)
        if host_data.get("status", {}).get("state") != "up":
            return None

        # Hostname resolution (safe fallback)
        hostnames = host_data.get("hostnames", [])
        if hostnames and isinstance(hostnames[0], dict):
            _hostname = hostnames[0].get("name") or ip
        elif hostnames:
            _hostname = str(hostnames[0]) or ip
        else:
            _hostname = ip

        # ✅ Collect open ports (if any)
        open_ports: list[int] = []
        for protocol in ("tcp", "udp"):
            for port, port_data in host_data.get(protocol, {}).items():
                if port_data.get("state") == "open":
                    open_ports.append(int(port))

        port_count = len(open_ports)
        is_discovery_only = port_count == 0

        # ✅ NEW: handle discovery-only hosts properly
        if is_discovery_only:
            criticality = "LOW"
            vuln = 2.0          # slightly above baseline so node is visible
            exposure = 2.0
            exploitability = 0.2
        else:
            criticality = (
                "CRITICAL" if any(port in {3306, 5432} for port in open_ports)
                else "HIGH" if port_count >= 3
                else "MEDIUM"
            )
            vuln = min(10.0, max(1.0, port_count * 1.5))
            exposure = min(10.0, 1.0 + port_count)
            exploitability = min(1.0, 0.3 + (port_count * 0.1))

        # ✅ Debug log (very useful)
        logger.debug(
            "Parsed host %s | state=up | ports=%s | discovery_only=%s",
            ip,
            open_ports,
            is_discovery_only,
        )

        return (
            NodeSchema(
                id=ip,
                type="host",
                vuln=vuln,
                criticality=criticality,
                exposure=exposure,
                cves=[],
                # Optional: include metadata if schema supports it
                # metadata={"discovered": True, "ports_found": port_count > 0}
            ),
            EdgeSchema(
                source="internet",
                target=ip,
                exploitability=exploitability,
                lateral_movement_probability=0.5,
            ),
        )

    def parse_xml(self, nmap_xml: str) -> tuple[TopologySchema, list[str]]:
        if not nmap_xml.strip():
            raise ValueError("Nmap XML payload is empty")

        warnings: list[str] = []
        try:
            root = ET.fromstring(nmap_xml)
        except ET.ParseError as exc:
            raise ValueError("Invalid Nmap XML payload") from exc

        nodes: list[NodeSchema] = [
            NodeSchema(
                id="internet",
                type="external",
                vuln=1.0,
                criticality="LOW",
                exposure=1.0,
                cves=[],
            )
        ]
        edges: list[EdgeSchema] = []

        for host in root.findall(".//host"):
            status = host.find("status")
            if status is not None and status.attrib.get("state") != "up":
                continue

            address = host.find("address")
            host_id = address.attrib.get("addr") if address is not None else None
            if not host_id:
                warnings.append("Skipped host without IP address")
                continue

            open_ports: list[int] = []
            for port in host.findall("ports/port"):
                state = port.find("state")
                if state is not None and state.attrib.get("state") == "open":
                    port_id = port.attrib.get("portid")
                    try:
                        open_ports.append(int(port_id))
                    except (TypeError, ValueError):
                        continue

            port_count = len(open_ports)
            is_discovery_only = port_count == 0

            # ✅ Same fix applied here
            if is_discovery_only:
                criticality = "LOW"
                vuln = 2.0
                exposure = 2.0
            else:
                criticality = (
                    "CRITICAL" if any(port in {3306, 5432} for port in open_ports)
                    else "HIGH" if port_count >= 3
                    else "MEDIUM"
                )
                vuln = min(10.0, max(1.0, port_count * 1.5))
                exposure = min(10.0, 1.0 + port_count)

            nodes.append(
                NodeSchema(
                    id=host_id,
                    type="host",
                    vuln=vuln,
                    criticality=criticality,
                    exposure=exposure,
                    cves=[],
                )
            )
            edges.append(
                EdgeSchema(
                    source="internet",
                    target=host_id,
                    exploitability=min(1.0, 0.3 + (port_count * 0.1)),
                    lateral_movement_probability=0.5,
                )
            )

        if len(nodes) == 1:
            warnings.append("No reachable hosts were found in the Nmap scan")

        logger.info(
            "Parsed Nmap XML into topology",
            extra={"node_count": len(nodes), "edge_count": len(edges)},
        )
        return TopologySchema(nodes=nodes, edges=edges), warnings
