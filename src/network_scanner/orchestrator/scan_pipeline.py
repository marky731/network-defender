"""Master scan pipeline: L1 -> L2 -> L3 -> L4 -> L5 -> aggregate.

Orchestrates the full scanning lifecycle for one or more targets,
running each layer in sequence per host and aggregating the results
into a single NetworkObservation.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import List

from ..core.config import ScanConfig
from ..core.interfaces import ScanContext
from ..core.logging_setup import get_logger
from ..core.models import (
    HostObservation,
    NetworkObservation,
    PortInfo,
    PortState,
    SSLInfo,
)
from ..core.utils import expand_cidr, is_valid_cidr
from ..scanners.host_discovery import HostDiscoveryOrchestrator
from ..scanners.port_scanner import PortScanOrchestrator
from ..scanners.service_detector import ServiceDetectionOrchestrator
from ..scanners.os_fingerprinter import OSFingerprintOrchestrator
from ..scanners.vuln_assessor import VulnAssessmentOrchestrator
from ..aggregator.state_builder import StateBuilder
from .capability import detect_capabilities

# Maximum number of hosts scanned concurrently.
_MAX_HOST_CONCURRENCY = 10


class ScanPipeline:
    """End-to-end scan pipeline.

    Parameters
    ----------
    config:
        Top-level scan configuration (profile, timeout, concurrency).
    """

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.logger = get_logger("network_scanner.pipeline")

    # ── Public API ───────────────────────────────────────────────────────

    async def run(self, target: str) -> NetworkObservation:
        """Run the full scan pipeline on a target (IP or CIDR).

        Parameters
        ----------
        target:
            A single IP address (e.g. ``"192.168.1.1"``) or a CIDR
            block (e.g. ``"192.168.1.0/24"``).

        Returns
        -------
        NetworkObservation
            Aggregated observation containing all discovered hosts.
        """
        scan_start = datetime.now(timezone.utc)
        self.logger.info("Pipeline started for target=%s, profile=%s",
                         target, self.config.profile.value)

        # ── Step 0: Detect runtime capabilities ──────────────────────────
        caps = detect_capabilities()
        self.logger.info("Capabilities: has_root=%s, has_scapy=%s",
                         caps["has_root"], caps["has_scapy"])

        # ── Step 1: Build ScanContext ────────────────────────────────────
        context = ScanContext(
            profile=self.config.profile,
            timeout=self.config.timeout,
            max_concurrency=self.config.max_concurrency,
            tcp_ports=self.config.get_tcp_ports(),
            udp_ports=self.config.get_udp_ports(),
            has_root=caps["has_root"],
            has_scapy=caps["has_scapy"],
        )

        # ── Step 2: Expand target to IP list ─────────────────────────────
        if is_valid_cidr(target) and "/" in target:
            ip_list = expand_cidr(target)
            self.logger.info("Expanded CIDR %s to %d hosts", target, len(ip_list))
        else:
            ip_list = [target]

        # ── Layer 1: Host Discovery ──────────────────────────────────────
        self.logger.info("Layer 1 - Host Discovery: starting (%d targets)", len(ip_list))
        host_discovery = HostDiscoveryOrchestrator()

        discovery_tasks = [
            host_discovery.scan(ip, context)
            for ip in ip_list
        ]
        discovery_results = await asyncio.gather(*discovery_tasks, return_exceptions=True)

        alive_hosts: List[dict] = []
        for ip, result in zip(ip_list, discovery_results):
            if isinstance(result, Exception):
                self.logger.error("Host discovery failed for %s: %s", ip, result)
                continue
            if result.success and result.data and result.data.get("is_alive"):
                alive_hosts.append({
                    "ip": ip,
                    "mac": result.data.get("mac", ""),
                    "method": result.data.get("method_used", ""),
                })

        self.logger.info("Layer 1 - Host Discovery: complete. %d/%d hosts alive",
                         len(alive_hosts), len(ip_list))

        # ── Layers 2-5: Per-host scanning (concurrency limited) ──────────
        semaphore = asyncio.Semaphore(_MAX_HOST_CONCURRENCY)
        host_observations: List[HostObservation] = []

        async def _scan_host(host_info: dict) -> HostObservation:
            async with semaphore:
                return await self._scan_single_host(host_info, context)

        if alive_hosts:
            self.logger.info("Scanning %d alive hosts (layers 2-5)", len(alive_hosts))
            tasks = [_scan_host(h) for h in alive_hosts]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for host_info, result in zip(alive_hosts, results):
                if isinstance(result, Exception):
                    self.logger.error("Scan failed for %s: %s",
                                      host_info["ip"], result)
                    # Build a minimal observation for the failed host.
                    host_observations.append(
                        StateBuilder.build_host(
                            ip=host_info["ip"],
                            is_alive=True,
                            mac=host_info.get("mac", ""),
                        )
                    )
                else:
                    host_observations.append(result)

        # Add non-alive hosts as well (is_alive=False).
        alive_ips = {h["ip"] for h in alive_hosts}
        for ip in ip_list:
            if ip not in alive_ips:
                host_observations.append(
                    StateBuilder.build_host(ip=ip, is_alive=False)
                )

        # ── Aggregate ────────────────────────────────────────────────────
        scan_end = datetime.now(timezone.utc)
        observation = StateBuilder.build_network(
            target_subnet=target,
            hosts=host_observations,
            profile=self.config.profile,
            scan_start=scan_start,
            scan_end=scan_end,
        )

        self.logger.info("Pipeline complete. Duration=%.2fs, hosts=%d",
                         (scan_end - scan_start).total_seconds(),
                         len(observation.hosts))

        return observation

    # ── Private helpers ──────────────────────────────────────────────────

    async def _scan_single_host(
        self, host_info: dict, context: ScanContext
    ) -> HostObservation:
        """Run layers 2-5 on a single alive host and aggregate results."""
        ip = host_info["ip"]
        mac = host_info.get("mac", "")

        # ── Layer 2: Port Scan ───────────────────────────────────────────
        self.logger.info("Layer 2 - Port Scan: starting for %s", ip)
        port_scanner = PortScanOrchestrator()
        port_result = await port_scanner.scan(ip, context)

        ports: List[PortInfo] = []
        if port_result.success and port_result.data is not None:
            ports = port_result.data
        else:
            self.logger.warning("Port scan failed for %s: %s",
                                ip, port_result.error_message)
        self.logger.info("Layer 2 - Port Scan: complete for %s (%d ports found)", ip, len(ports))

        # Filter to open ports for subsequent layers.
        open_ports = [p for p in ports if p.state == PortState.OPEN]

        # ── Layer 3: Service Detection ───────────────────────────────────
        self.logger.info("Layer 3 - Service Detection: starting for %s", ip)
        service_detector = ServiceDetectionOrchestrator()
        enriched_ports: List[PortInfo] = ports
        ssl_infos: List[SSLInfo] = []

        if open_ports:
            enriched_ports, ssl_infos = await service_detector.detect_services(
                ip, open_ports, context
            )
            # Merge enriched open ports back with the closed/filtered ones.
            enriched_set = {p.port for p in enriched_ports}
            for p in ports:
                if p.port not in enriched_set:
                    enriched_ports.append(p)
        self.logger.info("Layer 3 - Service Detection: complete for %s", ip)

        # ── Layer 4: OS Fingerprint ──────────────────────────────────────
        self.logger.info("Layer 4 - OS Fingerprint: starting for %s", ip)
        os_fingerprinter = OSFingerprintOrchestrator()
        os_guess = await os_fingerprinter.fingerprint(ip, enriched_ports, context)
        self.logger.info("Layer 4 - OS Fingerprint: complete for %s (family=%s)",
                         ip, os_guess.os_family.value)

        # ── Layer 5: Vulnerability Assessment ────────────────────────────
        self.logger.info("Layer 5 - Vuln Assessment: starting for %s", ip)
        vuln_assessor = VulnAssessmentOrchestrator()
        cves, creds, misconfigs = await vuln_assessor.assess(
            ip, enriched_ports, ssl_infos, context
        )
        self.logger.info("Layer 5 - Vuln Assessment: complete for %s "
                         "(cves=%d, creds=%d, misconfigs=%d)",
                         ip, len(cves), len(creds), len(misconfigs))

        # ── Aggregate into HostObservation ───────────────────────────────
        return StateBuilder.build_host(
            ip=ip,
            is_alive=True,
            mac=mac,
            ports=enriched_ports,
            ssl_info=ssl_infos,
            os_guess=os_guess,
            cves=cves,
            credential_results=creds,
            misconfigurations=misconfigs,
        )
