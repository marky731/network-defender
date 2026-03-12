"""In-memory network simulation for RL environment.

Provides SimulatedNetwork and supporting dataclasses that model
a network topology with hosts, services, vulnerabilities, and
credentials. Bridges to the existing observation dataclasses via
StateBuilder.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ..aggregator.state_builder import StateBuilder
from ..core.models import (
    CVEInfo,
    CredentialResult,
    HostObservation,
    Misconfiguration,
    OSFamily,
    OSGuess,
    PortInfo,
    PortState,
    Protocol,
    Severity,
    SSLInfo,
)


@dataclass
class SimulatedService:
    """A service running on a simulated host."""

    port: int
    protocol: Protocol
    service_name: str
    service_version: str
    banner: str = ""
    has_ssl: bool = False
    ssl_self_signed: bool = False
    ssl_expired: bool = False


@dataclass
class SimulatedVulnerability:
    """A vulnerability present on a simulated host."""

    cve_id: str
    cvss_score: float
    severity: Severity
    affected_service: str
    exploitability_score: float
    requires_credential: bool = False


@dataclass
class SimulatedCredential:
    """A working credential on a simulated host."""

    service: str
    port: int
    username: str
    password: str


@dataclass
class SimulatedHost:
    """A host in the simulated network."""

    ip: str
    is_alive: bool = True
    os_family: OSFamily = OSFamily.LINUX
    os_detail: str = ""
    os_confidence: float = 0.85
    services: List[SimulatedService] = field(default_factory=list)
    vulnerabilities: List[SimulatedVulnerability] = field(default_factory=list)
    credentials: List[SimulatedCredential] = field(default_factory=list)
    misconfigurations: List[dict] = field(default_factory=list)
    reachable_hosts: Set[str] = field(default_factory=set)
    value: float = 1.0


class SimulatedNetwork:
    """In-memory network simulation.

    Parameters
    ----------
    hosts:
        List of SimulatedHost instances that make up the network.
    subnet:
        CIDR notation for the network.
    seed:
        Optional RNG seed for reproducibility.
    """

    def __init__(
        self,
        hosts: List[SimulatedHost],
        subnet: str = "192.168.1.0/24",
        seed: Optional[int] = None,
    ):
        self.subnet = subnet
        self.hosts: Dict[str, SimulatedHost] = {h.ip: h for h in hosts}
        self._rng = random.Random(seed)

    def get_host(self, ip: str) -> Optional[SimulatedHost]:
        """Return the host object for the given IP, or None."""
        return self.hosts.get(ip)

    def get_alive_hosts(self) -> List[SimulatedHost]:
        """Return all hosts that are alive."""
        return [h for h in self.hosts.values() if h.is_alive]

    def host_discover(self, ip: str) -> bool:
        """Simulate host discovery. 5% false-negative rate for alive hosts."""
        host = self.hosts.get(ip)
        if host is None or not host.is_alive:
            return False
        # 5% false-negative
        if self._rng.random() < 0.05:
            return False
        return True

    def port_scan(self, ip: str) -> List[int]:
        """Return list of open port numbers for the host."""
        host = self.hosts.get(ip)
        if host is None or not host.is_alive:
            return []
        return [s.port for s in host.services]

    def detect_service(
        self, ip: str, port: int
    ) -> Optional[Tuple[str, str, str]]:
        """Return (name, version, banner) for a service on the given port."""
        host = self.hosts.get(ip)
        if host is None:
            return None
        for svc in host.services:
            if svc.port == port:
                return (svc.service_name, svc.service_version, svc.banner)
        return None

    def fingerprint_os(
        self, ip: str
    ) -> Optional[Tuple[OSFamily, str, float]]:
        """Return (os_family, os_detail, confidence) for the host."""
        host = self.hosts.get(ip)
        if host is None or not host.is_alive:
            return None
        return (host.os_family, host.os_detail, host.os_confidence)

    def check_credentials(self, ip: str, port: int) -> List[SimulatedCredential]:
        """Return working credentials for the given host and port."""
        host = self.hosts.get(ip)
        if host is None:
            return []
        return [c for c in host.credentials if c.port == port]

    def get_vulnerabilities(self, ip: str) -> List[SimulatedVulnerability]:
        """Return all vulnerabilities for the host."""
        host = self.hosts.get(ip)
        if host is None:
            return []
        return list(host.vulnerabilities)

    def attempt_exploit(self, ip: str, cve_id: str) -> bool:
        """Attempt to exploit a vulnerability. Success probability = exploitability_score / 10."""
        host = self.hosts.get(ip)
        if host is None:
            return False
        for vuln in host.vulnerabilities:
            if vuln.cve_id == cve_id:
                return self._rng.random() < (vuln.exploitability_score / 10.0)
        return False

    def to_host_observation(
        self, ip: str, discovered: Dict
    ) -> HostObservation:
        """Bridge simulated data to a HostObservation via StateBuilder.

        Parameters
        ----------
        ip:
            Host IP address.
        discovered:
            Dict with keys like "ports", "os_guess", "cves",
            "credential_results", "misconfigurations" containing
            discovered information about the host.
        """
        ports = None
        if "ports" in discovered:
            ports = [
                PortInfo(
                    port=p["port"],
                    protocol=p.get("protocol", Protocol.TCP),
                    state=p.get("state", PortState.OPEN),
                    service_name=p.get("service_name", ""),
                    service_version=p.get("service_version", ""),
                    banner=p.get("banner", ""),
                    tunnel=p.get("tunnel", ""),
                )
                for p in discovered["ports"]
            ]

        ssl_info = None
        if "ssl_info" in discovered:
            ssl_info = [
                SSLInfo(
                    port=s["port"],
                    is_self_signed=s.get("is_self_signed", False),
                    is_expired=s.get("is_expired", False),
                )
                for s in discovered["ssl_info"]
            ]

        os_guess = None
        if "os_guess" in discovered:
            og = discovered["os_guess"]
            os_guess = OSGuess(
                os_family=og.get("os_family", OSFamily.UNKNOWN),
                os_detail=og.get("os_detail", ""),
                confidence=og.get("confidence", 0.0),
            )

        cves = None
        if "cves" in discovered:
            cves = [
                CVEInfo(
                    cve_id=c["cve_id"],
                    cvss_score=c.get("cvss_score", 0.0),
                    severity=c.get("severity", Severity.UNKNOWN),
                    description=c.get("description", ""),
                    exploitability_score=c.get("exploitability_score", 0.0),
                )
                for c in discovered["cves"]
            ]

        credential_results = None
        if "credential_results" in discovered:
            credential_results = [
                CredentialResult(
                    service=cr["service"],
                    port=cr["port"],
                    username=cr["username"],
                    success=cr.get("success", True),
                    auth_method=cr.get("auth_method", ""),
                )
                for cr in discovered["credential_results"]
            ]

        misconfigurations = None
        if "misconfigurations" in discovered:
            misconfigurations = [
                Misconfiguration(
                    category=m["category"],
                    service=m["service"],
                    port=m["port"],
                    description=m["description"],
                    severity=m.get("severity", Severity.MEDIUM),
                )
                for m in discovered["misconfigurations"]
            ]

        return StateBuilder.build_host(
            ip=ip,
            is_alive=True,
            ports=ports,
            ssl_info=ssl_info,
            os_guess=os_guess,
            cves=cves,
            credential_results=credential_results,
            misconfigurations=misconfigurations,
        )
