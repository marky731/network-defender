"""Tests for SimulatedNetwork and supporting dataclasses."""

import pytest

from network_scanner.core.models import (
    HostObservation,
    OSFamily,
    Protocol,
    Severity,
)
from network_scanner.rl.sim_network import (
    SimulatedCredential,
    SimulatedHost,
    SimulatedNetwork,
    SimulatedService,
    SimulatedVulnerability,
)


def _make_host(ip="192.168.1.10", alive=True, **kwargs):
    """Helper to create a SimulatedHost with defaults."""
    return SimulatedHost(ip=ip, is_alive=alive, **kwargs)


def _make_network(hosts=None, seed=42):
    """Helper to create a SimulatedNetwork."""
    if hosts is None:
        hosts = [
            _make_host(
                ip="192.168.1.10",
                os_family=OSFamily.LINUX,
                os_detail="Ubuntu 22.04",
                services=[
                    SimulatedService(
                        port=22,
                        protocol=Protocol.TCP,
                        service_name="ssh",
                        service_version="OpenSSH 8.9",
                        banner="SSH-2.0-OpenSSH_8.9",
                    ),
                    SimulatedService(
                        port=80,
                        protocol=Protocol.TCP,
                        service_name="http",
                        service_version="Apache 2.4",
                        banner="",
                    ),
                ],
                vulnerabilities=[
                    SimulatedVulnerability(
                        cve_id="CVE-2023-0001",
                        cvss_score=7.5,
                        severity=Severity.HIGH,
                        affected_service="ssh",
                        exploitability_score=6.0,
                    ),
                ],
                credentials=[
                    SimulatedCredential(
                        service="ssh", port=22, username="admin", password="admin"
                    ),
                ],
                misconfigurations=[
                    {
                        "category": "auth",
                        "service": "ssh",
                        "port": 22,
                        "description": "Password auth enabled",
                    }
                ],
            ),
            _make_host(ip="192.168.1.11", alive=False),
        ]
    return SimulatedNetwork(hosts=hosts, seed=seed)


class TestSimulatedNetworkCreation:
    def test_create_network_from_hosts(self):
        net = _make_network()
        assert len(net.hosts) == 2

    def test_get_host_existing(self):
        net = _make_network()
        host = net.get_host("192.168.1.10")
        assert host is not None
        assert host.ip == "192.168.1.10"

    def test_get_host_nonexistent(self):
        net = _make_network()
        assert net.get_host("10.0.0.1") is None


class TestHostDiscovery:
    def test_host_discover_alive(self):
        net = _make_network(seed=100)
        # With seed=100 the first random() should be > 0.05
        assert net.host_discover("192.168.1.10") is True

    def test_host_discover_dead(self):
        net = _make_network()
        assert net.host_discover("192.168.1.11") is False


class TestPortScan:
    def test_port_scan_returns_open_ports(self):
        net = _make_network()
        ports = net.port_scan("192.168.1.10")
        assert sorted(ports) == [22, 80]

    def test_port_scan_dead_host(self):
        net = _make_network()
        assert net.port_scan("192.168.1.11") == []


class TestServiceDetection:
    def test_detect_service_known_port(self):
        net = _make_network()
        result = net.detect_service("192.168.1.10", 22)
        assert result is not None
        name, version, banner = result
        assert name == "ssh"
        assert version == "OpenSSH 8.9"
        assert banner == "SSH-2.0-OpenSSH_8.9"

    def test_detect_service_unknown_port(self):
        net = _make_network()
        assert net.detect_service("192.168.1.10", 9999) is None


class TestOSFingerprint:
    def test_fingerprint_os(self):
        net = _make_network()
        result = net.fingerprint_os("192.168.1.10")
        assert result is not None
        family, detail, confidence = result
        assert family == OSFamily.LINUX
        assert detail == "Ubuntu 22.04"
        assert confidence == 0.85


class TestCredentials:
    def test_check_credentials(self):
        net = _make_network()
        creds = net.check_credentials("192.168.1.10", 22)
        assert len(creds) == 1
        assert creds[0].username == "admin"


class TestVulnerabilities:
    def test_get_vulnerabilities(self):
        net = _make_network()
        vulns = net.get_vulnerabilities("192.168.1.10")
        assert len(vulns) == 1
        assert vulns[0].cve_id == "CVE-2023-0001"


class TestExploit:
    def test_attempt_exploit_success(self):
        """With seed=42, verify exploit attempt is deterministic."""
        net = _make_network(seed=42)
        # exploitability_score=6.0, so threshold=0.6
        # With seed=42, random.Random(42).random() = 0.6394..., so first attempt fails
        # Try a seed that gives success
        net2 = SimulatedNetwork(
            hosts=[
                _make_host(
                    vulnerabilities=[
                        SimulatedVulnerability(
                            cve_id="CVE-2023-0001",
                            cvss_score=9.0,
                            severity=Severity.CRITICAL,
                            affected_service="ssh",
                            exploitability_score=9.5,  # 95% success rate
                        ),
                    ],
                )
            ],
            seed=42,
        )
        assert net2.attempt_exploit("192.168.1.10", "CVE-2023-0001") is True

    def test_attempt_exploit_unknown_cve(self):
        net = _make_network()
        assert net.attempt_exploit("192.168.1.10", "CVE-9999-9999") is False


class TestSeedReproducibility:
    def test_seed_reproducibility(self):
        net1 = _make_network(seed=123)
        net2 = _make_network(seed=123)
        results1 = [net1.host_discover("192.168.1.10") for _ in range(20)]
        results2 = [net2.host_discover("192.168.1.10") for _ in range(20)]
        assert results1 == results2


class TestToHostObservation:
    def test_to_host_observation(self):
        net = _make_network()
        discovered = {
            "ports": [
                {
                    "port": 22,
                    "protocol": Protocol.TCP,
                    "service_name": "ssh",
                    "service_version": "OpenSSH 8.9",
                    "banner": "SSH-2.0-OpenSSH_8.9",
                },
            ],
            "os_guess": {
                "os_family": OSFamily.LINUX,
                "os_detail": "Ubuntu 22.04",
                "confidence": 0.85,
            },
            "cves": [
                {
                    "cve_id": "CVE-2023-0001",
                    "cvss_score": 7.5,
                    "severity": Severity.HIGH,
                    "exploitability_score": 6.0,
                },
            ],
            "credential_results": [
                {
                    "service": "ssh",
                    "port": 22,
                    "username": "admin",
                    "success": True,
                },
            ],
            "misconfigurations": [
                {
                    "category": "auth",
                    "service": "ssh",
                    "port": 22,
                    "description": "Password auth enabled",
                },
            ],
        }
        obs = net.to_host_observation("192.168.1.10", discovered)
        assert isinstance(obs, HostObservation)
        assert obs.ip == "192.168.1.10"
        assert obs.is_alive is True
        assert len(obs.ports) == 1
        assert obs.ports[0].port == 22
        assert obs.os_guess.os_family == OSFamily.LINUX
        assert len(obs.cves) == 1
        assert obs.cves[0].cve_id == "CVE-2023-0001"
        assert len(obs.credential_results) == 1
        assert len(obs.misconfigurations) == 1
