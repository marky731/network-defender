"""Tests for core data models."""
import pytest
from src.network_scanner.core.models import *


class TestEnums:
    def test_scan_profile_values(self):
        assert ScanProfile.QUICK.value == "quick"
        assert ScanProfile.MODERATE.value == "moderate"
        assert ScanProfile.DEEP.value == "deep"

    def test_port_state_values(self):
        assert PortState.OPEN.value == "open"
        assert PortState.CLOSED.value == "closed"
        assert PortState.FILTERED.value == "filtered"
        assert PortState.OPEN_FILTERED.value == "open|filtered"

    def test_os_family_values(self):
        families = [OSFamily.LINUX, OSFamily.WINDOWS, OSFamily.MACOS,
                    OSFamily.BSD, OSFamily.NETWORK_DEVICE, OSFamily.UNKNOWN]
        assert len(families) == 6

    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"


class TestPortInfo:
    def test_creation(self):
        p = PortInfo(port=80, protocol=Protocol.TCP, state=PortState.OPEN)
        assert p.port == 80
        assert p.protocol == Protocol.TCP
        assert p.state == PortState.OPEN
        assert p.service_name == ""

    def test_immutability(self):
        p = PortInfo(port=80, protocol=Protocol.TCP, state=PortState.OPEN)
        with pytest.raises(AttributeError):
            p.port = 443

    def test_with_service(self):
        p = PortInfo(port=22, protocol=Protocol.TCP, state=PortState.OPEN,
                     service_name="ssh", service_version="OpenSSH_8.9",
                     banner="SSH-2.0-OpenSSH_8.9p1")
        assert p.service_name == "ssh"
        assert p.service_version == "OpenSSH_8.9"


class TestSSLInfo:
    def test_creation(self):
        s = SSLInfo(port=443, subject_cn="example.com", is_expired=False)
        assert s.port == 443
        assert s.subject_cn == "example.com"
        assert s.is_self_signed == False


class TestCVEInfo:
    def test_creation(self):
        c = CVEInfo(cve_id="CVE-2021-44228", cvss_score=10.0,
                    severity=Severity.CRITICAL)
        assert c.cvss_score == 10.0
        assert c.severity == Severity.CRITICAL


class TestHostObservation:
    def test_creation_minimal(self):
        h = HostObservation(ip="192.168.1.1")
        assert h.ip == "192.168.1.1"
        assert h.is_alive == False
        assert h.ports == ()
        assert h.cves == ()

    def test_creation_full(self, sample_host_observation):
        h = sample_host_observation
        assert h.is_alive == True
        assert len(h.ports) == 5
        assert len(h.cves) == 1
        assert h.os_guess.os_family == OSFamily.LINUX

    def test_immutability(self):
        h = HostObservation(ip="192.168.1.1")
        with pytest.raises(AttributeError):
            h.ip = "10.0.0.1"


class TestNetworkObservation:
    def test_creation(self):
        n = NetworkObservation(target_subnet="192.168.1.0/24")
        assert n.target_subnet == "192.168.1.0/24"
        assert n.hosts == ()
        assert n.scan_profile == ScanProfile.QUICK
