"""Shared fixtures for unit tests."""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from src.network_scanner.core.models import *
from src.network_scanner.core.interfaces import ScanContext, Capability, ScanResult
from tests.mocks.fake_network import create_test_network, FakeNetwork


@pytest.fixture
def scan_context():
    """Default scan context for testing."""
    return ScanContext(
        profile=ScanProfile.QUICK,
        timeout=2.0,
        max_concurrency=10,
        tcp_ports=[22, 80, 443, 3306, 6379, 8080],
        udp_ports=[53, 161],
        has_root=False,
        has_scapy=False,
    )


@pytest.fixture
def root_context():
    """Scan context with root and scapy."""
    return ScanContext(
        profile=ScanProfile.MODERATE,
        timeout=5.0,
        max_concurrency=50,
        tcp_ports=[22, 80, 443, 3306, 6379, 8080],
        udp_ports=[53, 161],
        has_root=True,
        has_scapy=True,
    )


@pytest.fixture
def fake_network():
    """Standard test network."""
    return create_test_network()


@pytest.fixture
def sample_ports():
    """Sample PortInfo list for testing."""
    return [
        PortInfo(port=22, protocol=Protocol.TCP, state=PortState.OPEN,
                 service_name="ssh", banner="SSH-2.0-OpenSSH_8.9p1"),
        PortInfo(port=80, protocol=Protocol.TCP, state=PortState.OPEN,
                 service_name="http", banner="HTTP/1.1 200 OK\r\nServer: Apache/2.4.41"),
        PortInfo(port=443, protocol=Protocol.TCP, state=PortState.OPEN,
                 service_name="https", tunnel="ssl"),
        PortInfo(port=3306, protocol=Protocol.TCP, state=PortState.OPEN,
                 service_name="mysql"),
        PortInfo(port=6379, protocol=Protocol.TCP, state=PortState.OPEN,
                 service_name="redis"),
    ]


@pytest.fixture
def sample_host_observation(sample_ports):
    """Sample HostObservation for testing."""
    return HostObservation(
        ip="192.168.1.10",
        mac="AA:BB:CC:DD:EE:01",
        hostname="testhost",
        is_alive=True,
        ports=tuple(sample_ports),
        ssl_info=(
            SSLInfo(port=443, subject_cn="test.local", issuer_cn="test.local",
                    is_self_signed=True, is_expired=False, protocol_version="TLSv1.2",
                    cipher_suite="ECDHE-RSA-AES256-GCM-SHA384", key_bits=2048),
        ),
        os_guess=OSGuess(os_family=OSFamily.LINUX, os_detail="Ubuntu 20.04",
                         confidence=0.8, ttl=64, tcp_window_size=29200,
                         methods_used=("scapy", "banner")),
        cves=(
            CVEInfo(cve_id="CVE-2021-44228", cvss_score=10.0,
                    severity=Severity.CRITICAL, description="Log4Shell"),
        ),
        credential_results=(
            CredentialResult(service="ssh", port=22, username="admin",
                           success=True, auth_method="password"),
        ),
        misconfigurations=(
            Misconfiguration(category="ssl", service="https", port=443,
                           description="Self-signed certificate",
                           severity=Severity.MEDIUM),
        ),
    )
