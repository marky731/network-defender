"""Data models for network scanning results.

All dataclasses use frozen=True for immutability.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


# ─── Enums ───────────────────────────────────────────────────────────────────


class ScanProfile(enum.Enum):
    """Scan depth profile."""

    QUICK = "quick"
    MODERATE = "moderate"
    DEEP = "deep"


class PortState(enum.Enum):
    """Port state as determined by scanning."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"


class Protocol(enum.Enum):
    """Transport protocol."""

    TCP = "tcp"
    UDP = "udp"


class OSFamily(enum.Enum):
    """Operating system family."""

    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    BSD = "bsd"
    NETWORK_DEVICE = "network_device"
    UNKNOWN = "unknown"


class Severity(enum.Enum):
    """Vulnerability severity level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


# ─── Dataclasses ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PortInfo:
    """Information about a single port."""

    port: int
    protocol: Protocol
    state: PortState
    service_name: str = ""
    service_version: str = ""
    banner: str = ""
    tunnel: str = ""  # e.g. "ssl"


@dataclass(frozen=True)
class SSLInfo:
    """SSL/TLS certificate and connection information."""

    port: int
    subject_cn: str = ""
    issuer_cn: str = ""
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    is_expired: bool = False
    is_self_signed: bool = False
    protocol_version: str = ""
    cipher_suite: str = ""
    key_bits: int = 0


@dataclass(frozen=True)
class CVEInfo:
    """CVE vulnerability information."""

    cve_id: str
    cvss_score: float = 0.0
    severity: Severity = Severity.UNKNOWN
    description: str = ""
    exploitability_score: float = 0.0


@dataclass(frozen=True)
class CredentialResult:
    """Result of a default credential check."""

    service: str
    port: int
    username: str
    success: bool
    auth_method: str = ""


@dataclass(frozen=True)
class Misconfiguration:
    """Detected misconfiguration."""

    category: str
    service: str
    port: int
    description: str
    severity: Severity = Severity.MEDIUM


@dataclass(frozen=True)
class OSGuess:
    """Operating system fingerprinting result."""

    os_family: OSFamily = OSFamily.UNKNOWN
    os_detail: str = ""
    confidence: float = 0.0
    ttl: int = 0
    tcp_window_size: int = 0
    methods_used: tuple = ()


# ─── Container Dataclasses ───────────────────────────────────────────────────


@dataclass(frozen=True)
class HostObservation:
    """Complete observation of a single host."""

    ip: str
    mac: str = ""
    hostname: str = ""
    is_alive: bool = False
    ports: tuple = ()  # Tuple[PortInfo, ...]
    ssl_info: tuple = ()  # Tuple[SSLInfo, ...]
    os_guess: OSGuess = field(default_factory=OSGuess)
    cves: tuple = ()  # Tuple[CVEInfo, ...]
    credential_results: tuple = ()  # Tuple[CredentialResult, ...]
    misconfigurations: tuple = ()  # Tuple[Misconfiguration, ...]


@dataclass(frozen=True)
class NetworkObservation:
    """Complete observation of the scanned network."""

    target_subnet: str
    hosts: tuple = ()  # Tuple[HostObservation, ...]
    scan_profile: ScanProfile = ScanProfile.QUICK
    scan_start: Optional[datetime] = None
    scan_end: Optional[datetime] = None
