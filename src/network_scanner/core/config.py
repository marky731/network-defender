"""Scan configuration, port lists, and YAML config loader."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .models import ScanProfile

# Default config directory
_CONFIG_DIR = Path(__file__).resolve().parent.parent.parent.parent / "config"

# ─── Port Lists ──────────────────────────────────────────────────────────────

# Top ports by profile
QUICK_TCP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                   993, 995, 1723, 3306, 3389, 5900, 8080]
QUICK_UDP_PORTS = [53, 67, 68, 69, 123, 135, 137, 138, 161, 445]

MODERATE_TCP_PORTS = QUICK_TCP_PORTS + [
    8, 20, 26, 37, 49, 79, 81, 82, 83, 84, 85, 88, 100, 106, 113, 119, 199,
    211, 264, 389, 465, 500, 512, 513, 514, 515, 543, 544, 548, 554, 587,
    631, 636, 646, 873, 990, 992, 1080, 1099, 1433, 1434, 1521, 1720, 1883,
    2049, 2100, 2181, 2222, 2375, 2376, 3000, 3128, 3268, 3690, 4443, 4444,
    4567, 4848, 5000, 5001, 5432, 5555, 5601, 5672, 5984, 5985, 5986, 6000,
    6379, 6443, 6667, 7001, 7002, 7199, 8000, 8008, 8009, 8081, 8088, 8181,
    8443, 8888, 9000, 9042, 9090, 9091, 9200, 9300, 9418, 9999, 10000, 11211,
    27017, 27018, 50000,
]
MODERATE_UDP_PORTS = QUICK_UDP_PORTS + [
    500, 514, 520, 623, 1194, 1434, 1604, 1900, 4500, 5353,
]

DEEP_TCP_PORTS = list(range(1, 1025)) + [
    1080, 1099, 1433, 1434, 1521, 1723, 1883, 2049, 2100, 2181, 2222, 2375,
    2376, 3000, 3128, 3268, 3306, 3389, 3690, 4443, 4444, 4567, 4848, 5000,
    5001, 5432, 5555, 5601, 5672, 5900, 5984, 5985, 5986, 6000, 6379, 6443,
    6667, 7001, 7002, 7199, 8000, 8008, 8009, 8080, 8081, 8088, 8181, 8443,
    8888, 9000, 9042, 9090, 9091, 9200, 9300, 9418, 9999, 10000, 11211,
    27017, 27018, 50000,
]
DEEP_UDP_PORTS = QUICK_UDP_PORTS + [
    500, 514, 520, 623, 1194, 1434, 1604, 1900, 4500, 5060, 5353, 11211,
    27017,
]


def get_ports_for_profile(profile: ScanProfile) -> tuple:
    """Return (tcp_ports, udp_ports) for a given scan profile."""
    if profile == ScanProfile.QUICK:
        return QUICK_TCP_PORTS, QUICK_UDP_PORTS
    elif profile == ScanProfile.MODERATE:
        return MODERATE_TCP_PORTS, MODERATE_UDP_PORTS
    else:  # DEEP
        # Deduplicate
        tcp = sorted(set(DEEP_TCP_PORTS))
        udp = sorted(set(DEEP_UDP_PORTS))
        return tcp, udp


# ─── YAML Loading ────────────────────────────────────────────────────────────


def load_yaml_config(filename: str, config_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Load a YAML config file from the config directory."""
    base = config_dir or _CONFIG_DIR
    filepath = base / filename
    if not filepath.exists():
        return {}
    with open(filepath, "r") as f:
        data = yaml.safe_load(f)
    return data if isinstance(data, dict) else {}


def load_scan_profiles(config_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Load scan profile configuration."""
    return load_yaml_config("scan_profiles.yaml", config_dir)


def load_service_patterns(config_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Load service detection regex patterns."""
    return load_yaml_config("service_patterns.yaml", config_dir)


def load_os_signatures(config_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Load OS fingerprint signatures."""
    return load_yaml_config("os_signatures.yaml", config_dir)


def load_default_credentials(config_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Load default credential lists."""
    return load_yaml_config("default_credentials.yaml", config_dir)


# ─── ScanConfig ──────────────────────────────────────────────────────────────


@dataclass
class ScanConfig:
    """Top-level scan configuration."""

    profile: ScanProfile = ScanProfile.QUICK
    timeout: float = 5.0
    max_concurrency: int = 100
    config_dir: Optional[Path] = None

    def get_tcp_ports(self) -> List[int]:
        tcp, _ = get_ports_for_profile(self.profile)
        return tcp

    def get_udp_ports(self) -> List[int]:
        _, udp = get_ports_for_profile(self.profile)
        return udp

    @classmethod
    def from_yaml(cls, config_dir: Optional[Path] = None) -> "ScanConfig":
        """Create ScanConfig from YAML profile settings."""
        profiles = load_scan_profiles(config_dir)
        defaults = profiles.get("defaults", {})
        return cls(
            profile=ScanProfile(defaults.get("profile", "quick")),
            timeout=float(defaults.get("timeout", 5.0)),
            max_concurrency=int(defaults.get("max_concurrency", 100)),
            config_dir=config_dir,
        )
