"""Scenario generator for RL environment.

Provides service templates, curriculum levels, and factory functions
for creating SimulatedNetwork instances suitable for RL training.
"""

from __future__ import annotations

import random
from typing import Dict, List, Optional

from ..core.models import OSFamily, Protocol, Severity
from .sim_network import (
    SimulatedCredential,
    SimulatedHost,
    SimulatedNetwork,
    SimulatedService,
    SimulatedVulnerability,
)

# ─── Service Templates ──────────────────────────────────────────────────────

SIM_SERVICE_TEMPLATES: Dict[str, dict] = {
    "web-apache": {
        "services": [
            SimulatedService(
                port=80, protocol=Protocol.TCP,
                service_name="http", service_version="Apache/2.4.41",
                banner="HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n",
            ),
        ],
        "vulns": [
            SimulatedVulnerability(
                cve_id="CVE-2021-41773", cvss_score=7.5,
                severity=Severity.HIGH, affected_service="http",
                exploitability_score=6.5,
            ),
        ],
        "credentials": [],
        "os": OSFamily.LINUX,
        "os_detail": "Ubuntu 20.04",
        "value": 1.0,
    },
    "web-nginx": {
        "services": [
            SimulatedService(
                port=443, protocol=Protocol.TCP,
                service_name="https", service_version="nginx/1.18.0",
                banner="", has_ssl=True, ssl_self_signed=True,
            ),
        ],
        "vulns": [
            SimulatedVulnerability(
                cve_id="CVE-2021-23017", cvss_score=7.7,
                severity=Severity.HIGH, affected_service="https",
                exploitability_score=5.0,
            ),
        ],
        "credentials": [],
        "os": OSFamily.LINUX,
        "os_detail": "Alpine 3.14",
        "value": 1.0,
    },
    "ssh-server": {
        "services": [
            SimulatedService(
                port=2222, protocol=Protocol.TCP,
                service_name="ssh", service_version="OpenSSH_8.9p1",
                banner="SSH-2.0-OpenSSH_8.9p1\r\n",
            ),
        ],
        "vulns": [],
        "credentials": [
            SimulatedCredential(
                service="ssh", port=2222,
                username="admin", password="admin",
            ),
        ],
        "os": OSFamily.LINUX,
        "os_detail": "Ubuntu 22.04",
        "value": 1.5,
    },
    "ftp-server": {
        "services": [
            SimulatedService(
                port=21, protocol=Protocol.TCP,
                service_name="ftp", service_version="vsftpd 3.0.3",
                banner="220 (vsFTPd 3.0.3)\r\n",
            ),
        ],
        "vulns": [
            SimulatedVulnerability(
                cve_id="CVE-2015-3306", cvss_score=10.0,
                severity=Severity.CRITICAL, affected_service="ftp",
                exploitability_score=8.0,
            ),
        ],
        "credentials": [
            SimulatedCredential(
                service="ftp", port=21,
                username="anonymous", password="",
            ),
        ],
        "os": OSFamily.LINUX,
        "os_detail": "Debian 10",
        "value": 1.0,
    },
    "mysql-server": {
        "services": [
            SimulatedService(
                port=3306, protocol=Protocol.TCP,
                service_name="mysql", service_version="MySQL 5.7.42",
                banner="J\x00\x00\x005.7.42\x00",
            ),
        ],
        "vulns": [
            SimulatedVulnerability(
                cve_id="CVE-2020-14812", cvss_score=4.9,
                severity=Severity.MEDIUM, affected_service="mysql",
                exploitability_score=3.0,
            ),
        ],
        "credentials": [
            SimulatedCredential(
                service="mysql", port=3306,
                username="root", password="root",
            ),
        ],
        "os": OSFamily.LINUX,
        "os_detail": "Debian 10",
        "value": 3.0,
    },
    "postgres-server": {
        "services": [
            SimulatedService(
                port=5432, protocol=Protocol.TCP,
                service_name="postgresql", service_version="PostgreSQL 14.2",
                banner="",
            ),
        ],
        "vulns": [
            SimulatedVulnerability(
                cve_id="CVE-2022-1552", cvss_score=8.8,
                severity=Severity.HIGH, affected_service="postgresql",
                exploitability_score=5.5,
            ),
        ],
        "credentials": [
            SimulatedCredential(
                service="postgresql", port=5432,
                username="postgres", password="postgres",
            ),
        ],
        "os": OSFamily.LINUX,
        "os_detail": "Debian 11",
        "value": 3.0,
    },
    "redis-server": {
        "services": [
            SimulatedService(
                port=6379, protocol=Protocol.TCP,
                service_name="redis", service_version="Redis 6.2.6",
                banner="+PONG\r\n",
            ),
        ],
        "vulns": [
            SimulatedVulnerability(
                cve_id="CVE-2022-0543", cvss_score=10.0,
                severity=Severity.CRITICAL, affected_service="redis",
                exploitability_score=9.0,
            ),
        ],
        "credentials": [],
        "os": OSFamily.LINUX,
        "os_detail": "Ubuntu 20.04",
        "value": 2.0,
    },
    "mongodb-server": {
        "services": [
            SimulatedService(
                port=27017, protocol=Protocol.TCP,
                service_name="mongodb", service_version="MongoDB 4.4.6",
                banner="",
            ),
        ],
        "vulns": [
            SimulatedVulnerability(
                cve_id="CVE-2021-20334", cvss_score=6.5,
                severity=Severity.MEDIUM, affected_service="mongodb",
                exploitability_score=4.0,
            ),
        ],
        "credentials": [
            SimulatedCredential(
                service="mongodb", port=27017,
                username="admin", password="admin",
            ),
        ],
        "os": OSFamily.LINUX,
        "os_detail": "Ubuntu 20.04",
        "value": 2.5,
    },
}

TEMPLATE_NAMES = list(SIM_SERVICE_TEMPLATES.keys())

# ─── Curriculum Levels ──────────────────────────────────────────────────────

CURRICULUM_SCENARIOS: Dict[str, dict] = {
    "tiny":   {"num_hosts": 3,  "max_vulns": 2,  "max_creds": 1},
    "small":  {"num_hosts": 6,  "max_vulns": 5,  "max_creds": 3},
    "medium": {"num_hosts": 10, "max_vulns": 10, "max_creds": 5},
    "large":  {"num_hosts": 15, "max_vulns": 15, "max_creds": 8},
}


# ─── Factory Functions ──────────────────────────────────────────────────────


def create_scenario(
    level: str = "small",
    seed: Optional[int] = None,
) -> SimulatedNetwork:
    """Create a scenario from a curriculum level name.

    Parameters
    ----------
    level:
        One of "tiny", "small", "medium", "large".
    seed:
        RNG seed for reproducibility.
    """
    if level not in CURRICULUM_SCENARIOS:
        raise ValueError(
            f"Unknown level {level!r}. Choose from: {list(CURRICULUM_SCENARIOS)}"
        )
    cfg = CURRICULUM_SCENARIOS[level]
    return generate_random_scenario(
        num_hosts=cfg["num_hosts"],
        seed=seed,
    )


def generate_random_scenario(
    num_hosts: int = 6,
    seed: Optional[int] = None,
    subnet: str = "192.168.1.0/24",
) -> SimulatedNetwork:
    """Generate a random network scenario.

    Parameters
    ----------
    num_hosts:
        Number of hosts to generate.
    seed:
        RNG seed for reproducibility.
    subnet:
        CIDR notation for the network.
    """
    rng = random.Random(seed)
    hosts: List[SimulatedHost] = []

    # Pick random templates for each host
    selected_templates = rng.choices(TEMPLATE_NAMES, k=num_hosts)

    for i, template_name in enumerate(selected_templates):
        template = SIM_SERVICE_TEMPLATES[template_name]
        ip = f"192.168.1.{10 + i}"

        host = SimulatedHost(
            ip=ip,
            is_alive=True,
            os_family=template["os"],
            os_detail=template["os_detail"],
            os_confidence=round(rng.uniform(0.7, 0.95), 2),
            services=list(template["services"]),
            vulnerabilities=list(template["vulns"]),
            credentials=list(template["credentials"]),
            value=template["value"],
        )
        hosts.append(host)

    # Assign reachability — each host can reach 30-70% of others
    all_ips = [h.ip for h in hosts]
    for host in hosts:
        others = [ip for ip in all_ips if ip != host.ip]
        num_reachable = rng.randint(
            max(1, len(others) // 3),
            max(1, len(others) * 2 // 3),
        )
        host.reachable_hosts = set(rng.sample(others, min(num_reachable, len(others))))

    return SimulatedNetwork(hosts=hosts, subnet=subnet, seed=seed)


def create_demo_scenario() -> SimulatedNetwork:
    """Create a scenario mirroring the Docker Compose lab (6 hosts @ 172.30.0.0/24).

    Matches the structure in ``lab/docker-compose.yml`` for real vs
    simulated comparison.
    """
    hosts = [
        SimulatedHost(
            ip="172.30.0.10",
            os_family=OSFamily.LINUX, os_detail="Ubuntu 20.04",
            os_confidence=0.90,
            services=[SimulatedService(
                port=80, protocol=Protocol.TCP,
                service_name="http", service_version="Apache/2.4.41",
                banner="HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n",
            )],
            vulnerabilities=[SimulatedVulnerability(
                cve_id="CVE-2021-41773", cvss_score=7.5,
                severity=Severity.HIGH, affected_service="http",
                exploitability_score=6.5,
            )],
            value=1.0,
        ),
        SimulatedHost(
            ip="172.30.0.11",
            os_family=OSFamily.LINUX, os_detail="Alpine 3.14",
            os_confidence=0.85,
            services=[SimulatedService(
                port=443, protocol=Protocol.TCP,
                service_name="https", service_version="nginx/1.18.0",
                banner="", has_ssl=True, ssl_self_signed=True,
            )],
            vulnerabilities=[SimulatedVulnerability(
                cve_id="CVE-2021-23017", cvss_score=7.7,
                severity=Severity.HIGH, affected_service="https",
                exploitability_score=5.0,
            )],
            value=1.0,
        ),
        SimulatedHost(
            ip="172.30.0.12",
            os_family=OSFamily.LINUX, os_detail="Ubuntu 22.04",
            os_confidence=0.88,
            services=[SimulatedService(
                port=2222, protocol=Protocol.TCP,
                service_name="ssh", service_version="OpenSSH_8.9p1",
                banner="SSH-2.0-OpenSSH_8.9p1\r\n",
            )],
            credentials=[SimulatedCredential(
                service="ssh", port=2222,
                username="admin", password="admin",
            )],
            value=1.5,
        ),
        SimulatedHost(
            ip="172.30.0.13",
            os_family=OSFamily.LINUX, os_detail="Debian 10",
            os_confidence=0.82,
            services=[SimulatedService(
                port=21, protocol=Protocol.TCP,
                service_name="ftp", service_version="vsftpd 3.0.3",
                banner="220 (vsFTPd 3.0.3)\r\n",
            )],
            vulnerabilities=[SimulatedVulnerability(
                cve_id="CVE-2015-3306", cvss_score=10.0,
                severity=Severity.CRITICAL, affected_service="ftp",
                exploitability_score=8.0,
            )],
            credentials=[SimulatedCredential(
                service="ftp", port=21,
                username="anonymous", password="",
            )],
            value=1.0,
        ),
        SimulatedHost(
            ip="172.30.0.14",
            os_family=OSFamily.LINUX, os_detail="Debian 10",
            os_confidence=0.90,
            services=[SimulatedService(
                port=3306, protocol=Protocol.TCP,
                service_name="mysql", service_version="MySQL 5.7.42",
                banner="J\x00\x00\x005.7.42\x00",
            )],
            vulnerabilities=[SimulatedVulnerability(
                cve_id="CVE-2020-14812", cvss_score=4.9,
                severity=Severity.MEDIUM, affected_service="mysql",
                exploitability_score=3.0,
            )],
            credentials=[SimulatedCredential(
                service="mysql", port=3306,
                username="root", password="root",
            )],
            value=3.0,
        ),
        SimulatedHost(
            ip="172.30.0.15",
            os_family=OSFamily.LINUX, os_detail="Ubuntu 20.04",
            os_confidence=0.87,
            services=[SimulatedService(
                port=6379, protocol=Protocol.TCP,
                service_name="redis", service_version="Redis 6.2.6",
                banner="+PONG\r\n",
            )],
            vulnerabilities=[SimulatedVulnerability(
                cve_id="CVE-2022-0543", cvss_score=10.0,
                severity=Severity.CRITICAL, affected_service="redis",
                exploitability_score=9.0,
            )],
            value=2.0,
        ),
    ]

    # Full mesh reachability for the demo lab
    all_ips = [h.ip for h in hosts]
    for host in hosts:
        host.reachable_hosts = {ip for ip in all_ips if ip != host.ip}

    return SimulatedNetwork(
        hosts=hosts, subnet="172.30.0.0/24", seed=42,
    )
