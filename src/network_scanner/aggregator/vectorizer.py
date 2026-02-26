"""Observation vectorizer: converts NetworkObservation to numpy arrays.

Produces a fixed-size (256, 47) float32 matrix suitable for use as
an observation in a Gymnasium/RL environment.  Each row represents
one host, and each column is a normalised feature.
"""

from __future__ import annotations

import numpy as np

from ..core.models import (
    HostObservation,
    NetworkObservation,
    OSFamily,
    PortState,
)

# ─── Feature Constants ──────────────────────────────────────────────────────

# 28 tracked ports for the port-open bitmap (indices 1-28).
TRACKED_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 443, 445,
    993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
    9200, 27017, 27018,
]

# Database ports for the ``has_database`` feature.
DATABASE_PORTS = {3306, 5432, 27017, 27018, 1433, 9042, 6379}

# SMB ports for the ``has_smb`` feature.
SMB_PORTS = {139, 445}

# Web ports for the ``has_web_service`` feature.
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000}


class ObservationVectorizer:
    """Convert a NetworkObservation into a fixed-size numpy array.

    The output shape is ``(MAX_HOSTS, FEATURES_PER_HOST)`` = ``(256, 47)``.

    Feature layout per host row
    ---------------------------
    ========  =====================================================
    Index     Description
    ========  =====================================================
    0         is_alive (1.0 / 0.0)
    1-28      port_open bitmap for 28 tracked ports
    29-34     os_family one-hot (linux, windows, macos, bsd,
              network_device, unknown)
    35        os_confidence (0.0-1.0)
    36        open_port_count / 1024 (normalised, capped at 1.0)
    37        max_cvss_score / 10.0
    38        vuln_count / 50.0 (capped at 1.0)
    39        has_default_creds (any successful credential result)
    40        misconfig_count / 10.0 (capped at 1.0)
    41        has_ssl_issues (expired or self-signed cert)
    42        has_web_service (open port in WEB_PORTS)
    43        has_ssh (port 22 or 2222 open)
    44        has_database (open port in DATABASE_PORTS)
    45        has_smb (open port in SMB_PORTS)
    46        has_snmp (port 161 open)
    ========  =====================================================
    """

    MAX_HOSTS: int = 256
    FEATURES_PER_HOST: int = 47

    def vectorize(self, observation: NetworkObservation) -> np.ndarray:
        """Convert *observation* to a ``(256, 47)`` float32 numpy array.

        Hosts beyond :pyattr:`MAX_HOSTS` are silently truncated.
        Unused rows remain zero-filled.
        """
        result = np.zeros(
            (self.MAX_HOSTS, self.FEATURES_PER_HOST), dtype=np.float32
        )

        for i, host in enumerate(observation.hosts[: self.MAX_HOSTS]):
            result[i] = self._vectorize_host(host)

        return result

    # ── Private ──────────────────────────────────────────────────────────

    def _vectorize_host(self, host: HostObservation) -> np.ndarray:
        """Produce the 47-element feature vector for a single host."""
        vec = np.zeros(self.FEATURES_PER_HOST, dtype=np.float32)

        # Index 0: is_alive
        vec[0] = 1.0 if host.is_alive else 0.0

        # Collect open ports once.
        open_ports = {p.port for p in host.ports if p.state == PortState.OPEN}

        # Index 1-28: port_open bitmap (28 tracked ports)
        for j, tracked_port in enumerate(TRACKED_PORTS):
            vec[1 + j] = 1.0 if tracked_port in open_ports else 0.0

        # Index 29-34: os_family one-hot (6 categories)
        os_families = [
            OSFamily.LINUX,
            OSFamily.WINDOWS,
            OSFamily.MACOS,
            OSFamily.BSD,
            OSFamily.NETWORK_DEVICE,
            OSFamily.UNKNOWN,
        ]
        for j, fam in enumerate(os_families):
            vec[29 + j] = 1.0 if host.os_guess.os_family == fam else 0.0

        # Index 35: os_confidence
        vec[35] = host.os_guess.confidence

        # Index 36: open_port_count normalised (/ 1024, capped at 1.0)
        vec[36] = min(len(open_ports) / 1024.0, 1.0)

        # Index 37: max_cvss_score / 10.0
        if host.cves:
            vec[37] = max(c.cvss_score for c in host.cves) / 10.0

        # Index 38: vuln_count / 50.0 (capped at 1.0)
        vec[38] = min(len(host.cves) / 50.0, 1.0)

        # Index 39: has_default_creds
        vec[39] = 1.0 if any(cr.success for cr in host.credential_results) else 0.0

        # Index 40: misconfig_count / 10.0 (capped at 1.0)
        vec[40] = min(len(host.misconfigurations) / 10.0, 1.0)

        # Index 41: has_ssl_issues
        vec[41] = (
            1.0
            if any(s.is_expired or s.is_self_signed for s in host.ssl_info)
            else 0.0
        )

        # Index 42: has_web_service
        vec[42] = 1.0 if open_ports & WEB_PORTS else 0.0

        # Index 43: has_ssh
        vec[43] = 1.0 if 22 in open_ports or 2222 in open_ports else 0.0

        # Index 44: has_database
        vec[44] = 1.0 if open_ports & DATABASE_PORTS else 0.0

        # Index 45: has_smb
        vec[45] = 1.0 if open_ports & SMB_PORTS else 0.0

        # Index 46: has_snmp
        vec[46] = 1.0 if 161 in open_ports else 0.0

        return vec

    @staticmethod
    def get_observation_space() -> dict:
        """Return a Gymnasium-compatible Box space descriptor.

        This returns a plain dictionary rather than an actual
        ``gymnasium.spaces.Box`` to avoid a hard dependency on
        gymnasium at import time.

        Returns
        -------
        dict
            ``{"low": 0.0, "high": 1.0, "shape": (256, 47), "dtype": "float32"}``
        """
        return {
            "low": 0.0,
            "high": 1.0,
            "shape": (256, 47),
            "dtype": "float32",
        }
