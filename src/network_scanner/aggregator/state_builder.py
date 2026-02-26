"""State builder: assembles scanner results into observation dataclasses.

Provides static factory methods that construct immutable HostObservation
and NetworkObservation instances from the outputs of the various
scanning layers.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from ..core.models import (
    CVEInfo,
    CredentialResult,
    HostObservation,
    Misconfiguration,
    NetworkObservation,
    OSGuess,
    PortInfo,
    ScanProfile,
    SSLInfo,
)


class StateBuilder:
    """Factory for building observation dataclasses from scanner results."""

    @staticmethod
    def build_host(
        ip: str,
        is_alive: bool,
        mac: str = "",
        hostname: str = "",
        ports: Optional[List[PortInfo]] = None,
        ssl_info: Optional[List[SSLInfo]] = None,
        os_guess: Optional[OSGuess] = None,
        cves: Optional[List[CVEInfo]] = None,
        credential_results: Optional[List[CredentialResult]] = None,
        misconfigurations: Optional[List[Misconfiguration]] = None,
    ) -> HostObservation:
        """Build a HostObservation from individual scanner results.

        Converts mutable lists to tuples for compatibility with the
        frozen dataclass.

        Parameters
        ----------
        ip:
            Host IP address.
        is_alive:
            Whether the host responded to discovery probes.
        mac:
            MAC address (from ARP scan, if available).
        hostname:
            Resolved hostname (from reverse DNS, if available).
        ports:
            Port scan and service detection results.
        ssl_info:
            SSL/TLS certificate analysis results.
        os_guess:
            OS fingerprinting result.
        cves:
            CVE lookup results.
        credential_results:
            Default credential check results.
        misconfigurations:
            Misconfiguration detection results.

        Returns
        -------
        HostObservation
            Immutable observation for a single host.
        """
        return HostObservation(
            ip=ip,
            mac=mac,
            hostname=hostname,
            is_alive=is_alive,
            ports=tuple(ports or []),
            ssl_info=tuple(ssl_info or []),
            os_guess=os_guess or OSGuess(),
            cves=tuple(cves or []),
            credential_results=tuple(credential_results or []),
            misconfigurations=tuple(misconfigurations or []),
        )

    @staticmethod
    def build_network(
        target_subnet: str,
        hosts: List[HostObservation],
        profile: ScanProfile,
        scan_start: datetime,
        scan_end: datetime,
    ) -> NetworkObservation:
        """Build a NetworkObservation from host observations.

        Parameters
        ----------
        target_subnet:
            The original target string (IP or CIDR).
        hosts:
            List of HostObservation instances.
        profile:
            The scan profile that was used.
        scan_start:
            Timestamp when the scan began.
        scan_end:
            Timestamp when the scan finished.

        Returns
        -------
        NetworkObservation
            Immutable observation for the scanned network.
        """
        return NetworkObservation(
            target_subnet=target_subnet,
            hosts=tuple(hosts),
            scan_profile=profile,
            scan_start=scan_start,
            scan_end=scan_end,
        )
