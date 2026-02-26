"""Layer 5: Vulnerability Assessment scanners.

Provides CVE lookup, default credential checking, misconfiguration
detection, and an orchestrator that coordinates all three.
"""

from __future__ import annotations

import asyncio
import ftplib
import logging
from typing import Any, Dict, List, Optional, Tuple

from ..core.interfaces import BaseScanner, Capability, ScanContext, ScanResult
from ..core.models import (
    CVEInfo,
    CredentialResult,
    Misconfiguration,
    PortInfo,
    PortState,
    Severity,
    SSLInfo,
)

logger = logging.getLogger(__name__)


# ─── CVE Lookup ─────────────────────────────────────────────────────────────


def _cvss_to_severity(score: float) -> Severity:
    """Map a CVSS 3.x score to a Severity enum value."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.UNKNOWN


class CVELookupScanner(BaseScanner[List[CVEInfo]]):
    """Query the NVD API for known CVEs affecting discovered services.

    For each port that has both a service_name and service_version, uses
    nvdlib to search for matching CVEs.  Respects the NVD public API
    rate limit by sleeping 6 seconds between queries.

    Requires no special system capabilities.
    """

    @property
    def name(self) -> str:
        return "CVELookupScanner"

    @property
    def required_capability(self) -> Capability:
        return Capability.NONE

    async def _execute(
        self, target: str, context: ScanContext, **kwargs: Any
    ) -> List[CVEInfo]:
        try:
            import nvdlib
        except ImportError:
            logger.warning("nvdlib is not installed; CVE lookup unavailable")
            return []

        ports: List[PortInfo] = kwargs.get("ports", [])
        results: List[CVEInfo] = []
        loop = asyncio.get_running_loop()

        first_query = True
        for port_info in ports:
            if not port_info.service_name or not port_info.service_version:
                continue

            # NVD rate limit: 6 seconds between requests.
            if not first_query:
                await asyncio.sleep(6)
            first_query = False

            keyword = f"{port_info.service_name} {port_info.service_version}"
            logger.debug("Querying NVD for: %s", keyword)

            try:
                cves = await loop.run_in_executor(
                    None, lambda kw=keyword: nvdlib.searchCVE(keywordSearch=kw)
                )
            except Exception as exc:
                logger.error("NVD query failed for '%s': %s", keyword, exc)
                continue

            for cve in cves:
                try:
                    cve_id = cve.id if hasattr(cve, "id") else str(cve)
                    cvss_score = 0.0
                    exploitability = 0.0

                    # nvdlib v2 exposes score via .score; older via v31score, etc.
                    if hasattr(cve, "score"):
                        try:
                            score_data = cve.score
                            if isinstance(score_data, (list, tuple)) and len(score_data) >= 2:
                                cvss_score = float(score_data[1])
                            elif isinstance(score_data, (int, float)):
                                cvss_score = float(score_data)
                        except (TypeError, ValueError, IndexError):
                            pass

                    if hasattr(cve, "v31exploitability"):
                        try:
                            exploitability = float(cve.v31exploitability)
                        except (TypeError, ValueError):
                            pass

                    description = ""
                    if hasattr(cve, "descriptions"):
                        for desc in cve.descriptions:
                            if hasattr(desc, "lang") and desc.lang == "en":
                                description = desc.value if hasattr(desc, "value") else str(desc)
                                break
                        if not description and cve.descriptions:
                            first_desc = cve.descriptions[0]
                            description = first_desc.value if hasattr(first_desc, "value") else str(first_desc)

                    results.append(
                        CVEInfo(
                            cve_id=cve_id,
                            cvss_score=cvss_score,
                            severity=_cvss_to_severity(cvss_score),
                            description=description[:500],
                            exploitability_score=exploitability,
                        )
                    )
                except Exception as exc:
                    logger.error("Failed to parse CVE entry: %s", exc)
                    continue

        return results


# ─── Default Credential Checker ─────────────────────────────────────────────

# Default credentials to try per service.
_SSH_CREDENTIALS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("root", "root"),
    ("root", "toor"),
    ("admin", "password"),
]

_FTP_CREDENTIALS: List[Tuple[str, str]] = [
    ("anonymous", "anonymous"),
    ("admin", "admin"),
    ("ftp", "ftp"),
]


class DefaultCredentialChecker(BaseScanner[List[CredentialResult]]):
    """Check for default/weak credentials on discovered services.

    Currently supports SSH (via paramiko) and FTP (via ftplib).
    Each connection attempt uses a short timeout (3 seconds).

    Requires no special system capabilities.
    """

    TIMEOUT = 3

    @property
    def name(self) -> str:
        return "DefaultCredentialChecker"

    @property
    def required_capability(self) -> Capability:
        return Capability.NONE

    async def _execute(
        self, target: str, context: ScanContext, **kwargs: Any
    ) -> List[CredentialResult]:
        ports: List[PortInfo] = kwargs.get("ports", [])
        results: List[CredentialResult] = []
        loop = asyncio.get_running_loop()

        for port_info in ports:
            service = port_info.service_name.lower() if port_info.service_name else ""
            port = port_info.port

            if service == "ssh" or port == 22:
                ssh_results = await self._check_ssh(target, port, loop)
                results.extend(ssh_results)
            elif service == "ftp" or port == 21:
                ftp_results = await self._check_ftp(target, port, loop)
                results.extend(ftp_results)

        return results

    async def _check_ssh(
        self, target: str, port: int, loop: asyncio.AbstractEventLoop
    ) -> List[CredentialResult]:
        """Try default SSH credentials using paramiko."""
        try:
            import paramiko
        except ImportError:
            logger.warning("paramiko is not installed; SSH credential check unavailable")
            return []

        results: List[CredentialResult] = []

        for username, password in _SSH_CREDENTIALS:

            def _try_ssh(user: str = username, pwd: str = password) -> bool:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    client.connect(
                        target,
                        port=port,
                        username=user,
                        password=pwd,
                        timeout=self.TIMEOUT,
                        look_for_keys=False,
                        allow_agent=False,
                    )
                    return True
                except Exception:
                    return False
                finally:
                    client.close()

            try:
                success = await asyncio.wait_for(
                    loop.run_in_executor(None, _try_ssh),
                    timeout=self.TIMEOUT + 2,
                )
            except (asyncio.TimeoutError, Exception):
                success = False

            results.append(
                CredentialResult(
                    service="ssh",
                    port=port,
                    username=username,
                    success=success,
                    auth_method="password",
                )
            )

        return results

    async def _check_ftp(
        self, target: str, port: int, loop: asyncio.AbstractEventLoop
    ) -> List[CredentialResult]:
        """Try default FTP credentials using ftplib."""
        results: List[CredentialResult] = []

        for username, password in _FTP_CREDENTIALS:

            def _try_ftp(user: str = username, pwd: str = password) -> bool:
                try:
                    ftp = ftplib.FTP(timeout=self.TIMEOUT)
                    ftp.connect(target, port, timeout=self.TIMEOUT)
                    ftp.login(user, pwd)
                    ftp.quit()
                    return True
                except Exception:
                    return False

            try:
                success = await asyncio.wait_for(
                    loop.run_in_executor(None, _try_ftp),
                    timeout=self.TIMEOUT + 2,
                )
            except (asyncio.TimeoutError, Exception):
                success = False

            results.append(
                CredentialResult(
                    service="ftp",
                    port=port,
                    username=username,
                    success=success,
                    auth_method="password",
                )
            )

        return results


# ─── Misconfiguration Checker ───────────────────────────────────────────────

# Ports considered dangerous when exposed without auth.
_UNENCRYPTED_SERVICES: Dict[int, str] = {
    23: "telnet",
    21: "ftp",
    80: "http",
    110: "pop3",
    143: "imap",
}

_DATABASE_PORTS: Dict[int, str] = {
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
}


class MisconfigurationChecker(BaseScanner[List[Misconfiguration]]):
    """Check for common security misconfigurations.

    Analyzes port data, SSL/TLS info, and credential test results
    to detect configuration weaknesses.

    Requires no special system capabilities.
    """

    @property
    def name(self) -> str:
        return "MisconfigurationChecker"

    @property
    def required_capability(self) -> Capability:
        return Capability.NONE

    async def _execute(
        self, target: str, context: ScanContext, **kwargs: Any
    ) -> List[Misconfiguration]:
        ports: List[PortInfo] = kwargs.get("ports", [])
        ssl_info: List[SSLInfo] = kwargs.get("ssl_info", [])
        credential_results: List[CredentialResult] = kwargs.get("credential_results", [])

        misconfigs: List[Misconfiguration] = []

        # -- Port-based checks --
        for port_info in ports:
            if port_info.state != PortState.OPEN:
                continue

            # Telnet exposed
            if port_info.port == 23:
                misconfigs.append(
                    Misconfiguration(
                        category="exposed_service",
                        service="telnet",
                        port=23,
                        description="Telnet service is exposed. Telnet transmits data "
                        "including credentials in cleartext.",
                        severity=Severity.HIGH,
                    )
                )

            # Unencrypted services (except telnet, handled above)
            if port_info.port in _UNENCRYPTED_SERVICES and port_info.port != 23:
                svc_name = _UNENCRYPTED_SERVICES[port_info.port]
                # Only flag if there is no SSL tunnel on this port.
                if not port_info.tunnel:
                    misconfigs.append(
                        Misconfiguration(
                            category="unencrypted_service",
                            service=svc_name,
                            port=port_info.port,
                            description=f"{svc_name} on port {port_info.port} is running "
                            f"without encryption.",
                            severity=Severity.MEDIUM,
                        )
                    )

            # Redis without auth
            if port_info.port == 6379:
                misconfigs.append(
                    Misconfiguration(
                        category="exposed_service",
                        service="redis",
                        port=6379,
                        description="Redis is exposed on port 6379, potentially without "
                        "authentication. This may allow unauthorized access.",
                        severity=Severity.HIGH,
                    )
                )

            # Open database ports
            if port_info.port in _DATABASE_PORTS:
                db_name = _DATABASE_PORTS[port_info.port]
                misconfigs.append(
                    Misconfiguration(
                        category="exposed_database",
                        service=db_name,
                        port=port_info.port,
                        description=f"{db_name} database is exposed on port {port_info.port}. "
                        f"Ensure authentication is properly configured.",
                        severity=Severity.HIGH,
                    )
                )

        # -- SSL/TLS checks --
        for info in ssl_info:
            if info.is_expired:
                misconfigs.append(
                    Misconfiguration(
                        category="ssl_certificate",
                        service="ssl/tls",
                        port=info.port,
                        description=f"SSL certificate on port {info.port} has expired.",
                        severity=Severity.HIGH,
                    )
                )

            if info.is_self_signed:
                misconfigs.append(
                    Misconfiguration(
                        category="ssl_certificate",
                        service="ssl/tls",
                        port=info.port,
                        description=f"SSL certificate on port {info.port} is self-signed.",
                        severity=Severity.MEDIUM,
                    )
                )

            # Weak protocols
            proto = info.protocol_version.lower() if info.protocol_version else ""
            if proto in ("sslv3", "ssl3", "ssl 3.0"):
                misconfigs.append(
                    Misconfiguration(
                        category="weak_protocol",
                        service="ssl/tls",
                        port=info.port,
                        description=f"SSLv3 is enabled on port {info.port}. "
                        f"SSLv3 is vulnerable to the POODLE attack.",
                        severity=Severity.HIGH,
                    )
                )
            elif proto in ("tlsv1", "tls1", "tls 1.0", "tlsv1.0"):
                misconfigs.append(
                    Misconfiguration(
                        category="weak_protocol",
                        service="ssl/tls",
                        port=info.port,
                        description=f"TLS 1.0 is enabled on port {info.port}. "
                        f"TLS 1.0 is deprecated and has known vulnerabilities.",
                        severity=Severity.MEDIUM,
                    )
                )

        # -- Credential result checks --
        for cred in credential_results:
            if cred.success:
                misconfigs.append(
                    Misconfiguration(
                        category="default_credentials",
                        service=cred.service,
                        port=cred.port,
                        description=f"Default credential login succeeded for {cred.service} "
                        f"on port {cred.port} with username '{cred.username}'.",
                        severity=Severity.CRITICAL,
                    )
                )

        return misconfigs


# ─── Orchestrator ───────────────────────────────────────────────────────────


class VulnAssessmentOrchestrator:
    """Coordinate vulnerability assessment across all checkers.

    Flow:
    1. DefaultCredentialChecker (parallel per service)
    2. CVELookupScanner (sequential, rate limited)
    3. MisconfigurationChecker (uses results from steps 1 and 2)

    Returns a tuple of (cves, credentials, misconfigs).
    """

    def __init__(self) -> None:
        self._cve_scanner = CVELookupScanner()
        self._credential_checker = DefaultCredentialChecker()
        self._misconfig_checker = MisconfigurationChecker()

    async def assess(
        self,
        target: str,
        ports: List[PortInfo],
        ssl_info: List[SSLInfo],
        context: ScanContext,
    ) -> tuple:
        """Run full vulnerability assessment.

        Parameters
        ----------
        target:
            IP address or hostname to assess.
        ports:
            List of discovered PortInfo objects.
        ssl_info:
            List of SSL/TLS information from discovered services.
        context:
            Scan runtime context.

        Returns
        -------
        Tuple of (cves: List[CVEInfo], credentials: List[CredentialResult],
                  misconfigs: List[Misconfiguration]).
        """
        credentials: List[CredentialResult] = []
        cves: List[CVEInfo] = []
        misconfigs: List[Misconfiguration] = []

        # Step 1: Default credential check (parallel per service).
        cred_result: ScanResult[List[CredentialResult]] = (
            await self._credential_checker.scan(target, context, ports=ports)
        )
        if cred_result.success and cred_result.data:
            credentials = cred_result.data

        # Step 2: CVE lookup (sequential, rate limited internally).
        cve_result: ScanResult[List[CVEInfo]] = await self._cve_scanner.scan(
            target, context, ports=ports
        )
        if cve_result.success and cve_result.data:
            cves = cve_result.data

        # Step 3: Misconfiguration check (uses all prior results).
        misconfig_result: ScanResult[List[Misconfiguration]] = (
            await self._misconfig_checker.scan(
                target,
                context,
                ports=ports,
                ssl_info=ssl_info,
                credential_results=credentials,
            )
        )
        if misconfig_result.success and misconfig_result.data:
            misconfigs = misconfig_result.data

        return (cves, credentials, misconfigs)
