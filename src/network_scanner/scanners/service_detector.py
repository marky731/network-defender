"""Layer 3: Service Detection scanners.

Provides banner grabbing, HTTP header analysis, SSH version detection,
SSL/TLS certificate analysis, and an orchestrator that coordinates all
service-detection scanners.
"""

from __future__ import annotations

import asyncio
import logging
import re
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..core.interfaces import BaseScanner, Capability, ScanContext, ScanResult
from ..core.models import PortInfo, PortState, Protocol, SSLInfo

try:
    import requests  # type: ignore[import-untyped]

    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

try:
    import paramiko  # type: ignore[import-untyped]

    _HAS_PARAMIKO = True
except ImportError:
    _HAS_PARAMIKO = False

logger = logging.getLogger(__name__)

# ─── Banner patterns ────────────────────────────────────────────────────────

_BANNER_PATTERNS: List[Tuple[str, str, int]] = [
    # (regex, service_name, group_index_for_version)
    # Order matters: SMTP before FTP because both use "220"
    (r"SSH-([\d.]+)-(.+)", "ssh", 2),
    (r"HTTP/([\d.]+)", "http", 1),
    (r"220[- ](.+)SMTP", "smtp", 1),
    (r"220[- ](.+)", "ftp", 1),
    (r"\+PONG|-ERR|(\$\d+\r\n)?redis", "redis", 0),
]

# Well-known HTTP ports
_HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000}

# Well-known SSH ports
_SSH_PORTS = {22, 2222}

# Well-known TLS ports
_TLS_PORTS = {443, 8443}

# Common security headers to check
_SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy",
]


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _new_port_info(original: PortInfo, **overrides: Any) -> PortInfo:
    """Create a new PortInfo with selected fields overridden.

    Since PortInfo is frozen, we cannot mutate it in place.
    """
    return PortInfo(
        port=overrides.get("port", original.port),
        protocol=overrides.get("protocol", original.protocol),
        state=overrides.get("state", original.state),
        service_name=overrides.get("service_name", original.service_name),
        service_version=overrides.get("service_version", original.service_version),
        banner=overrides.get("banner", original.banner),
        tunnel=overrides.get("tunnel", original.tunnel),
    )


def _parse_banner(raw: str) -> Tuple[str, str]:
    """Return (service_name, service_version) extracted from a raw banner."""
    for pattern, svc_name, ver_group in _BANNER_PATTERNS:
        match = re.search(pattern, raw, re.IGNORECASE)
        if match:
            try:
                version = match.group(ver_group).strip() if ver_group else ""
            except (IndexError, AttributeError):
                version = ""
            return svc_name, version
    return "", ""


def _detect_mysql(raw_bytes: bytes) -> bool:
    """Heuristic check for MySQL greeting packet."""
    # MySQL protocol: first 4 bytes are packet length + sequence id,
    # followed by protocol version (0x0a for MySQL 5+).
    if len(raw_bytes) > 4 and raw_bytes[4:5] in (b"\x0a", b"\xff"):
        return True
    # Also look for "mysql" or "MariaDB" in the bytes as a fallback
    lowered = raw_bytes.lower()
    if b"mysql" in lowered or b"mariadb" in lowered:
        return True
    return False


# ─── 1. BannerGrabber ───────────────────────────────────────────────────────


class BannerGrabber(BaseScanner[List[PortInfo]]):
    """Grab service banners from open TCP ports."""

    @property
    def name(self) -> str:
        return "BannerGrabber"

    @property
    def required_capability(self) -> Capability:
        return Capability.NONE

    async def _execute(
        self, target: str, context: ScanContext, **kwargs: Any
    ) -> List[PortInfo]:
        ports: List[PortInfo] = kwargs.get("ports", [])
        if not ports:
            return []

        semaphore = asyncio.Semaphore(context.max_concurrency)
        timeout = context.timeout

        async def _grab(port_info: PortInfo) -> PortInfo:
            if port_info.state != PortState.OPEN:
                return port_info

            async with semaphore:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port_info.port),
                        timeout=timeout,
                    )
                except Exception as exc:
                    logger.debug(
                        "BannerGrabber: connect to %s:%d failed: %s",
                        target,
                        port_info.port,
                        exc,
                    )
                    return port_info

                raw_bytes = b""
                try:
                    # Send a generic probe
                    writer.write(b"\r\n")
                    await writer.drain()

                    raw_bytes = await asyncio.wait_for(
                        reader.read(1024), timeout=timeout
                    )
                except Exception as exc:
                    logger.debug(
                        "BannerGrabber: read from %s:%d failed: %s",
                        target,
                        port_info.port,
                        exc,
                    )
                finally:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

                if not raw_bytes:
                    return port_info

                # Check for MySQL binary protocol first
                if _detect_mysql(raw_bytes):
                    banner_text = raw_bytes.decode("utf-8", errors="replace").strip()
                    # Try to extract version from MySQL greeting
                    version = ""
                    try:
                        # After protocol version byte, the version string is
                        # null-terminated starting at offset 5.
                        if raw_bytes[4:5] == b"\x0a":
                            end = raw_bytes.index(b"\x00", 5)
                            version = raw_bytes[5:end].decode("utf-8", errors="replace")
                    except (ValueError, IndexError):
                        pass
                    return _new_port_info(
                        port_info,
                        service_name="mysql",
                        service_version=version,
                        banner=banner_text,
                    )

                banner_text = raw_bytes.decode("utf-8", errors="replace").strip()
                svc_name, svc_version = _parse_banner(banner_text)

                if svc_name or banner_text:
                    return _new_port_info(
                        port_info,
                        service_name=svc_name or port_info.service_name,
                        service_version=svc_version or port_info.service_version,
                        banner=banner_text or port_info.banner,
                    )

                return port_info

        tasks = [_grab(p) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        enriched: List[PortInfo] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(
                    "BannerGrabber: unexpected error for port %d: %s",
                    ports[i].port,
                    result,
                )
                enriched.append(ports[i])
            else:
                enriched.append(result)

        return enriched


# ─── 2. HTTPHeaderAnalyzer ──────────────────────────────────────────────────


class HTTPHeaderAnalyzer(BaseScanner[dict]):
    """Analyze HTTP response headers for server info and security headers."""

    @property
    def name(self) -> str:
        return "HTTPHeaderAnalyzer"

    @property
    def required_capability(self) -> Capability:
        return Capability.NONE

    async def _execute(
        self, target: str, context: ScanContext, **kwargs: Any
    ) -> dict:
        if not _HAS_REQUESTS:
            logger.warning("HTTPHeaderAnalyzer: 'requests' library not installed")
            return {}

        ports: List[PortInfo] = kwargs.get("ports", [])
        if not ports:
            return {}

        timeout = context.timeout
        results: Dict[int, dict] = {}

        for port_info in ports:
            port = port_info.port
            if port not in _HTTP_PORTS:
                continue

            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{target}:{port}/"

            try:
                # Run blocking requests.head in a thread executor
                response = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda u=url, t=timeout: requests.head(
                        u, timeout=t, verify=False, allow_redirects=True
                    ),
                )

                headers = response.headers
                header_info: Dict[str, Any] = {
                    "status_code": response.status_code,
                    "server": headers.get("Server", ""),
                    "x_powered_by": headers.get("X-Powered-By", ""),
                    "security_headers": {},
                }

                for hdr in _SECURITY_HEADERS:
                    value = headers.get(hdr, "")
                    header_info["security_headers"][hdr] = value

                results[port] = header_info

            except Exception as exc:
                logger.debug(
                    "HTTPHeaderAnalyzer: request to %s failed: %s", url, exc
                )

        return results


# ─── 3. SSHVersionDetector ──────────────────────────────────────────────────


class SSHVersionDetector(BaseScanner[dict]):
    """Detect SSH protocol/software version and optionally enumerate host keys."""

    @property
    def name(self) -> str:
        return "SSHVersionDetector"

    @property
    def required_capability(self) -> Capability:
        return Capability.NONE

    async def _execute(
        self, target: str, context: ScanContext, **kwargs: Any
    ) -> dict:
        ports: List[PortInfo] = kwargs.get("ports", [])
        if not ports:
            return {}

        timeout = context.timeout
        results: Dict[int, dict] = {}

        for port_info in ports:
            port = port_info.port
            if port not in _SSH_PORTS:
                continue

            ssh_info: Dict[str, Any] = {
                "ssh_version": "",
                "software": "",
                "key_types": [],
            }

            # Phase 1: raw banner read
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=timeout,
                )
                try:
                    banner_bytes = await asyncio.wait_for(
                        reader.readline(), timeout=timeout
                    )
                    banner = banner_bytes.decode("utf-8", errors="replace").strip()

                    # Parse SSH-<proto_version>-<software>
                    match = re.match(r"SSH-([\d.]+)-(.+)", banner)
                    if match:
                        ssh_info["ssh_version"] = match.group(1)
                        ssh_info["software"] = match.group(2)
                finally:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
            except Exception as exc:
                logger.debug(
                    "SSHVersionDetector: banner read from %s:%d failed: %s",
                    target,
                    port,
                    exc,
                )

            # Phase 2: paramiko host key enumeration (optional)
            if _HAS_PARAMIKO:
                try:
                    key_types = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda t=target, p=port, to=timeout: self._get_host_key_types(
                            t, p, to
                        ),
                    )
                    ssh_info["key_types"] = key_types
                except Exception as exc:
                    logger.debug(
                        "SSHVersionDetector: paramiko key enum for %s:%d failed: %s",
                        target,
                        port,
                        exc,
                    )

            results[port] = ssh_info

        return results

    @staticmethod
    def _get_host_key_types(host: str, port: int, timeout: float) -> List[str]:
        """Use paramiko.Transport to discover supported host key types."""
        key_types: List[str] = []
        try:
            sock = paramiko.Transport((host, port))
            sock.connect()
            remote_key = sock.get_remote_server_key()
            if remote_key:
                key_types.append(remote_key.get_name())
            sock.close()
        except Exception as exc:
            logger.debug("paramiko key detection failed: %s", exc)
        return key_types


# ─── 4. SSLAnalyzer ─────────────────────────────────────────────────────────


class SSLAnalyzer(BaseScanner[List[SSLInfo]]):
    """Analyze SSL/TLS certificates and connection parameters."""

    @property
    def name(self) -> str:
        return "SSLAnalyzer"

    @property
    def required_capability(self) -> Capability:
        return Capability.NONE

    async def _execute(
        self, target: str, context: ScanContext, **kwargs: Any
    ) -> List[SSLInfo]:
        ports: List[PortInfo] = kwargs.get("ports", [])
        if not ports:
            return []

        timeout = context.timeout
        results: List[SSLInfo] = []

        for port_info in ports:
            port = port_info.port
            # Determine whether this port is TLS-capable
            if not self._is_tls_port(port_info):
                continue

            try:
                ssl_info = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda t=target, p=port, to=timeout: self._analyze_ssl(t, p, to),
                )
                if ssl_info is not None:
                    results.append(ssl_info)
            except Exception as exc:
                logger.debug(
                    "SSLAnalyzer: analysis for %s:%d failed: %s",
                    target,
                    port,
                    exc,
                )

        return results

    @staticmethod
    def _is_tls_port(port_info: PortInfo) -> bool:
        """Decide whether the given port likely speaks TLS."""
        if port_info.port in _TLS_PORTS:
            return True
        if port_info.tunnel and "ssl" in port_info.tunnel.lower():
            return True
        svc = port_info.service_name.lower()
        if "https" in svc or "ssl" in svc:
            return True
        return False

    @staticmethod
    def _analyze_ssl(host: str, port: int, timeout: float) -> Optional[SSLInfo]:
        """Perform a blocking SSL handshake and certificate inspection."""
        import socket

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        raw_sock = socket.create_connection((host, port), timeout=timeout)
        try:
            ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
            try:
                # Certificate info (DER → parsed dict)
                der_cert = ssl_sock.getpeercert(binary_form=True)
                peer_cert = ssl_sock.getpeercert()  # may be empty when CERT_NONE

                # Connection-level info
                proto_version = ssl_sock.version() or ""
                cipher_info = ssl_sock.cipher()  # (name, proto, bits)
                cipher_suite = cipher_info[0] if cipher_info else ""
                key_bits = cipher_info[2] if cipher_info else 0

                subject_cn = ""
                issuer_cn = ""
                not_before: Optional[datetime] = None
                not_after: Optional[datetime] = None
                is_expired = False
                is_self_signed = False

                if peer_cert:
                    # Extract subject CN
                    for rdn in peer_cert.get("subject", ()):
                        for attr_type, attr_value in rdn:
                            if attr_type == "commonName":
                                subject_cn = attr_value

                    # Extract issuer CN
                    for rdn in peer_cert.get("issuer", ()):
                        for attr_type, attr_value in rdn:
                            if attr_type == "commonName":
                                issuer_cn = attr_value

                    is_self_signed = subject_cn == issuer_cn and subject_cn != ""

                    # Parse dates — format: 'Sep  9 00:00:00 2024 GMT'
                    nb_raw = peer_cert.get("notBefore", "")
                    na_raw = peer_cert.get("notAfter", "")
                    date_fmt = "%b %d %H:%M:%S %Y %Z"
                    if nb_raw:
                        try:
                            not_before = datetime.strptime(nb_raw, date_fmt)
                        except ValueError:
                            pass
                    if na_raw:
                        try:
                            not_after = datetime.strptime(na_raw, date_fmt)
                        except ValueError:
                            pass

                    if not_after is not None:
                        is_expired = not_after < datetime.utcnow()

                elif der_cert:
                    # Fallback: try to parse DER with ssl helpers
                    try:
                        parsed = ssl._ssl._test_decode_cert(None)  # type: ignore[attr-defined]
                    except Exception:
                        pass

                return SSLInfo(
                    port=port,
                    subject_cn=subject_cn,
                    issuer_cn=issuer_cn,
                    not_before=not_before,
                    not_after=not_after,
                    is_expired=is_expired,
                    is_self_signed=is_self_signed,
                    protocol_version=proto_version,
                    cipher_suite=cipher_suite,
                    key_bits=key_bits,
                )
            finally:
                ssl_sock.close()
        except Exception:
            raw_sock.close()
            raise


# ─── 5. ServiceDetectionOrchestrator ────────────────────────────────────────


class ServiceDetectionOrchestrator:
    """Coordinate all service-detection scanners and merge their results.

    This is **not** a BaseScanner subclass; it is a higher-level coordinator.
    """

    def __init__(self) -> None:
        self._banner_grabber = BannerGrabber()
        self._http_analyzer = HTTPHeaderAnalyzer()
        self._ssh_detector = SSHVersionDetector()
        self._ssl_analyzer = SSLAnalyzer()

    async def detect_services(
        self, target: str, ports: List[PortInfo], context: ScanContext
    ) -> Tuple[List[PortInfo], List[SSLInfo]]:
        """Run all service-detection scanners and return merged results.

        Returns
        -------
        tuple
            (enriched_ports, ssl_infos)
        """
        enriched_ports = list(ports)
        ssl_infos: List[SSLInfo] = []

        # ── Step 1: Banner grabbing on all open ports ────────────────────
        try:
            banner_result: ScanResult[List[PortInfo]] = await self._banner_grabber.scan(
                target, context, ports=enriched_ports
            )
            if banner_result.success and banner_result.data is not None:
                enriched_ports = banner_result.data
                logger.info(
                    "BannerGrabber completed: %d ports processed", len(enriched_ports)
                )
            else:
                logger.warning(
                    "BannerGrabber failed: %s", banner_result.error_message
                )
        except Exception as exc:
            logger.error("BannerGrabber unexpected error: %s", exc)

        # ── Step 2: HTTP header analysis on HTTP ports ───────────────────
        http_ports = [p for p in enriched_ports if p.port in _HTTP_PORTS]
        if http_ports:
            try:
                http_result: ScanResult[dict] = await self._http_analyzer.scan(
                    target, context, ports=http_ports
                )
                if http_result.success and http_result.data:
                    enriched_ports = self._merge_http_info(
                        enriched_ports, http_result.data
                    )
                    logger.info(
                        "HTTPHeaderAnalyzer completed: %d ports analysed",
                        len(http_result.data),
                    )
            except Exception as exc:
                logger.error("HTTPHeaderAnalyzer unexpected error: %s", exc)

        # ── Step 3: SSH version detection on SSH ports ───────────────────
        ssh_ports = [p for p in enriched_ports if p.port in _SSH_PORTS]
        if ssh_ports:
            try:
                ssh_result: ScanResult[dict] = await self._ssh_detector.scan(
                    target, context, ports=ssh_ports
                )
                if ssh_result.success and ssh_result.data:
                    enriched_ports = self._merge_ssh_info(
                        enriched_ports, ssh_result.data
                    )
                    logger.info(
                        "SSHVersionDetector completed: %d ports analysed",
                        len(ssh_result.data),
                    )
            except Exception as exc:
                logger.error("SSHVersionDetector unexpected error: %s", exc)

        # ── Step 4: SSL/TLS analysis on TLS-capable ports ────────────────
        tls_ports = [
            p
            for p in enriched_ports
            if SSLAnalyzer._is_tls_port(p)
        ]
        if tls_ports:
            try:
                ssl_result: ScanResult[List[SSLInfo]] = await self._ssl_analyzer.scan(
                    target, context, ports=tls_ports
                )
                if ssl_result.success and ssl_result.data is not None:
                    ssl_infos = ssl_result.data
                    logger.info(
                        "SSLAnalyzer completed: %d certs analysed", len(ssl_infos)
                    )
            except Exception as exc:
                logger.error("SSLAnalyzer unexpected error: %s", exc)

        return enriched_ports, ssl_infos

    # ── Private merge helpers ────────────────────────────────────────────

    @staticmethod
    def _merge_http_info(
        ports: List[PortInfo], http_data: Dict[int, dict]
    ) -> List[PortInfo]:
        """Enrich PortInfo entries with HTTP header data."""
        merged: List[PortInfo] = []
        for p in ports:
            info = http_data.get(p.port)
            if info and info.get("server"):
                # Use server header as service_version if not already set
                svc_name = p.service_name or "http"
                svc_version = p.service_version or info.get("server", "")
                merged.append(
                    _new_port_info(
                        p, service_name=svc_name, service_version=svc_version
                    )
                )
            else:
                merged.append(p)
        return merged

    @staticmethod
    def _merge_ssh_info(
        ports: List[PortInfo], ssh_data: Dict[int, dict]
    ) -> List[PortInfo]:
        """Enrich PortInfo entries with SSH version data."""
        merged: List[PortInfo] = []
        for p in ports:
            info = ssh_data.get(p.port)
            if info and info.get("software"):
                svc_name = p.service_name or "ssh"
                svc_version = p.service_version or info.get("software", "")
                merged.append(
                    _new_port_info(
                        p, service_name=svc_name, service_version=svc_version
                    )
                )
            else:
                merged.append(p)
        return merged
