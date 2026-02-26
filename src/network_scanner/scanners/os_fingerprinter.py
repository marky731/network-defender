"""Layer 4: OS Fingerprinting scanners.

Provides active TCP/IP stack fingerprinting via scapy, passive
banner-based OS guessing, and an orchestrator that combines both
methods.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, List, Optional

from ..core.interfaces import BaseScanner, Capability, ScanContext, ScanResult
from ..core.models import OSFamily, OSGuess, PortInfo

logger = logging.getLogger(__name__)


# ─── OS Signature Database ──────────────────────────────────────────────────

# Maps (ttl, window_size) -> (OSFamily, detail_string)
# TTL matching uses "nearest standard" logic; window is exact.
_TCP_SIGNATURES: List[tuple] = [
    # Linux signatures
    (64, 5840, OSFamily.LINUX, "Linux 2.6.x"),
    (64, 29200, OSFamily.LINUX, "Linux 3.x/4.x"),
    (64, 65535, OSFamily.LINUX, "Linux (generic)"),
    # Windows signatures
    (128, 8192, OSFamily.WINDOWS, "Windows XP/7"),
    (128, 65535, OSFamily.WINDOWS, "Windows 10/Server"),
    # macOS
    (64, 65535, OSFamily.MACOS, "macOS / OS X"),
    # BSD
    (64, 65535, OSFamily.BSD, "BSD (generic)"),
    (64, 16384, OSFamily.BSD, "BSD (OpenBSD/FreeBSD)"),
    # Network devices
    (255, None, OSFamily.NETWORK_DEVICE, "Network device (router/switch)"),
]


def _match_os_signature(ttl: int, window_size: int) -> tuple:
    """Match TTL and TCP window size against known OS signatures.

    Returns (OSFamily, detail_string, confidence).
    """
    # Determine the "canonical" TTL bucket the observed value falls into.
    if ttl <= 64:
        canonical_ttl = 64
    elif ttl <= 128:
        canonical_ttl = 128
    else:
        canonical_ttl = 255

    # Network devices have distinctive TTL of 255 regardless of window.
    if canonical_ttl == 255:
        return OSFamily.NETWORK_DEVICE, "Network device (router/switch)", 0.7

    # Try exact (ttl, window) match.
    candidates = []
    for sig_ttl, sig_win, family, detail in _TCP_SIGNATURES:
        if sig_win is None:
            continue
        if sig_ttl == canonical_ttl and sig_win == window_size:
            candidates.append((family, detail))

    if candidates:
        # Windows has unique TTL=128, so it is unambiguous.
        if canonical_ttl == 128:
            return candidates[0][0], candidates[0][1], 0.85

        # TTL=64 is shared by Linux, macOS, BSD.  If only one match, high
        # confidence; if ambiguous (e.g. window 65535), lower confidence.
        if len(candidates) == 1:
            return candidates[0][0], candidates[0][1], 0.8
        # Multiple matches -- prefer Linux as most common, lower confidence.
        return candidates[0][0], candidates[0][1], 0.5

    # TTL matched a bucket but window is unknown -- weak guess.
    if canonical_ttl == 128:
        return OSFamily.WINDOWS, "Windows (unknown version)", 0.5
    if canonical_ttl == 64:
        return OSFamily.LINUX, "Linux/Unix (unknown variant)", 0.4

    return OSFamily.UNKNOWN, "", 0.0


# ─── Scapy Active Fingerprinter ─────────────────────────────────────────────


class ScapyOSFingerprinter(BaseScanner[OSGuess]):
    """Active OS fingerprinting via TCP SYN probe analysis.

    Sends a SYN to an open port, examines TTL and window size of the
    SYN-ACK response, and matches against known OS signatures.

    Requires root privileges and scapy.
    """

    @property
    def name(self) -> str:
        return "ScapyOSFingerprinter"

    @property
    def required_capability(self) -> Capability:
        return Capability.ROOT_AND_SCAPY

    async def _execute(self, target: str, context: ScanContext, **kwargs: Any) -> OSGuess:
        try:
            from scapy.all import IP, TCP, sr1
        except ImportError:
            logger.warning("scapy is not installed; active OS fingerprinting unavailable")
            return OSGuess()

        open_port: int = kwargs.get("open_port", 80)
        loop = asyncio.get_running_loop()

        def _probe() -> OSGuess:
            pkt = IP(dst=target) / TCP(dport=open_port, flags="S")
            reply = sr1(pkt, timeout=context.timeout, verbose=0)

            if reply is None or not reply.haslayer(TCP):
                logger.debug("No SYN-ACK received from %s:%d", target, open_port)
                return OSGuess(methods_used=("scapy_syn",))

            ttl = reply.ttl
            window_size = reply[TCP].window

            os_family, os_detail, confidence = _match_os_signature(ttl, window_size)

            return OSGuess(
                os_family=os_family,
                os_detail=os_detail,
                confidence=confidence,
                ttl=ttl,
                tcp_window_size=window_size,
                methods_used=("scapy_syn",),
            )

        try:
            return await loop.run_in_executor(None, _probe)
        except Exception as exc:
            logger.error("Scapy OS fingerprint failed for %s: %s", target, exc)
            return OSGuess(methods_used=("scapy_syn",))


# ─── Banner-based OS Guesser ────────────────────────────────────────────────

# Compiled patterns for banner matching.
_BANNER_PATTERNS: List[tuple] = [
    # Linux distributions
    (re.compile(r"Ubuntu", re.IGNORECASE), OSFamily.LINUX, "Ubuntu Linux"),
    (re.compile(r"Debian", re.IGNORECASE), OSFamily.LINUX, "Debian Linux"),
    (re.compile(r"CentOS", re.IGNORECASE), OSFamily.LINUX, "CentOS Linux"),
    (re.compile(r"Red\s*Hat", re.IGNORECASE), OSFamily.LINUX, "Red Hat Linux"),
    (re.compile(r"Fedora", re.IGNORECASE), OSFamily.LINUX, "Fedora Linux"),
    # Windows
    (re.compile(r"Windows", re.IGNORECASE), OSFamily.WINDOWS, "Windows"),
    (re.compile(r"Microsoft", re.IGNORECASE), OSFamily.WINDOWS, "Microsoft Windows"),
    (re.compile(r"IIS", re.IGNORECASE), OSFamily.WINDOWS, "Windows (IIS)"),
    # macOS
    (re.compile(r"Darwin", re.IGNORECASE), OSFamily.MACOS, "macOS (Darwin)"),
    (re.compile(r"macOS", re.IGNORECASE), OSFamily.MACOS, "macOS"),
    # BSD
    (re.compile(r"FreeBSD", re.IGNORECASE), OSFamily.BSD, "FreeBSD"),
    (re.compile(r"OpenBSD", re.IGNORECASE), OSFamily.BSD, "OpenBSD"),
    (re.compile(r"NetBSD", re.IGNORECASE), OSFamily.BSD, "NetBSD"),
    # Network devices
    (re.compile(r"Cisco", re.IGNORECASE), OSFamily.NETWORK_DEVICE, "Cisco"),
    (re.compile(r"MikroTik", re.IGNORECASE), OSFamily.NETWORK_DEVICE, "MikroTik"),
    (re.compile(r"Juniper", re.IGNORECASE), OSFamily.NETWORK_DEVICE, "Juniper"),
]


class BannerOSGuesser(BaseScanner[OSGuess]):
    """Passive OS guessing based on service banners.

    Examines banner strings from discovered ports and matches
    against known OS-indicative patterns.  Lower confidence than
    active fingerprinting (0.3--0.5).

    Requires no special capabilities.
    """

    @property
    def name(self) -> str:
        return "BannerOSGuesser"

    @property
    def required_capability(self) -> Capability:
        return Capability.NONE

    async def _execute(self, target: str, context: ScanContext, **kwargs: Any) -> OSGuess:
        ports: List[PortInfo] = kwargs.get("ports", [])

        if not ports:
            return OSGuess(methods_used=("banner",))

        # Collect all banners and service names for analysis.
        texts: List[str] = []
        for port_info in ports:
            if port_info.banner:
                texts.append(port_info.banner)
            if port_info.service_name:
                texts.append(port_info.service_name)
            if port_info.service_version:
                texts.append(port_info.service_version)

        combined_text = " ".join(texts)
        if not combined_text.strip():
            return OSGuess(methods_used=("banner",))

        # Score each OS family by number of pattern matches.
        family_scores: dict = {}
        family_details: dict = {}
        for pattern, family, detail in _BANNER_PATTERNS:
            if pattern.search(combined_text):
                family_scores[family] = family_scores.get(family, 0) + 1
                if family not in family_details:
                    family_details[family] = detail

        if not family_scores:
            return OSGuess(methods_used=("banner",))

        # Pick the family with the most pattern matches.
        best_family = max(family_scores, key=family_scores.get)
        match_count = family_scores[best_family]

        # Confidence: 0.3 base, up to 0.5 with more matches.
        confidence = min(0.3 + 0.05 * match_count, 0.5)

        return OSGuess(
            os_family=best_family,
            os_detail=family_details.get(best_family, ""),
            confidence=confidence,
            methods_used=("banner",),
        )


# ─── Orchestrator ───────────────────────────────────────────────────────────


class OSFingerprintOrchestrator:
    """Combine active and passive OS fingerprinting.

    Runs both ScapyOSFingerprinter and BannerOSGuesser.  Prefers
    the active result when available (higher confidence).  Merges
    methods_used from both.
    """

    def __init__(self) -> None:
        self._scapy_fingerprinter = ScapyOSFingerprinter()
        self._banner_guesser = BannerOSGuesser()

    async def fingerprint(
        self, target: str, ports: List[PortInfo], context: ScanContext
    ) -> OSGuess:
        """Run OS fingerprinting using all available methods.

        Parameters
        ----------
        target:
            IP address or hostname to fingerprint.
        ports:
            List of discovered PortInfo objects (used for banner analysis
            and to choose an open port for the SYN probe).
        context:
            Scan runtime context.

        Returns
        -------
        OSGuess with combined results.
        """
        scapy_guess: Optional[OSGuess] = None
        banner_guess: Optional[OSGuess] = None

        # Determine an open port for active probing.
        open_port = 80
        for pi in ports:
            from ..core.models import PortState
            if pi.state == PortState.OPEN:
                open_port = pi.port
                break

        # Run both fingerprinters concurrently.
        scapy_task = None
        banner_task = asyncio.create_task(
            self._banner_guesser.scan(target, context, ports=ports)
        )

        if self._scapy_fingerprinter.is_available(context):
            scapy_task = asyncio.create_task(
                self._scapy_fingerprinter.scan(target, context, open_port=open_port)
            )

        # Collect banner result.
        banner_result: ScanResult[OSGuess] = await banner_task
        if banner_result.success and banner_result.data and banner_result.data.os_family != OSFamily.UNKNOWN:
            banner_guess = banner_result.data

        # Collect scapy result.
        if scapy_task is not None:
            scapy_result: ScanResult[OSGuess] = await scapy_task
            if scapy_result.success and scapy_result.data and scapy_result.data.os_family != OSFamily.UNKNOWN:
                scapy_guess = scapy_result.data

        # Merge methods_used from both.
        all_methods: List[str] = []
        if scapy_guess:
            all_methods.extend(scapy_guess.methods_used)
        if banner_guess:
            all_methods.extend(banner_guess.methods_used)

        # If no usable results, return empty guess with methods recorded.
        if not scapy_guess and not banner_guess:
            return OSGuess(methods_used=tuple(all_methods) if all_methods else ())

        # Prefer scapy (higher confidence) when available.
        if scapy_guess and banner_guess:
            return OSGuess(
                os_family=scapy_guess.os_family,
                os_detail=scapy_guess.os_detail,
                confidence=scapy_guess.confidence,
                ttl=scapy_guess.ttl,
                tcp_window_size=scapy_guess.tcp_window_size,
                methods_used=tuple(all_methods),
            )

        if scapy_guess:
            return OSGuess(
                os_family=scapy_guess.os_family,
                os_detail=scapy_guess.os_detail,
                confidence=scapy_guess.confidence,
                ttl=scapy_guess.ttl,
                tcp_window_size=scapy_guess.tcp_window_size,
                methods_used=tuple(all_methods),
            )

        # Only banner guess available.
        return OSGuess(
            os_family=banner_guess.os_family,
            os_detail=banner_guess.os_detail,
            confidence=banner_guess.confidence,
            methods_used=tuple(all_methods),
        )
