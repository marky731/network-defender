"""Layer 1: Host Discovery scanners.

Provides ICMP ping, ARP scan, TCP ping, and an orchestrator that
falls back through available methods.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional

from ..core.interfaces import BaseScanner, Capability, ScanContext, ScanResult

logger = logging.getLogger(__name__)


# ─── ICMP Ping ──────────────────────────────────────────────────────────────


class ICMPPingScanner(BaseScanner[bool]):
    """Send an ICMP Echo Request and check for a reply.

    Requires root privileges and scapy.  Returns True if the host
    responds, False otherwise.
    """

    @property
    def name(self) -> str:
        return "ICMPPingScanner"

    @property
    def required_capability(self) -> Capability:
        return Capability.ROOT_AND_SCAPY

    async def _execute(self, target: str, context: ScanContext, **kwargs: Any) -> bool:
        try:
            from scapy.all import ICMP, IP, sr1
        except ImportError:
            logger.warning("scapy is not installed; ICMP ping unavailable")
            return False

        loop = asyncio.get_running_loop()

        def _ping() -> bool:
            pkt = IP(dst=target) / ICMP()
            reply = sr1(pkt, timeout=context.timeout, verbose=0)
            return reply is not None

        return await loop.run_in_executor(None, _ping)


# ─── ARP Scan ───────────────────────────────────────────────────────────────


class ARPScanScanner(BaseScanner[Dict[str, str]]):
    """ARP scan for a host on the local LAN segment.

    Requires root privileges and scapy.  Returns a dict with keys
    ``ip`` and ``mac`` when the host responds, or an empty dict
    if no reply is received.
    """

    @property
    def name(self) -> str:
        return "ARPScanScanner"

    @property
    def required_capability(self) -> Capability:
        return Capability.ROOT_AND_SCAPY

    async def _execute(
        self, target: str, context: ScanContext, **kwargs: Any
    ) -> Dict[str, str]:
        try:
            from scapy.all import ARP, Ether, srp
        except ImportError:
            logger.warning("scapy is not installed; ARP scan unavailable")
            return {}

        loop = asyncio.get_running_loop()

        def _arp() -> Dict[str, str]:
            # Build an Ethernet broadcast frame with an ARP who-has query.
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
            answered, _ = srp(pkt, timeout=context.timeout, verbose=0)
            if answered:
                # answered is a list of (sent, received) pairs
                for _, rcv in answered:
                    return {"ip": rcv.psrc, "mac": rcv.hwsrc}
            return {}

        return await loop.run_in_executor(None, _arp)


# ─── TCP Ping ───────────────────────────────────────────────────────────────


class TCPPingScanner(BaseScanner[bool]):
    """Determine host liveness via TCP connect to common ports.

    Does NOT require root or scapy.  Tries ports 80 and 443 by
    default.  Returns True if any connection succeeds.
    """

    DEFAULT_PORTS = (21, 22, 23, 80, 443, 445, 2222, 3306, 3389, 5432, 6379, 8080)

    @property
    def name(self) -> str:
        return "TCPPingScanner"

    @property
    def required_capability(self) -> Capability:
        return Capability.NONE

    async def _execute(self, target: str, context: ScanContext, **kwargs: Any) -> bool:
        ports = kwargs.get("ports", self.DEFAULT_PORTS)

        async def _try_connect(port: int) -> bool:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=context.timeout,
                )
                writer.close()
                await writer.wait_closed()
                return True
            except (OSError, asyncio.TimeoutError):
                return False

        # Fire connection attempts in parallel; succeed on first True.
        tasks = [asyncio.create_task(_try_connect(p)) for p in ports]
        try:
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    # Cancel remaining tasks before returning.
                    for t in tasks:
                        t.cancel()
                    return True
            return False
        except Exception:
            for t in tasks:
                t.cancel()
            return False


# ─── Orchestrator ────────────────────────────────────────────────────────────


class HostDiscoveryOrchestrator(BaseScanner[Dict[str, Any]]):
    """Orchestrate host discovery using ARP > ICMP > TCP fallback.

    Tries the most informative method first (ARP gives us a MAC
    address) and falls back through less-privileged methods.

    Returns a dict::

        {
            "is_alive": bool,
            "mac": str,           # empty string when unknown
            "method_used": str,   # scanner name or "" if all failed
        }
    """

    def __init__(self) -> None:
        self._arp_scanner = ARPScanScanner()
        self._icmp_scanner = ICMPPingScanner()
        self._tcp_scanner = TCPPingScanner()

    @property
    def name(self) -> str:
        return "HostDiscoveryOrchestrator"

    @property
    def required_capability(self) -> Capability:
        # The orchestrator itself has no hard requirement; it will
        # pick whichever child scanner is available.
        return Capability.NONE

    async def _execute(
        self, target: str, context: ScanContext, **kwargs: Any
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "is_alive": False,
            "mac": "",
            "method_used": "",
        }

        # 1) ARP scan (best on LAN -- gives MAC address)
        if self._arp_scanner.is_available(context):
            arp_result: ScanResult[Dict[str, str]] = await self._arp_scanner.scan(
                target, context, **kwargs
            )
            if arp_result.success and arp_result.data:
                result["is_alive"] = True
                result["mac"] = arp_result.data.get("mac", "")
                result["method_used"] = self._arp_scanner.name
                return result

        # 2) ICMP ping
        if self._icmp_scanner.is_available(context):
            icmp_result: ScanResult[bool] = await self._icmp_scanner.scan(
                target, context, **kwargs
            )
            if icmp_result.success and icmp_result.data:
                result["is_alive"] = True
                result["method_used"] = self._icmp_scanner.name
                return result

        # 3) TCP ping (no special privileges needed)
        if self._tcp_scanner.is_available(context):
            tcp_result: ScanResult[bool] = await self._tcp_scanner.scan(
                target, context, **kwargs
            )
            if tcp_result.success and tcp_result.data:
                result["is_alive"] = True
                result["method_used"] = self._tcp_scanner.name
                return result

        # All methods exhausted or unavailable.
        return result
