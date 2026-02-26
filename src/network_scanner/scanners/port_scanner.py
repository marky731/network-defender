"""Layer 2: Port Scanning.

Provides TCP connect, SYN half-open, UDP, and an orchestrator that
selects the best available scanning strategy.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, List

from ..core.interfaces import BaseScanner, Capability, ScanContext, ScanResult
from ..core.models import PortInfo, PortState, Protocol

logger = logging.getLogger(__name__)


# ─── Async TCP Connect Scanner ──────────────────────────────────────────────


class AsyncTCPConnectScanner(BaseScanner[List[PortInfo]]):
    """Full TCP connect() scan using asyncio.

    Does NOT require root or scapy.  Uses a semaphore for concurrency
    control and ``asyncio.open_connection`` with a timeout.
    """

    @property
    def name(self) -> str:
        return "AsyncTCPConnectScanner"

    @property
    def required_capability(self) -> Capability:
        return Capability.NONE

    async def _execute(
        self, target: str, context: ScanContext, **kwargs: Any
    ) -> List[PortInfo]:
        ports: List[int] = context.tcp_ports
        if not ports:
            return []

        semaphore = asyncio.Semaphore(context.max_concurrency)
        results: List[PortInfo] = []
        lock = asyncio.Lock()

        async def _probe(port: int) -> None:
            async with semaphore:
                state = PortState.CLOSED
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port),
                        timeout=context.timeout,
                    )
                    state = PortState.OPEN
                    writer.close()
                    await writer.wait_closed()
                except (OSError, asyncio.TimeoutError):
                    state = PortState.CLOSED
                except Exception:
                    state = PortState.CLOSED

                info = PortInfo(
                    port=port,
                    protocol=Protocol.TCP,
                    state=state,
                )
                async with lock:
                    results.append(info)

        tasks = [asyncio.create_task(_probe(p)) for p in ports]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Return sorted by port number for deterministic output.
        results.sort(key=lambda pi: pi.port)
        return results


# ─── SYN (Half-Open) Scanner ────────────────────────────────────────────────


class SYNScanScanner(BaseScanner[List[PortInfo]]):
    """TCP SYN (half-open) scan using scapy.

    Requires root privileges and scapy.  Sends a SYN packet and
    interprets the response:

    * SYN-ACK  -> OPEN
    * RST      -> CLOSED
    * No reply -> FILTERED
    """

    @property
    def name(self) -> str:
        return "SYNScanScanner"

    @property
    def required_capability(self) -> Capability:
        return Capability.ROOT_AND_SCAPY

    async def _execute(
        self, target: str, context: ScanContext, **kwargs: Any
    ) -> List[PortInfo]:
        try:
            from scapy.all import IP, TCP, sr1
        except ImportError:
            logger.warning("scapy is not installed; SYN scan unavailable")
            return []

        ports: List[int] = context.tcp_ports
        if not ports:
            return []

        loop = asyncio.get_running_loop()
        results: List[PortInfo] = []

        def _syn_probe(port: int) -> PortInfo:
            pkt = IP(dst=target) / TCP(dport=port, flags="S")
            reply = sr1(pkt, timeout=context.timeout, verbose=0)

            if reply is None:
                state = PortState.FILTERED
            elif reply.haslayer(TCP):
                tcp_layer = reply.getlayer(TCP)
                # SYN-ACK has flags 0x12
                if tcp_layer.flags == 0x12:
                    state = PortState.OPEN
                    # Send RST to tear down the half-open connection.
                    try:
                        from scapy.all import send as scapy_send

                        rst = IP(dst=target) / TCP(
                            dport=port, flags="R", seq=reply.ack
                        )
                        scapy_send(rst, verbose=0)
                    except Exception:
                        pass
                elif tcp_layer.flags & 0x04:  # RST flag
                    state = PortState.CLOSED
                else:
                    state = PortState.FILTERED
            else:
                state = PortState.FILTERED

            return PortInfo(port=port, protocol=Protocol.TCP, state=state)

        # Run all probes in the executor to avoid blocking the event loop.
        for port in ports:
            try:
                info = await loop.run_in_executor(None, _syn_probe, port)
                results.append(info)
            except Exception as exc:
                logger.debug("SYN probe for port %d failed: %s", port, exc)
                results.append(
                    PortInfo(
                        port=port,
                        protocol=Protocol.TCP,
                        state=PortState.FILTERED,
                    )
                )

        results.sort(key=lambda pi: pi.port)
        return results


# ─── UDP Scanner ─────────────────────────────────────────────────────────────


class UDPScanScanner(BaseScanner[List[PortInfo]]):
    """UDP scan using scapy.

    Requires root privileges and scapy.  Sends an empty UDP datagram
    and listens for an ICMP "port unreachable" reply:

    * ICMP port unreachable -> CLOSED
    * No response           -> OPEN_FILTERED
    """

    @property
    def name(self) -> str:
        return "UDPScanScanner"

    @property
    def required_capability(self) -> Capability:
        return Capability.ROOT_AND_SCAPY

    async def _execute(
        self, target: str, context: ScanContext, **kwargs: Any
    ) -> List[PortInfo]:
        try:
            from scapy.all import ICMP, IP, UDP, sr1
        except ImportError:
            logger.warning("scapy is not installed; UDP scan unavailable")
            return []

        ports: List[int] = context.udp_ports
        if not ports:
            return []

        loop = asyncio.get_running_loop()
        results: List[PortInfo] = []

        def _udp_probe(port: int) -> PortInfo:
            pkt = IP(dst=target) / UDP(dport=port)
            reply = sr1(pkt, timeout=context.timeout, verbose=0)

            if reply is None:
                # No response -- could be open or filtered.
                state = PortState.OPEN_FILTERED
            elif reply.haslayer(ICMP):
                icmp_layer = reply.getlayer(ICMP)
                # Type 3 = Destination Unreachable
                # Code 3 = Port Unreachable
                if icmp_layer.type == 3 and icmp_layer.code == 3:
                    state = PortState.CLOSED
                elif icmp_layer.type == 3 and icmp_layer.code in (1, 2, 9, 10, 13):
                    # Other unreachable codes indicate filtering.
                    state = PortState.FILTERED
                else:
                    state = PortState.OPEN_FILTERED
            elif reply.haslayer(UDP):
                # Got a UDP reply -- definitely open.
                state = PortState.OPEN_FILTERED
            else:
                state = PortState.OPEN_FILTERED

            return PortInfo(port=port, protocol=Protocol.UDP, state=state)

        for port in ports:
            try:
                info = await loop.run_in_executor(None, _udp_probe, port)
                results.append(info)
            except Exception as exc:
                logger.debug("UDP probe for port %d failed: %s", port, exc)
                results.append(
                    PortInfo(
                        port=port,
                        protocol=Protocol.UDP,
                        state=PortState.OPEN_FILTERED,
                    )
                )

        results.sort(key=lambda pi: pi.port)
        return results


# ─── Port Scan Orchestrator ─────────────────────────────────────────────────


class PortScanOrchestrator(BaseScanner[List[PortInfo]]):
    """Orchestrate port scanning across TCP and UDP.

    Strategy:

    * If root + scapy are available, run :class:`SYNScanScanner` for
      TCP ports **and** :class:`UDPScanScanner` for UDP ports, then
      merge the results.
    * Otherwise, fall back to :class:`AsyncTCPConnectScanner` for TCP
      only (UDP scanning without raw sockets is unreliable, so it is
      skipped in unprivileged mode).
    """

    def __init__(self) -> None:
        self._syn_scanner = SYNScanScanner()
        self._udp_scanner = UDPScanScanner()
        self._tcp_connect_scanner = AsyncTCPConnectScanner()

    @property
    def name(self) -> str:
        return "PortScanOrchestrator"

    @property
    def required_capability(self) -> Capability:
        return Capability.NONE

    async def _execute(
        self, target: str, context: ScanContext, **kwargs: Any
    ) -> List[PortInfo]:
        combined: List[PortInfo] = []

        if self._syn_scanner.is_available(context):
            # Privileged mode: SYN + UDP in parallel.
            syn_task = asyncio.create_task(
                self._syn_scanner.scan(target, context, **kwargs)
            )
            udp_task = asyncio.create_task(
                self._udp_scanner.scan(target, context, **kwargs)
            )

            syn_result: ScanResult[List[PortInfo]]
            udp_result: ScanResult[List[PortInfo]]
            syn_result, udp_result = await asyncio.gather(syn_task, udp_task)

            if syn_result.success and syn_result.data is not None:
                combined.extend(syn_result.data)
            else:
                logger.warning(
                    "SYN scan failed (%s); falling back to TCP connect",
                    syn_result.error_message,
                )
                fallback = await self._tcp_connect_scanner.scan(
                    target, context, **kwargs
                )
                if fallback.success and fallback.data is not None:
                    combined.extend(fallback.data)

            if udp_result.success and udp_result.data is not None:
                combined.extend(udp_result.data)
            else:
                logger.warning(
                    "UDP scan failed: %s", udp_result.error_message
                )
        else:
            # Unprivileged mode: TCP connect only.
            tcp_result: ScanResult[List[PortInfo]] = (
                await self._tcp_connect_scanner.scan(target, context, **kwargs)
            )
            if tcp_result.success and tcp_result.data is not None:
                combined.extend(tcp_result.data)

        # Sort by (protocol name, port) for consistent ordering.
        combined.sort(key=lambda pi: (pi.protocol.value, pi.port))
        return combined
