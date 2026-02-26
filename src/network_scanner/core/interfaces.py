"""Abstract interfaces for scanners and supporting types."""

from __future__ import annotations

import enum
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Generic, List, Optional, TypeVar

from .models import ScanProfile

T = TypeVar("T")


class Capability(enum.Enum):
    """Required system capability for a scanner."""

    NONE = "none"
    ROOT = "root"
    SCAPY = "scapy"
    ROOT_AND_SCAPY = "root_and_scapy"


@dataclass
class ScanContext:
    """Runtime context passed to every scanner."""

    profile: ScanProfile = ScanProfile.QUICK
    timeout: float = 5.0
    max_concurrency: int = 100
    tcp_ports: list = field(default_factory=list)
    udp_ports: list = field(default_factory=list)
    has_root: bool = False
    has_scapy: bool = False

    def satisfies(self, capability: Capability) -> bool:
        """Check if this context satisfies a given capability requirement."""
        if capability == Capability.NONE:
            return True
        if capability == Capability.ROOT:
            return self.has_root
        if capability == Capability.SCAPY:
            return self.has_scapy
        if capability == Capability.ROOT_AND_SCAPY:
            return self.has_root and self.has_scapy
        return False


@dataclass(frozen=True)
class ScanResult(Generic[T]):
    """Wrapper for scanner output with metadata."""

    scanner_name: str
    success: bool
    data: Optional[T] = None
    error_message: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0

    @property
    def duration(self) -> float:
        return self.finished_at - self.started_at


class BaseScanner(ABC, Generic[T]):
    """Abstract base class for all scanners."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable scanner name."""
        ...

    @property
    @abstractmethod
    def required_capability(self) -> Capability:
        """System capability required to run this scanner."""
        ...

    def is_available(self, context: ScanContext) -> bool:
        """Check if this scanner can run in the given context."""
        return context.satisfies(self.required_capability)

    async def scan(self, target: str, context: ScanContext, **kwargs: Any) -> ScanResult[T]:
        """Execute the scan, wrapping in ScanResult with timing and error handling."""
        if not self.is_available(context):
            return ScanResult(
                scanner_name=self.name,
                success=False,
                error_message=f"Required capability not available: {self.required_capability.value}",
            )

        started = time.time()
        try:
            data = await self._execute(target, context, **kwargs)
            return ScanResult(
                scanner_name=self.name,
                success=True,
                data=data,
                started_at=started,
                finished_at=time.time(),
            )
        except Exception as exc:
            return ScanResult(
                scanner_name=self.name,
                success=False,
                error_message=str(exc),
                started_at=started,
                finished_at=time.time(),
            )

    @abstractmethod
    async def _execute(self, target: str, context: ScanContext, **kwargs: Any) -> T:
        """Actual scan implementation. Override in subclasses."""
        ...
