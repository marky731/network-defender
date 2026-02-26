"""TTL-based scan result cache."""

from __future__ import annotations

import time
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class _CacheEntry:
    """Single cache entry with expiration."""

    value: Any
    expires_at: float


class ScanCache:
    """Thread-safe TTL-based cache for scan results.

    Keys are typically "{scanner_name}:{target}" strings.
    """

    def __init__(self, default_ttl: float = 300.0):
        self._default_ttl = default_ttl
        self._store: Dict[str, _CacheEntry] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        """Get a cached value. Returns None if expired or missing."""
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            if time.time() > entry.expires_at:
                del self._store[key]
                return None
            return entry.value

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Store a value with optional custom TTL."""
        with self._lock:
            self._store[key] = _CacheEntry(
                value=value,
                expires_at=time.time() + (ttl if ttl is not None else self._default_ttl),
            )

    def invalidate(self, key: str) -> bool:
        """Remove a specific key. Returns True if it existed."""
        with self._lock:
            return self._store.pop(key, None) is not None

    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._store.clear()

    def cleanup(self) -> int:
        """Remove expired entries. Returns number of entries removed."""
        now = time.time()
        removed = 0
        with self._lock:
            expired_keys = [k for k, v in self._store.items() if now > v.expires_at]
            for k in expired_keys:
                del self._store[k]
                removed += 1
        return removed

    @property
    def size(self) -> int:
        """Current number of (possibly expired) entries."""
        with self._lock:
            return len(self._store)
