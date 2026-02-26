"""Runtime capability detection.

Detects what system capabilities are available (root access, scapy
library) so that the scan pipeline can choose appropriate scanners.
"""

from __future__ import annotations

import os


def detect_capabilities() -> dict:
    """Detect available system capabilities.

    Returns
    -------
    dict
        Dictionary with the following boolean keys:

        - ``has_root``: True if the process is running as root (euid == 0).
        - ``has_scapy``: True if the ``scapy.all`` module can be imported.
    """
    has_root = os.geteuid() == 0

    has_scapy = False
    try:
        import scapy.all  # noqa: F401
        has_scapy = True
    except ImportError:
        pass

    return {"has_root": has_root, "has_scapy": has_scapy}
