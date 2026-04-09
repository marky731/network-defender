"""Action definitions for the RL environment.

Defines action types corresponding to scanner layers, encoding/decoding
utilities, and action masking based on discovered state.
"""

from __future__ import annotations

import enum
from typing import Dict, Tuple

import numpy as np


class ActionType(enum.IntEnum):
    """RL action types mapped to scanner layers."""

    DISCOVER_HOST = 0      # L1
    PORT_SCAN = 1          # L2
    DETECT_SERVICES = 2    # L3
    FINGERPRINT_OS = 3     # L4
    VULN_ASSESS = 4        # L5
    CHECK_CREDENTIALS = 5  # L5 sub
    EXPLOIT = 6            # Exploitation


NUM_ACTION_TYPES = 7
MAX_HOSTS = 256  # Matches ObservationVectorizer.MAX_HOSTS

NOISE_LEVELS: Dict[ActionType, float] = {
    ActionType.DISCOVER_HOST: 0.01,
    ActionType.PORT_SCAN: 0.05,
    ActionType.DETECT_SERVICES: 0.03,
    ActionType.FINGERPRINT_OS: 0.02,
    ActionType.VULN_ASSESS: 0.04,
    ActionType.CHECK_CREDENTIALS: 0.08,
    ActionType.EXPLOIT: 0.15,
}

CREDENTIAL_PORTS = {21, 22, 2222, 3306, 5432, 6379, 27017}


def encode_action(action_type: ActionType, host_index: int) -> int:
    """Encode action type and host index into a single integer."""
    return action_type.value * MAX_HOSTS + host_index


def decode_action(action: int) -> Tuple[ActionType, int]:
    """Decode a single integer into action type and host index."""
    return ActionType(action // MAX_HOSTS), action % MAX_HOSTS


def compute_action_mask(
    discovered: Dict[str, dict], num_hosts: int
) -> np.ndarray:
    """Compute valid action mask based on discovered state.

    Parameters
    ----------
    discovered:
        Dict mapping host IP (or index key) to a dict of discovered
        information. Keys in the inner dict indicate what has been
        discovered: "alive", "ports", "services", "cves",
        "credential_results".
    num_hosts:
        Total number of hosts in the network.

    Returns
    -------
    np.ndarray
        Boolean mask of shape (NUM_ACTION_TYPES * MAX_HOSTS,) = (1792,).
    """
    mask = np.zeros(NUM_ACTION_TYPES * MAX_HOSTS, dtype=np.int8)

    for host_idx in range(min(num_hosts, MAX_HOSTS)):
        host_key = str(host_idx)
        host_info = discovered.get(host_key, {})

        # DISCOVER_HOST: always valid for hosts in range
        mask[ActionType.DISCOVER_HOST * MAX_HOSTS + host_idx] = 1

        # PORT_SCAN: host must be discovered and alive
        if host_info.get("alive", False):
            mask[ActionType.PORT_SCAN * MAX_HOSTS + host_idx] = 1

        # DETECT_SERVICES: host must be port-scanned
        if "ports" in host_info:
            mask[ActionType.DETECT_SERVICES * MAX_HOSTS + host_idx] = 1

        # FINGERPRINT_OS: host must be port-scanned
        if "ports" in host_info:
            mask[ActionType.FINGERPRINT_OS * MAX_HOSTS + host_idx] = 1

        # VULN_ASSESS: services must be detected
        if "services" in host_info:
            mask[ActionType.VULN_ASSESS * MAX_HOSTS + host_idx] = 1

        # CHECK_CREDENTIALS: services detected + has credential ports
        if "services" in host_info:
            host_ports = [p["port"] if isinstance(p, dict) else p for p in host_info.get("ports", [])]
            if any(p in CREDENTIAL_PORTS for p in host_ports):
                mask[ActionType.CHECK_CREDENTIALS * MAX_HOSTS + host_idx] = 1

        # EXPLOIT: vulnerabilities found
        if "cves" in host_info and len(host_info["cves"]) > 0:
            mask[ActionType.EXPLOIT * MAX_HOSTS + host_idx] = 1

    return mask
