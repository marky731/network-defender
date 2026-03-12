"""Tests for RL action encoding, decoding, and masking."""

import numpy as np
import pytest

from network_scanner.rl.actions import (
    MAX_HOSTS,
    NUM_ACTION_TYPES,
    ActionType,
    compute_action_mask,
    decode_action,
    encode_action,
)


class TestEncodeDecode:
    def test_encode_decode_roundtrip(self):
        for action_type in ActionType:
            for host_idx in [0, 1, 127, 255]:
                encoded = encode_action(action_type, host_idx)
                decoded_type, decoded_idx = decode_action(encoded)
                assert decoded_type == action_type
                assert decoded_idx == host_idx

    def test_encode_action_values(self):
        assert encode_action(ActionType.DISCOVER_HOST, 0) == 0
        assert encode_action(ActionType.PORT_SCAN, 0) == 256
        assert encode_action(ActionType.DETECT_SERVICES, 0) == 512
        assert encode_action(ActionType.FINGERPRINT_OS, 0) == 768
        assert encode_action(ActionType.VULN_ASSESS, 0) == 1024
        assert encode_action(ActionType.CHECK_CREDENTIALS, 0) == 1280
        assert encode_action(ActionType.EXPLOIT, 0) == 1536

    def test_action_space_size(self):
        assert NUM_ACTION_TYPES * MAX_HOSTS == 1792


class TestActionMask:
    def test_action_mask_initial(self):
        """Initially only DISCOVER_HOST should be valid."""
        mask = compute_action_mask({}, num_hosts=3)
        # DISCOVER_HOST for indices 0,1,2
        for i in range(3):
            assert mask[ActionType.DISCOVER_HOST * MAX_HOSTS + i] == 1.0
        # Other actions should be 0
        for action_type in ActionType:
            if action_type == ActionType.DISCOVER_HOST:
                continue
            for i in range(3):
                assert mask[action_type * MAX_HOSTS + i] == 0.0

    def test_action_mask_after_discovery(self):
        """After discovering alive host, PORT_SCAN opens."""
        discovered = {"0": {"alive": True}}
        mask = compute_action_mask(discovered, num_hosts=1)
        assert mask[ActionType.PORT_SCAN * MAX_HOSTS + 0] == 1.0

    def test_action_mask_after_port_scan(self):
        """After port scan, DETECT_SERVICES and FINGERPRINT_OS open."""
        discovered = {"0": {"alive": True, "ports": [22, 80]}}
        mask = compute_action_mask(discovered, num_hosts=1)
        assert mask[ActionType.DETECT_SERVICES * MAX_HOSTS + 0] == 1.0
        assert mask[ActionType.FINGERPRINT_OS * MAX_HOSTS + 0] == 1.0

    def test_action_mask_after_services(self):
        """After service detection, VULN_ASSESS opens."""
        discovered = {
            "0": {"alive": True, "ports": [22, 80], "services": ["ssh", "http"]}
        }
        mask = compute_action_mask(discovered, num_hosts=1)
        assert mask[ActionType.VULN_ASSESS * MAX_HOSTS + 0] == 1.0

    def test_action_mask_credential_ports(self):
        """CHECK_CREDENTIALS only for hosts with credential ports."""
        # Host with credential port (22)
        discovered_yes = {
            "0": {"alive": True, "ports": [22, 80], "services": ["ssh", "http"]}
        }
        mask = compute_action_mask(discovered_yes, num_hosts=1)
        assert mask[ActionType.CHECK_CREDENTIALS * MAX_HOSTS + 0] == 1.0

        # Host without credential port
        discovered_no = {
            "0": {"alive": True, "ports": [80, 443], "services": ["http", "https"]}
        }
        mask = compute_action_mask(discovered_no, num_hosts=1)
        assert mask[ActionType.CHECK_CREDENTIALS * MAX_HOSTS + 0] == 0.0

    def test_action_mask_after_vulns(self):
        """After vulnerability discovery, EXPLOIT opens."""
        discovered = {
            "0": {
                "alive": True,
                "ports": [22],
                "services": ["ssh"],
                "cves": ["CVE-2023-0001"],
            }
        }
        mask = compute_action_mask(discovered, num_hosts=1)
        assert mask[ActionType.EXPLOIT * MAX_HOSTS + 0] == 1.0

    def test_action_mask_out_of_range(self):
        """Host indices beyond num_hosts should be 0."""
        mask = compute_action_mask({}, num_hosts=2)
        # Index 2 should be masked out for all action types
        for action_type in ActionType:
            assert mask[action_type * MAX_HOSTS + 2] == 0.0

    def test_action_mask_exploit_requires_cves(self):
        """EXPLOIT should not open if cves list is empty."""
        discovered = {
            "0": {
                "alive": True,
                "ports": [22],
                "services": ["ssh"],
                "cves": [],
            }
        }
        mask = compute_action_mask(discovered, num_hosts=1)
        assert mask[ActionType.EXPLOIT * MAX_HOSTS + 0] == 0.0
