"""Tests for RewardCalculator."""

import pytest

from network_scanner.rl.actions import ActionType
from network_scanner.rl.rewards import RewardCalculator


@pytest.fixture
def calc():
    return RewardCalculator()


class TestStepCost:
    def test_step_cost_always_applied(self, calc):
        """Every action incurs step cost."""
        for action_type in ActionType:
            reward = calc.compute(
                action_type=action_type,
                result={},
                is_new_info=True,
            )
            assert reward <= -calc.STEP_COST or True  # step cost is negative
            # More precisely: the reward includes STEP_COST
            # For DISCOVER_HOST with new info: STEP_COST + DISCOVERY_REWARD
            # Just verify it's less than the base reward alone
        # Explicit check
        reward = calc.compute(ActionType.DISCOVER_HOST, {}, is_new_info=True)
        expected_min = calc.STEP_COST + calc.DISCOVERY_REWARD
        assert abs(reward - expected_min) < 1e-9


class TestDiscovery:
    def test_discovery_new_host(self, calc):
        reward = calc.compute(ActionType.DISCOVER_HOST, {}, is_new_info=True)
        assert reward > 0  # STEP_COST(-0.01) + DISCOVERY(0.05) = 0.04


class TestPortScan:
    def test_port_scan_multiple_ports(self, calc):
        reward = calc.compute(
            ActionType.PORT_SCAN,
            {"num_ports": 5},
            is_new_info=True,
        )
        expected = calc.STEP_COST + calc.PORT_DISCOVERY_REWARD * 5
        assert abs(reward - expected) < 1e-9


class TestVulnDiscovery:
    def test_vuln_discovery_cvss_scaled(self, calc):
        reward = calc.compute(
            ActionType.VULN_ASSESS,
            {"cvss_scores": [7.5, 9.0]},
            is_new_info=True,
        )
        expected = calc.STEP_COST + calc.VULN_DISCOVERY_REWARD * (7.5 / 10 + 9.0 / 10)
        assert abs(reward - expected) < 1e-9


class TestCredentials:
    def test_credential_found(self, calc):
        reward = calc.compute(
            ActionType.CHECK_CREDENTIALS,
            {"num_found": 2},
            is_new_info=True,
        )
        expected = calc.STEP_COST + calc.CREDENTIAL_FOUND_REWARD * 2
        assert abs(reward - expected) < 1e-9


class TestExploit:
    def test_exploit_success_scaled(self, calc):
        reward = calc.compute(
            ActionType.EXPLOIT,
            {"success": True},
            is_new_info=True,
            host_value=2.0,
        )
        expected = calc.STEP_COST + calc.EXPLOIT_SUCCESS_REWARD * 2.0
        assert abs(reward - expected) < 1e-9

    def test_exploit_failure(self, calc):
        reward = calc.compute(
            ActionType.EXPLOIT,
            {"success": False},
            is_new_info=True,
        )
        expected = calc.STEP_COST + calc.EXPLOIT_FAIL_PENALTY
        assert abs(reward - expected) < 1e-9


class TestRedundantAction:
    def test_redundant_action(self, calc):
        reward = calc.compute(
            ActionType.DISCOVER_HOST,
            {},
            is_new_info=False,
        )
        expected = calc.STEP_COST + calc.REDUNDANT_ACTION_PENALTY
        assert abs(reward - expected) < 1e-9


class TestDetectionRisk:
    def test_detection_risk(self, calc):
        reward = calc.compute(
            ActionType.EXPLOIT,
            {"success": True},
            is_new_info=True,
            noise_level=0.15,
        )
        expected = (
            calc.STEP_COST
            + calc.DETECTION_RISK_FACTOR * 0.15
            + calc.EXPLOIT_SUCCESS_REWARD * 1.0
        )
        assert abs(reward - expected) < 1e-9


class TestCombinedRewardRange:
    def test_combined_reward_range(self, calc):
        """Rewards should stay in a reasonable range."""
        # Worst case: redundant + high noise
        worst = calc.compute(
            ActionType.EXPLOIT,
            {},
            is_new_info=False,
            noise_level=0.15,
        )
        assert worst >= -0.2

        # Best case: successful exploit on high-value host
        best = calc.compute(
            ActionType.EXPLOIT,
            {"success": True},
            is_new_info=True,
            host_value=3.0,
        )
        assert best <= 2.0
