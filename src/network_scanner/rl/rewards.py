"""Reward calculation for the RL environment.

Computes step rewards based on action type, outcome, novelty,
host value, and detection risk.
"""

from __future__ import annotations

from .actions import ActionType


class RewardCalculator:
    """Computes rewards for RL agent actions."""

    STEP_COST = -0.01
    DISCOVERY_REWARD = 0.05
    PORT_DISCOVERY_REWARD = 0.02
    SERVICE_DETECTION_REWARD = 0.03
    OS_FINGERPRINT_REWARD = 0.02
    VULN_DISCOVERY_REWARD = 0.10
    CREDENTIAL_FOUND_REWARD = 0.15
    EXPLOIT_SUCCESS_REWARD = 0.50
    EXPLOIT_FAIL_PENALTY = -0.05
    REDUNDANT_ACTION_PENALTY = -0.02
    DETECTION_RISK_FACTOR = -0.03

    def compute(
        self,
        action_type: ActionType,
        result: dict,
        is_new_info: bool,
        host_value: float = 1.0,
        noise_level: float = 0.0,
    ) -> float:
        """Compute reward for a single action.

        Parameters
        ----------
        action_type:
            The type of action taken.
        result:
            Dict with action-specific outcome data.
        is_new_info:
            Whether the action produced new information.
        host_value:
            Value of the target host (multiplier for exploit reward).
        noise_level:
            Detection noise level of the action.

        Returns
        -------
        float
            The computed reward.
        """
        reward = self.STEP_COST
        reward += self.DETECTION_RISK_FACTOR * noise_level

        if not is_new_info:
            reward += self.REDUNDANT_ACTION_PENALTY
            return reward

        if action_type == ActionType.DISCOVER_HOST:
            reward += self.DISCOVERY_REWARD

        elif action_type == ActionType.PORT_SCAN:
            reward += self.PORT_DISCOVERY_REWARD * result.get("num_ports", 0)

        elif action_type == ActionType.DETECT_SERVICES:
            reward += self.SERVICE_DETECTION_REWARD * result.get("num_services", 0)

        elif action_type == ActionType.FINGERPRINT_OS:
            reward += self.OS_FINGERPRINT_REWARD

        elif action_type == ActionType.VULN_ASSESS:
            cvss_scores = result.get("cvss_scores", [])
            reward += self.VULN_DISCOVERY_REWARD * sum(
                c / 10.0 for c in cvss_scores
            )

        elif action_type == ActionType.CHECK_CREDENTIALS:
            reward += self.CREDENTIAL_FOUND_REWARD * result.get("num_found", 0)

        elif action_type == ActionType.EXPLOIT:
            if result.get("success", False):
                reward += self.EXPLOIT_SUCCESS_REWARD * host_value
            else:
                reward += self.EXPLOIT_FAIL_PENALTY

        return reward
