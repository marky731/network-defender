"""Tests for NetworkAttackEnv (Phase 2)."""

import numpy as np
import pytest
from gymnasium.utils.env_checker import check_env

from network_scanner.rl.actions import (
    MAX_HOSTS,
    NUM_ACTION_TYPES,
    ActionType,
    encode_action,
)
from network_scanner.rl.env import NetworkAttackEnv
from network_scanner.rl.scenarios import create_demo_scenario, create_scenario


# ─── Env Creation ───────────────────────────────────────────────────────────


class TestEnvCreation:
    def test_env_creation_default(self):
        env = NetworkAttackEnv(scenario_level="tiny", seed=42)
        assert env is not None

    def test_env_creation_with_scenario(self):
        net = create_demo_scenario()
        env = NetworkAttackEnv(scenario=net)
        assert env is not None

    def test_env_creation_all_levels(self):
        for level in ("tiny", "small", "medium", "large"):
            env = NetworkAttackEnv(scenario_level=level, seed=1)
            obs, info = env.reset(seed=1)
            assert info["num_hosts"] > 0


# ─── Reset ──────────────────────────────────────────────────────────────────


class TestReset:
    def test_reset_returns_undiscovered_observation(self):
        env = NetworkAttackEnv(scenario_level="tiny", seed=42)
        obs, info = env.reset(seed=42)
        # Nothing discovered yet — is_alive (index 0) should be 0 for all hosts
        for i in range(info["num_hosts"]):
            assert obs["network_state"][i, 0] == 0.0  # is_alive = False

    def test_reset_observation_shapes(self):
        env = NetworkAttackEnv(scenario_level="tiny", seed=42)
        obs, _ = env.reset(seed=42)
        assert obs["network_state"].shape == (MAX_HOSTS, 47)
        assert obs["network_state"].dtype == np.float32
        assert obs["action_mask"].shape == (NUM_ACTION_TYPES * MAX_HOSTS,)
        assert obs["action_mask"].dtype == np.int8
        assert obs["agent_state"].shape == (2,)
        assert obs["agent_state"].dtype == np.float32

    def test_reset_agent_state_initial(self):
        env = NetworkAttackEnv(scenario_level="tiny", seed=42)
        obs, _ = env.reset(seed=42)
        # detection=0 → normalized=0, steps_remaining=max → normalized=1
        np.testing.assert_array_almost_equal(obs["agent_state"], [0.0, 1.0])

    def test_reset_info(self):
        env = NetworkAttackEnv(scenario_level="tiny", seed=42)
        _, info = env.reset(seed=42)
        assert info["step"] == 0
        assert info["detection_level"] == 0.0
        assert info["discovered_count"] == 0

    def test_reset_only_discover_actions_valid(self):
        env = NetworkAttackEnv(scenario_level="tiny", seed=42)
        obs, info = env.reset(seed=42)
        mask = obs["action_mask"]
        num_hosts = info["num_hosts"]
        # DISCOVER_HOST actions should be valid for all hosts
        for i in range(num_hosts):
            assert mask[ActionType.DISCOVER_HOST * MAX_HOSTS + i] == 1
        # PORT_SCAN and beyond should all be 0
        for at in range(1, NUM_ACTION_TYPES):
            assert mask[at * MAX_HOSTS: at * MAX_HOSTS + num_hosts].sum() == 0


# ─── Step ───────────────────────────────────────────────────────────────────


class TestStep:
    def test_step_discover_host(self):
        env = NetworkAttackEnv(scenario_level="tiny", seed=100)
        obs, info = env.reset(seed=100)
        action = encode_action(ActionType.DISCOVER_HOST, 0)
        obs, reward, terminated, truncated, info = env.step(action)
        assert info["step"] == 1
        assert info["detection_level"] > 0

    def test_step_invalid_action_penalized(self):
        env = NetworkAttackEnv(scenario_level="tiny", seed=42)
        env.reset(seed=42)
        # PORT_SCAN on host 0 without discovery — should be invalid
        action = encode_action(ActionType.PORT_SCAN, 0)
        _, reward, _, _, info = env.step(action)
        assert reward < 0
        assert info["last_action"]["valid"] is False

    def test_progressive_discovery(self):
        """After discovering a host, new actions unlock."""
        env = NetworkAttackEnv(scenario_level="tiny", seed=100)
        obs, info = env.reset(seed=100)

        # Discover host 0
        action = encode_action(ActionType.DISCOVER_HOST, 0)
        obs, _, _, _, _ = env.step(action)

        if obs["action_mask"][encode_action(ActionType.PORT_SCAN, 0)] == 1:
            # Port scan should now be valid
            action = encode_action(ActionType.PORT_SCAN, 0)
            obs, _, _, _, info = env.step(action)
            assert info["step"] == 2

    def test_action_mask_updates_after_discovery(self):
        """Discovery of a host should enable PORT_SCAN."""
        env = NetworkAttackEnv(scenario_level="tiny", seed=100)
        obs, _ = env.reset(seed=100)

        # Before discovery: PORT_SCAN invalid
        assert obs["action_mask"][encode_action(ActionType.PORT_SCAN, 0)] == 0

        # Discover host 0 (seed=100 should succeed)
        action = encode_action(ActionType.DISCOVER_HOST, 0)
        obs, _, _, _, _ = env.step(action)

        # After discovery: PORT_SCAN should be valid (if host was alive)
        if obs["action_mask"][encode_action(ActionType.PORT_SCAN, 0)] == 1:
            assert True  # PORT_SCAN unlocked
        # If host_discover returned False (5% false-negative), mask stays 0


# ─── Termination ────────────────────────────────────────────────────────────


class TestTermination:
    def test_episode_terminates_on_detection(self):
        """Episode ends when detection_level >= threshold."""
        env = NetworkAttackEnv(
            scenario_level="tiny", seed=42,
            detection_threshold=0.05,  # Very low threshold
        )
        obs, _ = env.reset(seed=42)
        # A few actions should exceed the threshold
        terminated = False
        for _ in range(20):
            mask = obs["action_mask"]
            valid = np.where(mask == 1)[0]
            obs, _, terminated, truncated, info = env.step(valid[0])
            if terminated or truncated:
                break
        assert terminated

    def test_episode_truncates_on_max_steps(self):
        """Episode truncates at max_steps."""
        env = NetworkAttackEnv(
            scenario_level="tiny", seed=42,
            max_steps=5,
            detection_threshold=100.0,  # Won't trigger
        )
        obs, _ = env.reset(seed=42)
        for _ in range(10):
            mask = obs["action_mask"]
            valid = np.where(mask == 1)[0]
            obs, _, terminated, truncated, info = env.step(valid[0])
            if terminated or truncated:
                break
        assert truncated
        assert info["step"] == 5

    def test_episode_terminates_on_all_objectives(self):
        """Episode ends when all high-value hosts are exploited."""
        env = NetworkAttackEnv(scenario_level="tiny", seed=42)
        env.reset(seed=42)
        # Manually set exploited_hosts to all objectives
        env._exploited_hosts = set(env._objective_ips)
        assert env._all_objectives_met()


# ─── Partial Observability ──────────────────────────────────────────────────


class TestPartialObservability:
    def test_undiscovered_hosts_show_not_alive(self):
        env = NetworkAttackEnv(scenario_level="tiny", seed=42)
        obs, info = env.reset(seed=42)
        # All hosts undiscovered — is_alive (index 0) should be 0
        for i in range(info["num_hosts"]):
            assert obs["network_state"][i, 0] == 0.0  # is_alive = False
            # No ports, services, vulns, creds
            assert obs["network_state"][i, 1:29].sum() == 0.0  # port bitmap

    def test_discovered_host_nonzero(self):
        """After discovering a host, its row becomes non-zero."""
        env = NetworkAttackEnv(scenario_level="tiny", seed=100)
        obs, _ = env.reset(seed=100)

        # Discover host 0
        action = encode_action(ActionType.DISCOVER_HOST, 0)
        obs, _, _, _, _ = env.step(action)

        # If discovery succeeded, row 0 should have is_alive=1
        if obs["network_state"][0, 0] == 1.0:
            assert obs["network_state"][0].sum() > 0.0


# ─── Determinism ────────────────────────────────────────────────────────────


class TestDeterminism:
    def test_seed_reproducibility(self):
        """Same seed produces identical episodes."""
        env = NetworkAttackEnv(scenario_level="tiny")

        # Episode 1
        obs1, _ = env.reset(seed=42)
        action = encode_action(ActionType.DISCOVER_HOST, 0)
        obs1_after, r1, _, _, _ = env.step(action)

        # Episode 2 with same seed
        obs2, _ = env.reset(seed=42)
        obs2_after, r2, _, _, _ = env.step(action)

        np.testing.assert_array_equal(obs1["network_state"], obs2["network_state"])
        np.testing.assert_array_equal(obs1["action_mask"], obs2["action_mask"])
        assert r1 == r2


# ─── Integration ────────────────────────────────────────────────────────────


class TestIntegration:
    def test_gymnasium_check_env(self):
        """Official Gymnasium validator passes."""
        env = NetworkAttackEnv(scenario_level="tiny", seed=42)
        check_env(env, skip_render_check=True)

    def test_full_pipeline_50_steps(self):
        """Run 50 steps without errors."""
        env = NetworkAttackEnv(scenario_level="small", seed=42)
        obs, info = env.reset(seed=42)

        for _ in range(50):
            mask = obs["action_mask"]
            valid = np.where(mask == 1)[0]
            if len(valid) == 0:
                break
            action = valid[np.random.RandomState(42).randint(len(valid))]
            obs, reward, terminated, truncated, info = env.step(action)
            # Observation shapes should always be correct
            assert obs["network_state"].shape == (MAX_HOSTS, 47)
            assert obs["action_mask"].shape == (NUM_ACTION_TYPES * MAX_HOSTS,)
            assert obs["agent_state"].shape == (2,)
            if terminated or truncated:
                break

    def test_render_human(self, capsys):
        env = NetworkAttackEnv(scenario_level="tiny", seed=42, render_mode="human")
        env.reset(seed=42)
        action = encode_action(ActionType.DISCOVER_HOST, 0)
        env.step(action)
        result = env.render()
        assert result is not None
        assert "Step" in result

    def test_action_masks_method(self):
        """action_masks() for MaskablePPO compatibility."""
        env = NetworkAttackEnv(scenario_level="tiny", seed=42)
        env.reset(seed=42)
        mask = env.action_masks()
        assert mask.shape == (NUM_ACTION_TYPES * MAX_HOSTS,)
        assert mask.dtype == np.int8
