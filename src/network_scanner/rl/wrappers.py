"""Gymnasium wrappers for RL training.

Provides ActionMaskWrapper (MaskablePPO compatibility),
CurriculumWrapper (difficulty progression), and
EpisodeRecorderWrapper (trajectory recording for web replay).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import List, Optional

import gymnasium
import numpy as np

from .scenarios import CURRICULUM_SCENARIOS, create_scenario


class ActionMaskWrapper(gymnasium.Wrapper):
    """Exposes action_masks() method for MaskablePPO compatibility.

    MaskablePPO from sb3-contrib expects the environment to have an
    ``action_masks()`` method. This wrapper tracks the latest observation
    and returns the action_mask component on demand.
    """

    def __init__(self, env: gymnasium.Env):
        super().__init__(env)
        self._last_obs: Optional[dict] = None

    def reset(self, **kwargs):
        obs, info = self.env.reset(**kwargs)
        self._last_obs = obs
        return obs, info

    def step(self, action):
        obs, reward, terminated, truncated, info = self.env.step(action)
        self._last_obs = obs
        return obs, reward, terminated, truncated, info

    def action_masks(self) -> np.ndarray:
        """Return the current action mask for MaskablePPO."""
        if self._last_obs is None:
            return self.env.action_masks()
        return self._last_obs["action_mask"]


class CurriculumWrapper(gymnasium.Wrapper):
    """Advances scenario difficulty based on agent success rate.

    Tracks episode outcomes over a sliding window. When the success
    rate exceeds the threshold, advances to the next curriculum level.

    Levels: tiny → small → medium → large
    """

    LEVELS = list(CURRICULUM_SCENARIOS.keys())

    def __init__(
        self,
        env: gymnasium.Env,
        advancement_threshold: float = 0.7,
        window_size: int = 100,
        start_level: int = 0,
    ):
        super().__init__(env)
        self._threshold = advancement_threshold
        self._window_size = window_size
        self._current_level = start_level
        self._episode_results: List[bool] = []

    @property
    def current_level_name(self) -> str:
        return self.LEVELS[self._current_level]

    def step(self, action):
        obs, reward, terminated, truncated, info = self.env.step(action)

        if terminated or truncated:
            success = info.get("objectives_met", False)
            self._episode_results.append(success)
            info["curriculum_level"] = self.current_level_name
            info["curriculum_success_rate"] = self._get_success_rate()

            if self._should_advance():
                self._current_level += 1
                self._episode_results.clear()
                info["curriculum_advanced"] = True
                info["curriculum_new_level"] = self.current_level_name

        return obs, reward, terminated, truncated, info

    def reset(self, **kwargs):
        # Override scenario level based on curriculum
        self.env.unwrapped._scenario_level = self.current_level_name
        self.env.unwrapped._scenario_arg = None
        return self.env.reset(**kwargs)

    def _get_success_rate(self) -> float:
        if not self._episode_results:
            return 0.0
        recent = self._episode_results[-self._window_size:]
        return sum(recent) / len(recent)

    def _should_advance(self) -> bool:
        if self._current_level >= len(self.LEVELS) - 1:
            return False
        if len(self._episode_results) < self._window_size:
            return False
        return self._get_success_rate() >= self._threshold


class EpisodeRecorderWrapper(gymnasium.Wrapper):
    """Records episode trajectories as JSON for web replay.

    Each completed episode is saved as a separate JSON file containing
    the full step-by-step action/reward/state history.
    """

    def __init__(self, env: gymnasium.Env, save_dir: str = "./recordings"):
        super().__init__(env)
        self._save_dir = Path(save_dir)
        self._save_dir.mkdir(parents=True, exist_ok=True)
        self._current_episode: List[dict] = []
        self._episode_count = 0

    def reset(self, **kwargs):
        obs, info = self.env.reset(**kwargs)
        self._current_episode = []
        return obs, info

    def step(self, action):
        obs, reward, terminated, truncated, info = self.env.step(action)

        last_action = info.get("last_action", {})
        self._current_episode.append({
            "step": info.get("step", 0),
            "action": int(action),
            "action_type": last_action.get("action_type", ""),
            "target_ip": last_action.get("target_ip", ""),
            "valid": last_action.get("valid", True),
            "reward": float(reward),
            "total_reward": info.get("total_reward", 0.0),
            "detection_level": info.get("detection_level", 0.0),
            "discovered_count": info.get("discovered_count", 0),
            "exploited_hosts": info.get("exploited_hosts", []),
        })

        if terminated or truncated:
            self._save_episode(info)
            self._current_episode = []

        return obs, reward, terminated, truncated, info

    def _save_episode(self, final_info: dict):
        self._episode_count += 1
        record = {
            "episode": self._episode_count,
            "timestamp": time.time(),
            "total_steps": final_info.get("step", 0),
            "total_reward": final_info.get("total_reward", 0.0),
            "objectives_met": final_info.get("objectives_met", False),
            "detection_level": final_info.get("detection_level", 0.0),
            "steps": self._current_episode,
        }
        path = self._save_dir / f"episode_{self._episode_count:05d}.json"
        with open(path, "w") as f:
            json.dump(record, f, indent=2, default=str)
