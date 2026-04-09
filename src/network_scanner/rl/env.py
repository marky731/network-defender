"""Gymnasium RL environment for network attack simulation.

Wraps the SimulatedNetwork, action system, and reward calculator
into a standard Gymnasium environment that any RL algorithm can use.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

import gymnasium
import numpy as np
from gymnasium import spaces

from ..aggregator.state_builder import StateBuilder
from ..aggregator.vectorizer import ObservationVectorizer
from ..core.models import (
    OSFamily,
    OSGuess,
    PortInfo,
    PortState,
    Protocol,
    Severity,
)
from .actions import (
    NOISE_LEVELS,
    ActionType,
    MAX_HOSTS,
    NUM_ACTION_TYPES,
    compute_action_mask,
    decode_action,
)
from .rewards import RewardCalculator
from .scenarios import create_scenario
from .sim_network import SimulatedNetwork


class NetworkAttackEnv(gymnasium.Env):
    """Gymnasium environment for network attack simulation.

    The agent discovers hosts, scans ports, detects services,
    finds vulnerabilities, and attempts exploits — while managing
    detection risk.

    Parameters
    ----------
    scenario:
        A pre-built SimulatedNetwork, or None to auto-generate.
    scenario_level:
        Curriculum level name ("tiny", "small", "medium", "large").
        Used when *scenario* is None.
    max_steps:
        Maximum steps per episode before truncation.
    detection_threshold:
        Cumulative detection level that terminates the episode.
    render_mode:
        "human" for terminal output, "json" for structured data.
    seed:
        RNG seed for reproducibility.
    """

    metadata = {"render_modes": ["human", "json"]}

    def __init__(
        self,
        scenario: Optional[SimulatedNetwork] = None,
        scenario_level: str = "small",
        max_steps: int = 300,
        detection_threshold: float = 3.0,
        render_mode: Optional[str] = None,
        seed: Optional[int] = None,
    ):
        super().__init__()

        self._scenario_arg = scenario
        self._scenario_level = scenario_level
        self._max_steps = max_steps
        self._detection_threshold = detection_threshold
        self.render_mode = render_mode
        self._seed = seed

        # Observation and action spaces
        self.observation_space = spaces.Dict({
            "network_state": spaces.Box(
                low=0.0, high=1.0,
                shape=(MAX_HOSTS, ObservationVectorizer.FEATURES_PER_HOST),
                dtype=np.float32,
            ),
            "action_mask": spaces.MultiBinary(NUM_ACTION_TYPES * MAX_HOSTS),
            "agent_state": spaces.Box(
                low=0.0, high=1.0, shape=(2,), dtype=np.float32,
            ),
        })
        self.action_space = spaces.Discrete(NUM_ACTION_TYPES * MAX_HOSTS)

        # Internal components
        self._vectorizer = ObservationVectorizer()
        self._reward_calc = RewardCalculator()

        # State (initialized in reset)
        self._network: Optional[SimulatedNetwork] = None
        self._discovered: Dict[str, dict] = {}
        self._ip_to_index: Dict[str, int] = {}
        self._index_to_ip: Dict[int, str] = {}
        self._step_count: int = 0
        self._detection_level: float = 0.0
        self._exploited_hosts: Set[str] = set()
        self._total_reward: float = 0.0
        self._action_history: List[dict] = []
        self._num_hosts: int = 0
        self._objective_ips: Set[str] = set()
        self._last_action_info: dict = {}

    def reset(
        self,
        *,
        seed: Optional[int] = None,
        options: Optional[dict] = None,
    ) -> Tuple[dict, dict]:
        """Reset the environment for a new episode."""
        super().reset(seed=seed)

        # Build network
        effective_seed = seed if seed is not None else self._seed
        if self._scenario_arg is not None:
            self._network = self._scenario_arg
        else:
            self._network = create_scenario(
                level=self._scenario_level, seed=effective_seed,
            )

        # Build IP <-> index mappings
        ips = sorted(self._network.hosts.keys())
        self._num_hosts = len(ips)
        self._ip_to_index = {ip: idx for idx, ip in enumerate(ips)}
        self._index_to_ip = {idx: ip for idx, ip in enumerate(ips)}

        # Identify objective hosts (value >= 2.0)
        self._objective_ips = {
            ip for ip, host in self._network.hosts.items()
            if host.value >= 2.0
        }

        # Reset state
        self._discovered = {}
        self._step_count = 0
        self._detection_level = 0.0
        self._exploited_hosts = set()
        self._total_reward = 0.0
        self._action_history = []
        self._last_action_info = {}

        obs = self._get_observation()
        info = self._get_info()
        return obs, info

    def step(
        self, action: int,
    ) -> Tuple[dict, float, bool, bool, dict]:
        """Execute one action and return the result."""
        self._step_count += 1

        action_type, host_idx = decode_action(action)
        ip = self._index_to_ip.get(host_idx)
        noise_level = NOISE_LEVELS[action_type]

        # Check action mask validity
        mask = compute_action_mask(self._discovered, self._num_hosts)
        if mask[action] == 0:
            # Invalid action — penalize but don't change state
            reward = self._reward_calc.REDUNDANT_ACTION_PENALTY + self._reward_calc.STEP_COST
            self._detection_level += noise_level
            self._total_reward += reward

            self._last_action_info = {
                "action_type": action_type.name,
                "host_index": host_idx,
                "target_ip": ip or "unknown",
                "valid": False,
                "reward": reward,
            }
            self._action_history.append(self._last_action_info)

            obs = self._get_observation()
            terminated, truncated = self._check_done()
            return obs, reward, terminated, truncated, self._get_info()

        # Execute valid action
        result, is_new_info = self._execute_action(action_type, ip)

        # Update detection level
        self._detection_level += noise_level

        # Calculate reward
        host_value = 1.0
        if ip and ip in self._network.hosts:
            host_value = self._network.hosts[ip].value

        reward = self._reward_calc.compute(
            action_type=action_type,
            result=result,
            is_new_info=is_new_info,
            host_value=host_value,
            noise_level=noise_level,
        )
        self._total_reward += reward

        # Record action
        self._last_action_info = {
            "action_type": action_type.name,
            "host_index": host_idx,
            "target_ip": ip or "unknown",
            "valid": True,
            "is_new_info": is_new_info,
            "reward": reward,
            "detection_level": self._detection_level,
            "result": result,
        }
        self._action_history.append(self._last_action_info)

        obs = self._get_observation()
        terminated, truncated = self._check_done()
        return obs, reward, terminated, truncated, self._get_info()

    def _execute_action(
        self, action_type: ActionType, ip: str,
    ) -> Tuple[dict, bool]:
        """Dispatch action to SimulatedNetwork and update discovered state.

        Returns (result_dict, is_new_info).
        """
        host_key = str(self._ip_to_index[ip])

        if host_key not in self._discovered:
            self._discovered[host_key] = {}
        info = self._discovered[host_key]

        if action_type == ActionType.DISCOVER_HOST:
            was_known = info.get("alive", False)
            alive = self._network.host_discover(ip)
            if alive:
                info["alive"] = True
            result = {"alive": alive}
            is_new = alive and not was_known
            return result, is_new

        elif action_type == ActionType.PORT_SCAN:
            had_ports = "ports" in info
            ports = self._network.port_scan(ip)
            # Store in enriched format for to_host_observation compatibility
            host_obj = self._network.hosts[ip]
            port_dicts = []
            for p in ports:
                svc = next((s for s in host_obj.services if s.port == p), None)
                port_dicts.append({
                    "port": p,
                    "protocol": Protocol.TCP,
                    "state": PortState.OPEN,
                    "service_name": svc.service_name if svc else "",
                    "service_version": "",
                    "banner": "",
                    "tunnel": "ssl" if (svc and svc.has_ssl) else "",
                })
            info["ports"] = port_dicts
            result = {"num_ports": len(ports)}
            is_new = not had_ports and len(ports) > 0
            return result, is_new

        elif action_type == ActionType.DETECT_SERVICES:
            had_services = "services" in info
            services = []
            for port_info in info.get("ports", []):
                p = port_info["port"]
                svc_data = self._network.detect_service(ip, p)
                if svc_data:
                    name, version, banner = svc_data
                    port_info["service_name"] = name
                    port_info["service_version"] = version
                    port_info["banner"] = banner
                    services.append(name)
            info["services"] = services
            result = {"num_services": len(services)}
            is_new = not had_services and len(services) > 0
            return result, is_new

        elif action_type == ActionType.FINGERPRINT_OS:
            had_os = "os_guess" in info
            os_data = self._network.fingerprint_os(ip)
            if os_data:
                os_family, os_detail, confidence = os_data
                info["os_guess"] = {
                    "os_family": os_family,
                    "os_detail": os_detail,
                    "confidence": confidence,
                }
            result = {"success": os_data is not None}
            is_new = not had_os and os_data is not None
            return result, is_new

        elif action_type == ActionType.VULN_ASSESS:
            had_cves = "cves" in info
            vulns = self._network.get_vulnerabilities(ip)
            info["cves"] = [
                {
                    "cve_id": v.cve_id,
                    "cvss_score": v.cvss_score,
                    "severity": v.severity,
                    "description": f"{v.affected_service} vulnerability",
                    "exploitability_score": v.exploitability_score,
                }
                for v in vulns
            ]
            result = {"cvss_scores": [v.cvss_score for v in vulns]}
            is_new = not had_cves and len(vulns) > 0
            return result, is_new

        elif action_type == ActionType.CHECK_CREDENTIALS:
            had_creds = "credential_results" in info
            all_creds = []
            for port_info in info.get("ports", []):
                p = port_info["port"]
                creds = self._network.check_credentials(ip, p)
                for c in creds:
                    all_creds.append({
                        "service": c.service,
                        "port": c.port,
                        "username": c.username,
                        "success": True,
                        "auth_method": "password",
                    })
            info["credential_results"] = all_creds
            result = {"num_found": len(all_creds)}
            is_new = not had_creds and len(all_creds) > 0
            return result, is_new

        elif action_type == ActionType.EXPLOIT:
            # Auto-select CVE with highest exploitability score
            cves = info.get("cves", [])
            if not cves:
                return {"success": False}, False

            best_cve = max(cves, key=lambda c: c.get("exploitability_score", 0))
            already_exploited = ip in self._exploited_hosts
            success = self._network.attempt_exploit(ip, best_cve["cve_id"])
            if success:
                self._exploited_hosts.add(ip)
            result = {"success": success}
            is_new = success and not already_exploited
            return result, is_new

        return {}, False

    def _get_observation(self) -> dict:
        """Build the observation dict from current discovered state."""
        # Build HostObservation list from discovered state
        host_observations = []
        for idx in range(self._num_hosts):
            host_key = str(idx)
            ip = self._index_to_ip[idx]

            if host_key in self._discovered and self._discovered[host_key].get("alive"):
                host_obs = self._network.to_host_observation(
                    ip, self._discovered[host_key],
                )
            else:
                # Undiscovered host — empty observation
                host_obs = StateBuilder.build_host(ip=ip, is_alive=False)

            host_observations.append(host_obs)

        # Build NetworkObservation and vectorize
        network_obs = StateBuilder.build_network(
            target_subnet=self._network.subnet,
            hosts=host_observations,
        )
        network_state = self._vectorizer.vectorize(network_obs)

        # Action mask
        action_mask = compute_action_mask(self._discovered, self._num_hosts)

        # Agent state: [detection_level_normalized, steps_remaining_normalized]
        detection_norm = min(self._detection_level / self._detection_threshold, 1.0)
        steps_remaining_norm = max(1.0 - self._step_count / self._max_steps, 0.0)
        agent_state = np.array(
            [detection_norm, steps_remaining_norm], dtype=np.float32,
        )

        return {
            "network_state": network_state,
            "action_mask": action_mask,
            "agent_state": agent_state,
        }

    def _check_done(self) -> Tuple[bool, bool]:
        """Return (terminated, truncated)."""
        # Terminated: detected or all objectives met
        detected = self._detection_level >= self._detection_threshold
        objectives_met = self._all_objectives_met()
        terminated = detected or objectives_met

        # Truncated: max steps reached
        truncated = not terminated and self._step_count >= self._max_steps

        return terminated, truncated

    def _all_objectives_met(self) -> bool:
        """Check if all high-value hosts have been exploited."""
        if not self._objective_ips:
            return False
        return self._objective_ips.issubset(self._exploited_hosts)

    def _get_info(self) -> dict:
        """Build the info dict for the current step."""
        return {
            "step": self._step_count,
            "detection_level": self._detection_level,
            "detection_threshold": self._detection_threshold,
            "exploited_hosts": list(self._exploited_hosts),
            "total_reward": self._total_reward,
            "objectives_met": self._all_objectives_met(),
            "discovered_count": sum(
                1 for v in self._discovered.values() if v.get("alive")
            ),
            "num_hosts": self._num_hosts,
            "last_action": self._last_action_info,
        }

    def render(self) -> Optional[str]:
        """Render current state."""
        if self.render_mode == "human":
            info = self._get_info()
            line = (
                f"Step {info['step']:3d} | "
                f"Detection {info['detection_level']:.2f}/{info['detection_threshold']:.1f} | "
                f"Discovered {info['discovered_count']}/{info['num_hosts']} | "
                f"Exploited {len(self._exploited_hosts)} | "
                f"Reward {info['total_reward']:.3f}"
            )
            print(line)
            return line
        elif self.render_mode == "json":
            import json
            return json.dumps(self._get_info(), default=str)
        return None

    def action_masks(self) -> np.ndarray:
        """Return current action mask (for MaskablePPO compatibility)."""
        return compute_action_mask(self._discovered, self._num_hosts)
