# Network Defender

A reinforcement learning agent that learns network attack strategies through simulation. The agent discovers hosts, scans ports, detects services, finds vulnerabilities, and attempts exploits — all while managing detection risk.

## How It Works

The project simulates a network environment where an RL agent plays the role of a penetration tester. Each episode, the agent starts with zero knowledge and must strategically explore the network:

```
Agent sees: network state (256×47 matrix) + detection risk + remaining steps
Agent picks: one of 1,792 actions (7 action types × 256 possible hosts)
Environment returns: updated observation + reward + done signal
```

The agent earns rewards for discovering new information (hosts, ports, services, vulnerabilities) and successfully exploiting targets. It gets penalized for redundant actions and detection risk. The episode ends if the agent gets detected or completes all objectives.

A typical episode plays out like this:

1. The agent starts blind — it knows nothing about the network
2. It pings a host and discovers it's alive (+0.04 reward, small detection risk)
3. It scans the host's ports and finds MySQL running on 3306 (+0.01 reward)
4. It probes the service and identifies MySQL 5.7.42 (+0.02 reward)
5. It checks for known vulnerabilities and finds CVE-2020-14812 (+0.08 reward)
6. It attempts exploitation — success (+1.49 reward, but high detection noise)

Total: 5 steps, detection level 0.28 / 3.0, one host compromised. The agent could keep exploring other hosts for more reward, but each action increases the chance of getting caught.

## Project Structure

```
src/network_scanner/
├── core/                # Data models, config, interfaces
│   └── models.py        # HostObservation, NetworkObservation, CVEInfo, ...
├── scanners/            # Real network scanning modules (5 layers)
├── orchestrator/        # Scan pipeline coordination
├── aggregator/
│   ├── state_builder.py # Assembles scanner results → observation dataclasses
│   └── vectorizer.py    # Converts observations → (256, 47) numpy arrays
└── rl/                  # Reinforcement learning components
    ├── sim_network.py   # In-memory network simulation
    ├── actions.py       # Action space (7 types, masking, encoding)
    ├── rewards.py       # Reward calculation (11 reward components)
    ├── scenarios.py     # Scenario generator (4 curriculum levels)
    └── env.py           # NetworkAttackEnv (Gymnasium environment)

web/                     # FastAPI backend + frontend (SSE real-time updates)
lab/                     # Docker Compose test network
docs/                    # Phase specifications (Turkish)
tests/                   # 103 unit tests
```

## Architecture

### Observation Pipeline

```
SimulatedNetwork (ground truth)
        ↓
    _execute_action() → updates discovered dict (enriched format)
        ↓
    StateBuilder.build_host() → HostObservation (per host)
        ↓
    StateBuilder.build_network() → NetworkObservation
        ↓
    ObservationVectorizer.vectorize() → (256, 47) float32 matrix
        ↓
    Dict observation: {network_state, action_mask, agent_state}
```

### Observation Space

| Component | Shape | Description |
|-----------|-------|-------------|
| `network_state` | (256, 47) | Per-host feature matrix. 28-port bitmap, OS one-hot, CVSS scores, credential flags, etc. |
| `action_mask` | (1792,) | Binary mask — 1 if action is valid, 0 otherwise |
| `agent_state` | (2,) | [detection_level / threshold, steps_remaining / max_steps] |

### Action Space

7 action types, each targeting one of 256 possible hosts:

| Action | Prerequisite | Detection Noise | What It Does |
|--------|-------------|-----------------|--------------|
| DISCOVER_HOST | None | 0.01 | Ping a host to check if alive |
| PORT_SCAN | Host discovered | 0.05 | Find open ports |
| DETECT_SERVICES | Ports found | 0.03 | Identify running services |
| FINGERPRINT_OS | Ports found | 0.02 | Determine operating system |
| VULN_ASSESS | Services detected | 0.04 | Find CVE vulnerabilities |
| CHECK_CREDENTIALS | Services + credential ports | 0.08 | Try default credentials |
| EXPLOIT | Vulnerabilities found | 0.15 | Attempt exploitation |

Actions follow an attack chain — you can't scan ports without discovering the host first. The action mask enforces this automatically.

### Reward System

| Event | Reward |
|-------|--------|
| Step cost (every action) | -0.01 |
| New host discovered | +0.05 |
| Port found | +0.02 per port |
| Service detected | +0.03 per service |
| OS fingerprinted | +0.02 |
| Vulnerability found | +0.10 × (CVSS / 10) |
| Credential found | +0.15 |
| Exploit success | +0.50 × host_value |
| Exploit failure | -0.05 |
| Redundant action | -0.02 |
| Detection risk | -0.03 × noise_level |

The agent must balance information gathering (positive rewards) against detection risk (negative rewards). Aggressive scanning yields more information but increases the chance of getting caught.

### Scenarios

Four difficulty levels for curriculum learning:

| Level | Hosts | Description |
|-------|-------|-------------|
| tiny | 3 | Minimal network for fast iteration |
| small | 6 | Default training scenario |
| medium | 10 | Intermediate difficulty |
| large | 15 | Complex network topology |

Each scenario generates hosts with randomized services, vulnerabilities, and credentials from 8 service templates (Apache, Nginx, SSH, FTP, MySQL, PostgreSQL, Redis, MongoDB).

### Episode Lifecycle

```
reset() → empty observation, only DISCOVER_HOST actions available
   ↓
step() loop:
   agent picks action → env executes → reward + new observation
   ↓
Episode ends when:
   - Detection level ≥ threshold (agent caught — failure)
   - All high-value hosts exploited (objectives met — success)
   - Step count ≥ 300 (timeout — truncation)
```

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| **Network Scanner** | ✅ Done | 5-layer scan pipeline, Docker lab, FastAPI web UI |
| **Phase 1: Simulation** | ✅ Done | In-memory network model, action space, reward system |
| **Phase 2: Gymnasium Env** | ✅ Done | NetworkAttackEnv, scenarios, curriculum levels, 103 tests |
| **Phase 3: Training** | ⬜ Next | MaskablePPO training, wrappers, evaluation |
| **Phase 4: Web Integration** | ⬜ Planned | Live agent visualization, replay controls |

### Network Scanner (Foundation)

Real 5-layer network scanning pipeline with FastAPI web UI, SSE progress streaming, and a Docker Compose lab for testing against real services.

### Phase 1: Simulation

In-memory network model with hosts, services, vulnerabilities, and credentials. Defines 7 action types, action masking (attack chain enforcement), and an 11-component reward system balancing exploration against stealth.

### Phase 2: Gymnasium Environment

Standard Gymnasium wrapper making the simulation compatible with any RL algorithm. 4 curriculum difficulty levels, scenario generator, and deterministic replay via seeded RNG.

### Phase 3 (Next)

- MaskablePPO training via Stable-Baselines3
- ActionMaskWrapper, CurriculumWrapper, EpisodeRecorderWrapper
- TensorBoard logging and evaluation metrics
- CPU-optimized training (small MLP policy)

### Phase 4 (Planned)

- REST API endpoints for running trained agents
- Real-time SSE streaming of agent actions
- Network visualization with host color coding (grey → blue → red)
- Replay speed controls

## Running Tests

```bash
# All tests
python3 -m pytest tests/unit/ -q

# Specific test files
python3 -m pytest tests/unit/test_env.py -v
python3 -m pytest tests/unit/test_scenarios.py -v

# Gymnasium environment validation
python3 -c "
from network_scanner.rl.env import NetworkAttackEnv
from gymnasium.utils.env_checker import check_env
check_env(NetworkAttackEnv(scenario_level='tiny', seed=42), skip_render_check=True)
print('check_env PASSED')
"
```

## Tech Stack

- **Python 3.10+**
- **Gymnasium** — RL environment standard
- **NumPy** — Observation vectorization
- **FastAPI + Uvicorn** — Web backend with SSE
- **Scapy** — Real network scanning
- **Pytest** — 103 unit tests
