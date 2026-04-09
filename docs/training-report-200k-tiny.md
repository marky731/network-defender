# Training Report — 200K Timestep, Tiny Scenario

## Training Configuration

| Parameter | Value |
|-----------|-------|
| Scenario | tiny (3 hosts, 2 vulnerabilities) |
| Algorithm | MaskablePPO (MultiInputPolicy) |
| Parallel envs | 4 (SubprocVecEnv) |
| Total timesteps | 200,704 |
| Duration | 11 min 44 sec |
| FPS | ~284 (CPU) |
| Learning rate | 3e-4 |
| Batch size | 64 |
| n_steps | 1024 |
| Seed | 42 |

## Learning Progress

| Timestep | Eval Reward | Episode Length | Explained Variance | Entropy |
|----------|-------------|---------------|--------------------|---------|
| 10K | -3.03 | 101 | -0.003 | -2.56 |
| 20K | -3.03 | 101 | 0.56 | -2.39 |
| 30K | -2.25 | 75 | 0.75 | -2.12 |
| 40K | -2.25 | 75 | 0.81 | -2.03 |
| 100K | -1.95 | 65 | 0.90 | -1.07 |
| 170K | -1.95 | 65 | 0.90 | -1.04 |
| 200K | -1.83 | 61 | 0.91 | -0.91 |

## Evaluation (100 Episodes)

| Metric | Result |
|--------|--------|
| Success Rate | 28% |
| Detection Rate | 73% |
| Avg Episode Length | 43.6 steps |
| Avg Reward | +0.71 |
| Discovery Rate | 92.3% |

## Action Distribution

| Action | Usage |
|--------|-------|
| DISCOVER_HOST | 15.6% |
| PORT_SCAN | 8.0% |
| DETECT_SERVICES | 13.8% |
| FINGERPRINT_OS | 0.1% |
| VULN_ASSESS | 27.5% |
| CHECK_CREDENTIALS | 15.8% |
| EXPLOIT | 19.3% |

## Analysis

**Learned:** The agent discovered the full attack chain (discover → scan → detect → vuln_assess → exploit). 92% host discovery rate. Correctly ignores FINGERPRINT_OS since it's not required for exploitation.

**Weakness:** 73% detection rate. The agent is too aggressive — frequent use of high-noise actions (EXPLOIT 19%, CHECK_CREDENTIALS 16%) pushes detection above threshold. Longer training could teach stealth/speed balance.

**Baseline comparison:** Random agent reward ≈ -9.0, trained agent reward = +0.71. Clear learning signal.
