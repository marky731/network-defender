"""Evaluate a trained MaskablePPO agent on NetworkAttackEnv.

Usage:
    python3 scripts/evaluate_agent.py --model ./models/final/ppo_network_attack --episodes 100
    python3 scripts/evaluate_agent.py --model ./models/best/best_model --scenario small --render
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import numpy as np
from sb3_contrib import MaskablePPO
from sb3_contrib.common.wrappers import ActionMasker

from network_scanner.rl.actions import ActionType, decode_action
from network_scanner.rl.env import NetworkAttackEnv
from network_scanner.rl.wrappers import ActionMaskWrapper


def mask_fn(env):
    return env.action_masks()


def evaluate(args):
    # Load model
    model = MaskablePPO.load(args.model)
    print(f"Model loaded: {args.model}")

    # Create environment
    env = NetworkAttackEnv(
        scenario_level=args.scenario,
        seed=args.seed,
        render_mode="human" if args.render else None,
    )
    env = ActionMaskWrapper(env)
    env = ActionMasker(env, mask_fn)

    # Run episodes
    results = []
    action_counts = Counter()
    total_actions = 0

    for ep in range(args.episodes):
        obs, info = env.reset(seed=args.seed + ep)
        episode_reward = 0.0
        steps = 0
        done = False

        while not done:
            action, _ = model.predict(obs, deterministic=True, action_masks=env.action_masks())
            obs, reward, terminated, truncated, info = env.step(action)
            episode_reward += reward
            steps += 1

            action_type, _ = decode_action(int(action))
            action_counts[action_type.name] += 1
            total_actions += 1

            if args.render:
                env.render()

            done = terminated or truncated

        results.append({
            "reward": episode_reward,
            "steps": steps,
            "success": info.get("objectives_met", False),
            "detected": info.get("detection_level", 0) >= info.get("detection_threshold", 3.0),
            "discovered": info.get("discovered_count", 0),
            "num_hosts": info.get("num_hosts", 0),
            "exploited": len(info.get("exploited_hosts", [])),
        })

    env.close()

    # Print results
    successes = sum(1 for r in results if r["success"])
    detected = sum(1 for r in results if r["detected"])
    avg_reward = np.mean([r["reward"] for r in results])
    avg_steps = np.mean([r["steps"] for r in results])
    avg_discovered = np.mean([r["discovered"] / max(r["num_hosts"], 1) for r in results])

    print(f"\n{'=' * 55}")
    print(f" Evaluation Results ({args.episodes} episodes, scenario={args.scenario})")
    print(f"{'=' * 55}")
    print(f"  Success Rate:       {successes / args.episodes * 100:.1f}%")
    print(f"  Detection Rate:     {detected / args.episodes * 100:.1f}%")
    print(f"  Avg Episode Length:  {avg_steps:.1f} steps")
    print(f"  Avg Reward:          {avg_reward:.2f}")
    print(f"  Discovery Rate:      {avg_discovered * 100:.1f}%")
    print(f"\n  Action Distribution:")
    for action_name in ActionType.__members__:
        count = action_counts.get(action_name, 0)
        pct = count / max(total_actions, 1) * 100
        print(f"    {action_name:20s} {pct:5.1f}%")
    print(f"{'=' * 55}")


def main():
    parser = argparse.ArgumentParser(description="Evaluate trained agent")
    parser.add_argument("--model", type=str, required=True)
    parser.add_argument("--scenario", type=str, default="tiny",
                        choices=["tiny", "small", "medium", "large"])
    parser.add_argument("--episodes", type=int, default=100)
    parser.add_argument("--seed", type=int, default=123)
    parser.add_argument("--render", action="store_true")
    args = parser.parse_args()
    evaluate(args)


if __name__ == "__main__":
    main()
