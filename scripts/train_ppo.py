"""Train a MaskablePPO agent on NetworkAttackEnv.

Usage:
    python3 scripts/train_ppo.py --timesteps 200000 --scenario tiny --num-envs 4
    python3 scripts/train_ppo.py --timesteps 500000 --scenario small --num-envs 8
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure src is importable when run as script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import numpy as np
from sb3_contrib import MaskablePPO
from sb3_contrib.common.wrappers import ActionMasker
from stable_baselines3.common.callbacks import (
    CallbackList,
    CheckpointCallback,
    EvalCallback,
)
from stable_baselines3.common.vec_env import SubprocVecEnv

from network_scanner.rl.env import NetworkAttackEnv
from network_scanner.rl.wrappers import ActionMaskWrapper


def mask_fn(env):
    """Extract action mask for sb3-contrib ActionMasker."""
    return env.action_masks()


def make_env(scenario_level: str, seed: int, rank: int):
    """Factory for creating wrapped environments."""
    def _init():
        env = NetworkAttackEnv(
            scenario_level=scenario_level,
            seed=seed + rank,
        )
        env = ActionMaskWrapper(env)
        env = ActionMasker(env, mask_fn)
        return env
    return _init


def make_eval_env(scenario_level: str, seed: int):
    """Create a single evaluation environment."""
    env = NetworkAttackEnv(
        scenario_level=scenario_level,
        seed=seed,
    )
    env = ActionMaskWrapper(env)
    env = ActionMasker(env, mask_fn)
    return env


def train(args):
    output_dir = Path(args.output_dir)
    log_dir = Path(args.log_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    print(f"Training config:")
    print(f"  Scenario:    {args.scenario}")
    print(f"  Timesteps:   {args.timesteps:,}")
    print(f"  Num envs:    {args.num_envs}")
    print(f"  LR:          {args.learning_rate}")
    print(f"  Batch size:  {args.batch_size}")
    print(f"  Seed:        {args.seed}")
    print()

    # 1. Parallel training environments
    vec_env = SubprocVecEnv(
        [make_env(args.scenario, args.seed, i) for i in range(args.num_envs)]
    )

    # 2. Evaluation environment
    eval_env = make_eval_env(args.scenario, seed=999)

    # 3. Create model
    model = MaskablePPO(
        "MultiInputPolicy",
        vec_env,
        learning_rate=args.learning_rate,
        n_steps=1024,
        batch_size=args.batch_size,
        n_epochs=10,
        gamma=0.99,
        gae_lambda=0.95,
        clip_range=0.2,
        ent_coef=0.01,
        vf_coef=0.5,
        max_grad_norm=0.5,
        verbose=1,
        tensorboard_log=str(log_dir),
        seed=args.seed,
    )

    # 4. Callbacks
    callbacks = CallbackList([
        EvalCallback(
            eval_env,
            best_model_save_path=str(output_dir / "best"),
            log_path=str(log_dir / "eval"),
            eval_freq=max(args.eval_freq // args.num_envs, 1),
            n_eval_episodes=20,
            deterministic=True,
        ),
        CheckpointCallback(
            save_freq=max(50000 // args.num_envs, 1),
            save_path=str(output_dir / "checkpoints"),
            name_prefix="ppo_network_attack",
        ),
    ])

    # 5. Train
    print("Starting training...")
    model.learn(
        total_timesteps=args.timesteps,
        callback=callbacks,
        progress_bar=True,
    )

    # 6. Save final model
    final_path = output_dir / "final" / "ppo_network_attack"
    final_path.parent.mkdir(parents=True, exist_ok=True)
    model.save(str(final_path))
    print(f"\nModel saved: {final_path}")

    vec_env.close()
    eval_env.close()


def main():
    parser = argparse.ArgumentParser(description="Train MaskablePPO on NetworkAttackEnv")
    parser.add_argument("--timesteps", type=int, default=200_000)
    parser.add_argument("--num-envs", type=int, default=4)
    parser.add_argument("--scenario", type=str, default="tiny",
                        choices=["tiny", "small", "medium", "large"])
    parser.add_argument("--learning-rate", type=float, default=3e-4)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--output-dir", type=str, default="./models")
    parser.add_argument("--log-dir", type=str, default="./logs")
    parser.add_argument("--eval-freq", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    train(args)


if __name__ == "__main__":
    main()
