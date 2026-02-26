"""CLI entry point for the network scanner."""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import enum
import json
import sys
from datetime import datetime

from .core.models import NetworkObservation, ScanProfile
from .core.config import ScanConfig
from .core.logging_setup import setup_logger
from .orchestrator.scan_pipeline import ScanPipeline
from .aggregator.vectorizer import ObservationVectorizer


# ─── Argument Parsing ───────────────────────────────────────────────────────


def parse_args(argv=None):
    """Parse command-line arguments.

    Parameters
    ----------
    argv:
        Argument list (defaults to ``sys.argv[1:]`` when *None*).
    """
    parser = argparse.ArgumentParser(
        description="Network Scanner - Observation layer for RL agents"
    )
    parser.add_argument(
        "--target", "-t", required=True,
        help="Target IP or CIDR (e.g., 192.168.1.0/24)",
    )
    parser.add_argument(
        "--profile", "-p", choices=["quick", "moderate", "deep"],
        default="quick", help="Scan profile",
    )
    parser.add_argument(
        "--timeout", type=float, default=5.0,
        help="Per-operation timeout in seconds",
    )
    parser.add_argument(
        "--concurrency", type=int, default=100,
        help="Max concurrent operations",
    )
    parser.add_argument(
        "--output", "-o", help="Output file path (JSON)",
    )
    parser.add_argument(
        "--vectorize", "-v", action="store_true",
        help="Output as numpy vector info",
    )
    parser.add_argument(
        "--log-file", help="Log file path",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Verbose output",
    )
    return parser.parse_args(argv)


# ─── Serialisation ──────────────────────────────────────────────────────────


def observation_to_dict(obs: NetworkObservation) -> dict:
    """Convert a NetworkObservation to a JSON-serialisable dict.

    Recursively converts dataclasses, enums, tuples and datetimes.
    """

    def to_dict(obj):
        if dataclasses.is_dataclass(obj):
            result = {}
            for f in dataclasses.fields(obj):
                val = getattr(obj, f.name)
                result[f.name] = to_dict(val)
            return result
        elif isinstance(obj, (list, tuple)):
            return [to_dict(item) for item in obj]
        elif isinstance(obj, enum.Enum):
            return obj.value
        elif isinstance(obj, datetime):
            return obj.isoformat()
        return obj

    return to_dict(obs)


# ─── Main ───────────────────────────────────────────────────────────────────


def main(argv=None):
    """CLI entry point."""
    args = parse_args(argv)

    setup_logger(
        log_file=args.log_file,
        json_format=True,
        level=10 if args.verbose else 20,  # DEBUG if verbose
    )

    config = ScanConfig(
        profile=ScanProfile(args.profile),
        timeout=args.timeout,
        max_concurrency=args.concurrency,
    )

    pipeline = ScanPipeline(config)

    print(f"Starting scan: target={args.target}, profile={args.profile}")

    observation = asyncio.run(pipeline.run(args.target))

    # ── Print summary ────────────────────────────────────────────────────
    alive_hosts = [h for h in observation.hosts if h.is_alive]
    print(f"\nScan complete. Found {len(alive_hosts)} alive hosts.")

    for host in alive_hosts:
        open_ports = [p for p in host.ports if p.state.value == "open"]
        parts = [f"  {host.ip}: {len(open_ports)} open ports"]
        if host.os_guess.os_family.value != "unknown":
            os_label = host.os_guess.os_detail or host.os_guess.os_family.value
            parts.append(f"OS: {os_label}")
        if host.cves:
            parts.append(f"{len(host.cves)} CVEs")
        cred_hits = [c for c in host.credential_results if c.success]
        if cred_hits:
            parts.append(f"{len(cred_hits)} default creds!")
        print(", ".join(parts))

    # ── JSON output ──────────────────────────────────────────────────────
    result_dict = observation_to_dict(observation)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result_dict, f, indent=2, default=str)
        print(f"\nResults saved to {args.output}")

    # ── Vectorisation ────────────────────────────────────────────────────
    if args.vectorize:
        import numpy as np

        vectorizer = ObservationVectorizer()
        vec = vectorizer.vectorize(observation)
        print(f"\nVector shape: {vec.shape}, dtype: {vec.dtype}")
        print(f"Value range: [{vec.min():.4f}, {vec.max():.4f}]")
        if args.output:
            np_path = args.output.replace(".json", ".npy")
            np.save(np_path, vec)
            print(f"Vector saved to {np_path}")


if __name__ == "__main__":
    main()
