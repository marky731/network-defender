"""Generate randomized Docker Compose lab configurations for RL training.

Each generated lab has a different network topology with varying services,
allowing the RL agent to train on diverse network environments.
"""

import random
import yaml
from typing import Dict, List, Any

# Available service templates
SERVICE_TEMPLATES = {
    "web-apache": {
        "image": "httpd:2.4.41",
        "ports_internal": [80],
        "category": "web",
    },
    "web-nginx": {
        "image": "nginx:1.18.0",
        "ports_internal": [80, 443],
        "category": "web",
    },
    "ssh-server": {
        "image": "linuxserver/openssh-server:latest",
        "environment": {
            "PASSWORD_ACCESS": "true",
            "USER_NAME": "admin",
            "USER_PASSWORD": "admin",
        },
        "ports_internal": [2222],
        "category": "remote",
    },
    "ftp-server": {
        "image": "delfer/alpine-ftp-server:latest",
        "environment": {"USERS": "testuser|testpass"},
        "ports_internal": [21],
        "category": "file",
    },
    "mysql-server": {
        "image": "mysql:5.7",
        "environment": {"MYSQL_ROOT_PASSWORD": "root"},
        "ports_internal": [3306],
        "category": "database",
    },
    "postgres-server": {
        "image": "postgres:13",
        "environment": {"POSTGRES_PASSWORD": "postgres"},
        "ports_internal": [5432],
        "category": "database",
    },
    "redis-server": {
        "image": "redis:6.0",
        "ports_internal": [6379],
        "category": "cache",
    },
    "mongodb-server": {
        "image": "mongo:4.4",
        "ports_internal": [27017],
        "category": "database",
    },
}


def generate_random_lab(
    num_hosts: int = 6,
    seed: int = 42,
    subnet: str = "172.20.0",
    start_ip: int = 10,
) -> str:
    """Generate a randomized Docker Compose YAML for lab environments.

    Args:
        num_hosts: Number of hosts to include (3-15).
        seed: Random seed for reproducibility.
        subnet: Subnet prefix (first 3 octets).
        start_ip: Starting IP for the last octet.

    Returns:
        Docker Compose YAML string.
    """
    rng = random.Random(seed)
    num_hosts = max(3, min(15, num_hosts))

    service_names = list(SERVICE_TEMPLATES.keys())
    selected_services = rng.choices(service_names, k=num_hosts)

    compose: Dict[str, Any] = {
        "version": "3.8",
        "services": {},
        "networks": {
            "lab-net": {
                "driver": "bridge",
                "ipam": {
                    "config": [{"subnet": f"{subnet}.0/24"}]
                },
            }
        },
    }

    used_names: Dict[str, int] = {}
    for i, svc_key in enumerate(selected_services):
        template = SERVICE_TEMPLATES[svc_key]

        count = used_names.get(svc_key, 0)
        used_names[svc_key] = count + 1
        name = f"{svc_key}-{count}" if count > 0 else svc_key

        ip = f"{subnet}.{start_ip + i}"

        service_def: Dict[str, Any] = {
            "image": template["image"],
            "networks": {
                "lab-net": {"ipv4_address": ip}
            },
        }

        if "environment" in template:
            # Randomly decide if this host has weak credentials
            if rng.random() < 0.7:
                service_def["environment"] = template["environment"]

        compose["services"][name] = service_def

    return yaml.dump(compose, default_flow_style=False, sort_keys=False)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate random Docker Compose lab")
    parser.add_argument("--hosts", type=int, default=6, help="Number of hosts (3-15)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    args = parser.parse_args()

    result = generate_random_lab(num_hosts=args.hosts, seed=args.seed)

    if args.output:
        with open(args.output, "w") as f:
            f.write(result)
        print(f"Lab config written to {args.output}")
    else:
        print(result)
