"""Utility functions: CIDR expansion, IP helpers."""

from __future__ import annotations

import ipaddress
import socket
from typing import List


def expand_cidr(cidr: str) -> List[str]:
    """Expand a CIDR notation into a list of host IP strings.

    Excludes network and broadcast addresses for networks larger than /31.
    """
    network = ipaddress.ip_network(cidr, strict=False)
    if network.prefixlen >= 31:
        return [str(ip) for ip in network]
    return [str(ip) for ip in network.hosts()]


def is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr: str) -> bool:
    """Check if a string is valid CIDR notation."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def resolve_hostname(hostname: str) -> str:
    """Resolve a hostname to an IP address. Returns empty string on failure."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return ""


def reverse_dns(ip: str) -> str:
    """Reverse DNS lookup. Returns empty string on failure."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ""


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private range."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def normalize_target(target: str) -> str:
    """Normalize a target string. If it's a plain IP, return as-is.
    If it's CIDR, return normalized form. If hostname, resolve to IP.
    """
    if is_valid_cidr(target) and "/" in target:
        return str(ipaddress.ip_network(target, strict=False))
    if is_valid_ip(target):
        return target
    resolved = resolve_hostname(target)
    return resolved if resolved else target
