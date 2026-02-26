"""Fake network environment for testing scanners without real network."""

import asyncio
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field

@dataclass
class FakeHost:
    """Simulated network host."""
    ip: str
    mac: str = "00:11:22:33:44:55"
    is_alive: bool = True
    open_tcp_ports: Set[int] = field(default_factory=set)
    open_udp_ports: Set[int] = field(default_factory=set)
    banners: Dict[int, str] = field(default_factory=dict)  # port -> banner
    os_ttl: int = 64
    os_window: int = 29200
    hostname: str = ""

class FakeNetwork:
    """Simulated network with configurable hosts."""

    def __init__(self):
        self.hosts: Dict[str, FakeHost] = {}

    def add_host(self, host: FakeHost) -> None:
        self.hosts[host.ip] = host

    def is_alive(self, ip: str) -> bool:
        host = self.hosts.get(ip)
        return host.is_alive if host else False

    def get_open_tcp_ports(self, ip: str) -> Set[int]:
        host = self.hosts.get(ip)
        return host.open_tcp_ports if host else set()

    def get_banner(self, ip: str, port: int) -> str:
        host = self.hosts.get(ip)
        if host and port in host.banners:
            return host.banners[port]
        return ""

def create_test_network() -> FakeNetwork:
    """Create a standard test network with common services."""
    net = FakeNetwork()

    # Web server
    net.add_host(FakeHost(
        ip="192.168.1.10",
        mac="AA:BB:CC:DD:EE:01",
        open_tcp_ports={80, 443},
        banners={
            80: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n",
            443: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n",
        },
        os_ttl=64,
        os_window=29200,
        hostname="webserver",
    ))

    # SSH server
    net.add_host(FakeHost(
        ip="192.168.1.11",
        mac="AA:BB:CC:DD:EE:02",
        open_tcp_ports={22, 80},
        banners={
            22: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n",
            80: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n",
        },
        os_ttl=64,
        hostname="sshserver",
    ))

    # Database server
    net.add_host(FakeHost(
        ip="192.168.1.12",
        mac="AA:BB:CC:DD:EE:03",
        open_tcp_ports={3306, 6379},
        banners={
            3306: "J\x00\x00\x005.7.42\x00",
            6379: "+PONG\r\n",
        },
        os_ttl=64,
        hostname="dbserver",
    ))

    # Windows host
    net.add_host(FakeHost(
        ip="192.168.1.13",
        mac="AA:BB:CC:DD:EE:04",
        open_tcp_ports={135, 139, 445, 3389},
        banners={},
        os_ttl=128,
        os_window=65535,
        hostname="winhost",
    ))

    # Dead host
    net.add_host(FakeHost(
        ip="192.168.1.14",
        is_alive=False,
    ))

    return net
