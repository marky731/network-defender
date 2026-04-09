"""Tests for scenario generator (Phase 2)."""

from network_scanner.rl.scenarios import (
    CURRICULUM_SCENARIOS,
    create_demo_scenario,
    create_scenario,
    generate_random_scenario,
)


class TestGenerateRandomScenario:
    def test_generates_correct_host_count(self):
        net = generate_random_scenario(num_hosts=8, seed=42)
        assert len(net.hosts) == 8

    def test_seed_reproducibility(self):
        net1 = generate_random_scenario(num_hosts=5, seed=99)
        net2 = generate_random_scenario(num_hosts=5, seed=99)
        ips1 = sorted(net1.hosts.keys())
        ips2 = sorted(net2.hosts.keys())
        assert ips1 == ips2
        for ip in ips1:
            h1, h2 = net1.hosts[ip], net2.hosts[ip]
            assert h1.os_family == h2.os_family
            assert len(h1.services) == len(h2.services)

    def test_hosts_have_services(self):
        net = generate_random_scenario(num_hosts=6, seed=42)
        for host in net.hosts.values():
            assert len(host.services) > 0

    def test_hosts_have_reachability(self):
        net = generate_random_scenario(num_hosts=6, seed=42)
        for host in net.hosts.values():
            assert len(host.reachable_hosts) > 0


class TestCurriculumScenarios:
    def test_all_levels_produce_valid_networks(self):
        for level in CURRICULUM_SCENARIOS:
            net = create_scenario(level=level, seed=42)
            expected = CURRICULUM_SCENARIOS[level]["num_hosts"]
            assert len(net.hosts) == expected

    def test_invalid_level_raises(self):
        import pytest
        with pytest.raises(ValueError):
            create_scenario(level="impossible")


class TestDemoScenario:
    def test_demo_has_6_hosts(self):
        net = create_demo_scenario()
        assert len(net.hosts) == 6

    def test_demo_subnet(self):
        net = create_demo_scenario()
        assert net.subnet == "172.30.0.0/24"

    def test_demo_has_high_value_targets(self):
        net = create_demo_scenario()
        high_value = [h for h in net.hosts.values() if h.value >= 2.0]
        assert len(high_value) >= 2

    def test_demo_full_mesh_reachability(self):
        net = create_demo_scenario()
        all_ips = set(net.hosts.keys())
        for host in net.hosts.values():
            assert host.reachable_hosts == all_ips - {host.ip}
