"""Tests for the observation vectorizer."""
import pytest
import numpy as np
from src.network_scanner.core.models import *


class TestObservationVectorizer:
    @pytest.fixture
    def vectorizer(self):
        from src.network_scanner.aggregator.vectorizer import ObservationVectorizer
        return ObservationVectorizer()

    def test_output_shape(self, vectorizer):
        obs = NetworkObservation(target_subnet="192.168.1.0/24")
        result = vectorizer.vectorize(obs)
        assert result.shape == (256, 47)
        assert result.dtype == np.float32

    def test_empty_network(self, vectorizer):
        obs = NetworkObservation(target_subnet="192.168.1.0/24")
        result = vectorizer.vectorize(obs)
        assert np.all(result == 0.0)

    def test_alive_host(self, vectorizer):
        host = HostObservation(ip="192.168.1.1", is_alive=True)
        obs = NetworkObservation(target_subnet="192.168.1.0/24", hosts=(host,))
        result = vectorizer.vectorize(obs)
        assert result[0, 0] == 1.0  # is_alive
        assert result[1, 0] == 0.0  # second host slot empty

    def test_port_bitmap(self, vectorizer):
        ports = (
            PortInfo(port=22, protocol=Protocol.TCP, state=PortState.OPEN),
            PortInfo(port=80, protocol=Protocol.TCP, state=PortState.OPEN),
            PortInfo(port=443, protocol=Protocol.TCP, state=PortState.OPEN),
        )
        host = HostObservation(ip="192.168.1.1", is_alive=True, ports=ports)
        obs = NetworkObservation(target_subnet="192.168.1.0/24", hosts=(host,))
        result = vectorizer.vectorize(obs)

        # Check that port bitmap has some 1s
        port_bitmap = result[0, 1:29]
        assert np.sum(port_bitmap) >= 3  # at least 3 ports marked

    def test_os_one_hot(self, vectorizer):
        host = HostObservation(
            ip="192.168.1.1", is_alive=True,
            os_guess=OSGuess(os_family=OSFamily.LINUX, confidence=0.9)
        )
        obs = NetworkObservation(target_subnet="192.168.1.0/24", hosts=(host,))
        result = vectorizer.vectorize(obs)

        # os_family one-hot at indices 29-34, LINUX should be index 29
        os_one_hot = result[0, 29:35]
        assert np.sum(os_one_hot) == 1.0  # exactly one active
        assert os_one_hot[0] == 1.0  # LINUX is first
        assert result[0, 35] == pytest.approx(0.9, abs=0.01)  # confidence

    def test_vuln_features(self, vectorizer, sample_host_observation):
        obs = NetworkObservation(
            target_subnet="192.168.1.0/24",
            hosts=(sample_host_observation,)
        )
        result = vectorizer.vectorize(obs)

        # max_cvss / 10
        assert result[0, 37] == pytest.approx(1.0, abs=0.01)  # 10.0/10.0
        # has_default_creds
        assert result[0, 39] == 1.0
        # has_ssl_issues (self-signed)
        assert result[0, 41] == 1.0

    def test_value_range(self, vectorizer, sample_host_observation):
        obs = NetworkObservation(
            target_subnet="192.168.1.0/24",
            hosts=(sample_host_observation,)
        )
        result = vectorizer.vectorize(obs)
        assert result.min() >= 0.0
        assert result.max() <= 1.0

    def test_max_hosts_cap(self, vectorizer):
        """Ensure more than 256 hosts are capped."""
        hosts = tuple(
            HostObservation(ip=f"10.0.{i//256}.{i%256}", is_alive=True)
            for i in range(300)
        )
        obs = NetworkObservation(target_subnet="10.0.0.0/16", hosts=hosts)
        result = vectorizer.vectorize(obs)
        assert result.shape == (256, 47)

    def test_service_features(self, vectorizer):
        ports = (
            PortInfo(port=22, protocol=Protocol.TCP, state=PortState.OPEN),
            PortInfo(port=80, protocol=Protocol.TCP, state=PortState.OPEN),
            PortInfo(port=3306, protocol=Protocol.TCP, state=PortState.OPEN),
            PortInfo(port=445, protocol=Protocol.TCP, state=PortState.OPEN),
            PortInfo(port=161, protocol=Protocol.UDP, state=PortState.OPEN),
        )
        host = HostObservation(ip="192.168.1.1", is_alive=True, ports=ports)
        obs = NetworkObservation(target_subnet="192.168.1.0/24", hosts=(host,))
        result = vectorizer.vectorize(obs)

        assert result[0, 42] == 1.0  # has_web (port 80)
        assert result[0, 43] == 1.0  # has_ssh (port 22)
        assert result[0, 44] == 1.0  # has_database (port 3306)
        assert result[0, 45] == 1.0  # has_smb (port 445)
        assert result[0, 46] == 1.0  # has_snmp (port 161)
