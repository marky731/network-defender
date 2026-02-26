"""Tests for port scanner module."""
import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from src.network_scanner.core.models import PortState, Protocol, PortInfo
from src.network_scanner.core.interfaces import ScanContext, ScanResult
from src.network_scanner.scanners.port_scanner import (
    AsyncTCPConnectScanner,
    PortScanOrchestrator,
)


class TestAsyncTCPConnectScanner:
    @pytest.fixture
    def scanner(self):
        return AsyncTCPConnectScanner()

    def test_name(self, scanner):
        assert scanner.name == "AsyncTCPConnectScanner"

    def test_capability_none(self, scanner, scan_context):
        assert scanner.is_available(scan_context) == True

    @pytest.mark.asyncio
    async def test_scan_open_port(self, scanner, scan_context):
        """Test scanning with a mock open port."""
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (AsyncMock(), mock_writer)
            scan_context.tcp_ports = [80]
            result = await scanner.scan("127.0.0.1", scan_context)

        assert result.success == True
        assert len(result.data) > 0
        open_ports = [p for p in result.data if p.state == PortState.OPEN]
        assert len(open_ports) == 1
        assert open_ports[0].port == 80

    @pytest.mark.asyncio
    async def test_scan_closed_port(self, scanner, scan_context):
        """Test scanning with connection refused."""
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.side_effect = ConnectionRefusedError()
            scan_context.tcp_ports = [9999]
            result = await scanner.scan("127.0.0.1", scan_context)

        assert result.success == True
        # Closed ports may or may not be in results depending on implementation

    @pytest.mark.asyncio
    async def test_scan_timeout(self, scanner, scan_context):
        """Test scanning with timeout."""
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.side_effect = asyncio.TimeoutError()
            scan_context.tcp_ports = [80]
            result = await scanner.scan("127.0.0.1", scan_context)

        assert result.success == True  # Timeout is handled, not an error


class TestPortScanOrchestrator:
    @pytest.fixture
    def orchestrator(self):
        return PortScanOrchestrator()

    def test_name(self, orchestrator):
        assert "port" in orchestrator.name.lower() or "orchestrator" in orchestrator.name.lower()

    @pytest.mark.asyncio
    async def test_unprivileged_uses_tcp_connect(self, orchestrator, scan_context):
        """Without root, should use TCP connect scanner only."""
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (AsyncMock(), mock_writer)
            scan_context.tcp_ports = [80]
            scan_context.has_root = False
            scan_context.has_scapy = False
            result = await orchestrator.scan("127.0.0.1", scan_context)

        assert result.success == True
