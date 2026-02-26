"""Tests for service detection module."""
import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from src.network_scanner.core.models import PortInfo, PortState, Protocol, SSLInfo
from src.network_scanner.core.interfaces import ScanContext, ScanResult


class TestBannerGrabber:
    @pytest.mark.asyncio
    async def test_banner_grab_ssh(self, scan_context):
        from src.network_scanner.scanners.service_detector import BannerGrabber
        scanner = BannerGrabber()

        ports = [PortInfo(port=22, protocol=Protocol.TCP, state=PortState.OPEN)]

        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"SSH-2.0-OpenSSH_8.9p1\r\n")
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (mock_reader, mock_writer)
            result = await scanner.scan("127.0.0.1", scan_context, ports=ports)

        assert result.success == True
        if result.data:
            assert any("ssh" in p.service_name.lower() or "SSH" in p.banner for p in result.data)

    @pytest.mark.asyncio
    async def test_banner_grab_http(self, scan_context):
        from src.network_scanner.scanners.service_detector import BannerGrabber
        scanner = BannerGrabber()

        ports = [PortInfo(port=80, protocol=Protocol.TCP, state=PortState.OPEN)]

        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n")
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (mock_reader, mock_writer)
            result = await scanner.scan("127.0.0.1", scan_context, ports=ports)

        assert result.success == True


class TestSSLAnalyzer:
    @pytest.mark.asyncio
    async def test_ssl_analysis(self, scan_context):
        from src.network_scanner.scanners.service_detector import SSLAnalyzer
        scanner = SSLAnalyzer()

        ports = [PortInfo(port=443, protocol=Protocol.TCP, state=PortState.OPEN, tunnel="ssl")]

        # Mock SSL connection
        mock_cert = {
            "subject": ((("commonName", "test.local"),),),
            "issuer": ((("commonName", "test.local"),),),
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": "Dec 31 23:59:59 2030 GMT",
        }
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.getpeercert.return_value = mock_cert
        mock_ssl_sock.version.return_value = "TLSv1.2"
        mock_ssl_sock.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256)
        mock_ssl_sock.connect = MagicMock()
        mock_ssl_sock.close = MagicMock()
        mock_ssl_sock.__enter__ = MagicMock(return_value=mock_ssl_sock)
        mock_ssl_sock.__exit__ = MagicMock(return_value=False)

        with patch("ssl.create_default_context") as mock_ctx_factory:
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value = mock_ssl_sock
            mock_ctx_factory.return_value = mock_ctx
            with patch("socket.create_connection", return_value=MagicMock()):
                result = await scanner.scan("127.0.0.1", scan_context, ports=ports)

        assert result.success == True
