"""Mock service implementations for testing."""

import asyncio
from typing import Dict, Optional


class MockTCPServer:
    """Simple mock TCP server that returns predefined banners."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, banner: str = ""):
        self.host = host
        self.port = port
        self.banner = banner.encode() if isinstance(banner, str) else banner
        self._server: Optional[asyncio.AbstractServer] = None

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        if self.banner:
            writer.write(self.banner)
            await writer.drain()
        # Read any incoming data (like probes)
        try:
            await asyncio.wait_for(reader.read(1024), timeout=1.0)
        except asyncio.TimeoutError:
            pass
        writer.close()

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        # Update port if it was 0 (auto-assigned)
        if self.port == 0:
            self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()


class MockServiceFactory:
    """Factory to create common mock services."""

    @staticmethod
    async def create_ssh_server(host="127.0.0.1", port=0):
        server = MockTCPServer(host, port, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")
        return await server.start()

    @staticmethod
    async def create_http_server(host="127.0.0.1", port=0):
        server = MockTCPServer(host, port, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n")
        return await server.start()

    @staticmethod
    async def create_ftp_server(host="127.0.0.1", port=0):
        server = MockTCPServer(host, port, "220 FTP Server Ready\r\n")
        return await server.start()

    @staticmethod
    async def create_redis_server(host="127.0.0.1", port=0):
        server = MockTCPServer(host, port, "+PONG\r\n")
        return await server.start()
