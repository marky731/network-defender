"""Tests for the scan pipeline orchestrator."""
import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from src.network_scanner.core.models import *
from src.network_scanner.core.config import ScanConfig
from src.network_scanner.core.interfaces import ScanContext, ScanResult


class TestScanPipeline:
    @pytest.mark.asyncio
    async def test_pipeline_creation(self):
        from src.network_scanner.orchestrator.scan_pipeline import ScanPipeline
        config = ScanConfig(profile=ScanProfile.QUICK)
        pipeline = ScanPipeline(config)
        assert pipeline is not None

    @pytest.mark.asyncio
    async def test_pipeline_single_host(self):
        """Test pipeline with mocked scanners for a single host."""
        from src.network_scanner.orchestrator.scan_pipeline import ScanPipeline
        config = ScanConfig(profile=ScanProfile.QUICK, timeout=2.0)
        pipeline = ScanPipeline(config)

        # Mock all the orchestrators
        with patch.object(pipeline, '_scan_single_host', new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = HostObservation(
                ip="127.0.0.1",
                is_alive=True,
                ports=(PortInfo(port=80, protocol=Protocol.TCP, state=PortState.OPEN),),
            )
            with patch("src.network_scanner.orchestrator.scan_pipeline.detect_capabilities") as mock_cap:
                mock_cap.return_value = {"has_root": False, "has_scapy": False}
                # Mock host discovery to return the target as alive
                with patch("src.network_scanner.orchestrator.scan_pipeline.HostDiscoveryOrchestrator") as mock_hd:
                    mock_hd_instance = MagicMock()
                    mock_hd_instance.scan = AsyncMock(return_value=ScanResult(
                        scanner_name="host_discovery",
                        success=True,
                        data={"is_alive": True, "mac": "", "method_used": "tcp_ping"},
                    ))
                    mock_hd.return_value = mock_hd_instance

                    result = await pipeline.run("127.0.0.1")

        assert isinstance(result, NetworkObservation)
