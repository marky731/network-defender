"""FastAPI web backend for Network Defender.

Provides REST + SSE endpoints that wrap the existing ScanPipeline,
adding real-time progress tracking for the browser frontend.

Usage:
    python web/app.py          # starts on http://0.0.0.0:8000
"""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Add project ``src/`` to the Python path so we can import the scanner
# package without installing it.
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from network_scanner.core.config import ScanConfig, ScanProfile  # noqa: E402
from network_scanner.core.interfaces import ScanContext  # noqa: E402
from network_scanner.core.models import (  # noqa: E402
    HostObservation,
    PortInfo,
    PortState,
    SSLInfo,
)
from network_scanner.core.utils import expand_cidr, is_valid_cidr  # noqa: E402
from network_scanner.orchestrator.scan_pipeline import ScanPipeline  # noqa: E402
from network_scanner.orchestrator.capability import detect_capabilities  # noqa: E402
from network_scanner.scanners.host_discovery import HostDiscoveryOrchestrator  # noqa: E402
from network_scanner.scanners.port_scanner import PortScanOrchestrator  # noqa: E402
from network_scanner.scanners.service_detector import ServiceDetectionOrchestrator  # noqa: E402
from network_scanner.scanners.os_fingerprinter import OSFingerprintOrchestrator  # noqa: E402
from network_scanner.scanners.vuln_assessor import VulnAssessmentOrchestrator  # noqa: E402
from network_scanner.aggregator.state_builder import StateBuilder  # noqa: E402
from network_scanner.aggregator.vectorizer import ObservationVectorizer  # noqa: E402
from network_scanner.main import observation_to_dict  # noqa: E402

# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------
app = FastAPI(title="Network Defender")

# In-memory scan store.  One scan at a time for the thesis demo.
scans: Dict[str, dict] = {}
active_scan_id: Optional[str] = None

LAYER_NAMES = {
    1: "Host Discovery",
    2: "Port Scanning",
    3: "Service Detection",
    4: "OS Fingerprinting",
    5: "Vulnerability Assessment",
}

PROFILES = {
    "quick": {
        "name": "Quick Scan",
        "description": "Fast scan \u2014 top 20 TCP + 10 UDP ports",
        "timeout": 3.0,
    },
    "moderate": {
        "name": "Moderate Scan",
        "description": "Balanced \u2014 ~100 TCP + ~20 UDP ports",
        "timeout": 5.0,
    },
    "deep": {
        "name": "Deep Scan",
        "description": "Comprehensive \u2014 1\u20131024 + high ports TCP + ~30 UDP",
        "timeout": 10.0,
    },
}


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------
class ScanRequest(BaseModel):
    target: str
    profile: str = "quick"


# ---------------------------------------------------------------------------
# ProgressTrackingPipeline
# ---------------------------------------------------------------------------
class ProgressTrackingPipeline(ScanPipeline):
    """ScanPipeline subclass that emits progress events to a shared list.

    The list is polled by the SSE endpoint so the browser can display
    real-time layer and per-host progress.
    """

    def __init__(self, config: ScanConfig, progress: list) -> None:
        super().__init__(config)
        self._progress = progress

    def _emit(self, event: dict) -> None:
        self._progress.append(event)

    # -- override run() to emit layer-level events --------------------------

    async def run(self, target: str):
        scan_start = datetime.now(timezone.utc)

        caps = detect_capabilities()
        context = ScanContext(
            profile=self.config.profile,
            timeout=self.config.timeout,
            max_concurrency=self.config.max_concurrency,
            tcp_ports=self.config.get_tcp_ports(),
            udp_ports=self.config.get_udp_ports(),
            has_root=caps["has_root"],
            has_scapy=caps["has_scapy"],
        )

        if is_valid_cidr(target) and "/" in target:
            ip_list = expand_cidr(target)
        else:
            ip_list = [target]

        self._emit({"type": "info", "total_targets": len(ip_list)})

        # Layer 1 -- Host Discovery -----------------------------------------
        self._emit({
            "type": "layer", "layer": 1,
            "name": LAYER_NAMES[1], "status": "started",
        })

        disco = HostDiscoveryOrchestrator()
        results = await asyncio.gather(
            *[disco.scan(ip, context) for ip in ip_list],
            return_exceptions=True,
        )

        alive_hosts: List[dict] = []
        for ip, res in zip(ip_list, results):
            if isinstance(res, Exception):
                continue
            if res.success and res.data and res.data.get("is_alive"):
                alive_hosts.append({
                    "ip": ip,
                    "mac": res.data.get("mac", ""),
                })

        self._emit({
            "type": "layer", "layer": 1,
            "name": LAYER_NAMES[1], "status": "completed",
            "detail": f"{len(alive_hosts)} alive hosts",
        })

        # Layers 2-5 per host (concurrency-limited) ------------------------
        sem = asyncio.Semaphore(10)
        host_obs: List[HostObservation] = []

        async def _scan(h: dict) -> HostObservation:
            async with sem:
                return await self._tracked_host(h, context)

        if alive_hosts:
            res_list = await asyncio.gather(
                *[_scan(h) for h in alive_hosts],
                return_exceptions=True,
            )
            for h, r in zip(alive_hosts, res_list):
                if isinstance(r, Exception):
                    self.logger.error("Scan failed for %s: %s", h["ip"], r)
                    host_obs.append(
                        StateBuilder.build_host(
                            ip=h["ip"], is_alive=True,
                            mac=h.get("mac", ""),
                        )
                    )
                else:
                    host_obs.append(r)

        alive_ips = {h["ip"] for h in alive_hosts}
        for ip in ip_list:
            if ip not in alive_ips:
                host_obs.append(StateBuilder.build_host(ip=ip, is_alive=False))

        scan_end = datetime.now(timezone.utc)
        observation = StateBuilder.build_network(
            target_subnet=target,
            hosts=host_obs,
            profile=self.config.profile,
            scan_start=scan_start,
            scan_end=scan_end,
        )

        self._emit({"type": "done", "status": "completed"})
        return observation

    # -- per-host scanning with progress events -----------------------------

    async def _tracked_host(
        self, host_info: dict, ctx: ScanContext,
    ) -> HostObservation:
        ip = host_info["ip"]
        mac = host_info.get("mac", "")

        # Layer 2 -- Port Scanning
        self._emit({
            "type": "host_layer", "ip": ip, "layer": 2,
            "name": LAYER_NAMES[2], "status": "started",
        })
        pr = await PortScanOrchestrator().scan(ip, ctx)
        ports: List[PortInfo] = pr.data if (pr.success and pr.data) else []
        open_ports = [p for p in ports if p.state == PortState.OPEN]
        self._emit({
            "type": "host_layer", "ip": ip, "layer": 2,
            "name": LAYER_NAMES[2], "status": "completed",
            "detail": f"{len(open_ports)} open ports",
        })

        # Layer 3 -- Service Detection
        self._emit({
            "type": "host_layer", "ip": ip, "layer": 3,
            "name": LAYER_NAMES[3], "status": "started",
        })
        enriched: List[PortInfo] = list(ports)
        ssl_infos: List[SSLInfo] = []
        if open_ports:
            enriched, ssl_infos = (
                await ServiceDetectionOrchestrator()
                .detect_services(ip, open_ports, ctx)
            )
            seen = {p.port for p in enriched}
            for p in ports:
                if p.port not in seen:
                    enriched.append(p)
        self._emit({
            "type": "host_layer", "ip": ip, "layer": 3,
            "name": LAYER_NAMES[3], "status": "completed",
        })

        # Layer 4 -- OS Fingerprinting
        self._emit({
            "type": "host_layer", "ip": ip, "layer": 4,
            "name": LAYER_NAMES[4], "status": "started",
        })
        os_guess = await OSFingerprintOrchestrator().fingerprint(
            ip, enriched, ctx,
        )
        self._emit({
            "type": "host_layer", "ip": ip, "layer": 4,
            "name": LAYER_NAMES[4], "status": "completed",
            "detail": os_guess.os_family.value,
        })

        # Layer 5 -- Vulnerability Assessment
        self._emit({
            "type": "host_layer", "ip": ip, "layer": 5,
            "name": LAYER_NAMES[5], "status": "started",
        })
        cves, creds, misconfigs = await VulnAssessmentOrchestrator().assess(
            ip, enriched, ssl_infos, ctx,
        )
        self._emit({
            "type": "host_layer", "ip": ip, "layer": 5,
            "name": LAYER_NAMES[5], "status": "completed",
            "detail": f"{len(cves)} CVEs, {len(creds)} creds, {len(misconfigs)} misconfigs",
        })

        return StateBuilder.build_host(
            ip=ip, is_alive=True, mac=mac,
            ports=enriched, ssl_info=ssl_infos, os_guess=os_guess,
            cves=cves, credential_results=creds,
            misconfigurations=misconfigs,
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
async def index():
    """Serve the single-page frontend."""
    return FileResponse(
        Path(__file__).parent / "index.html",
        media_type="text/html",
    )


@app.get("/api/profiles")
async def profiles():
    """Return available scan profiles."""
    return PROFILES


@app.post("/api/scans")
async def create_scan(req: ScanRequest):
    """Start a new scan. Only one scan at a time."""
    global active_scan_id

    if active_scan_id and scans.get(active_scan_id, {}).get("status") == "running":
        raise HTTPException(409, "A scan is already running")

    if req.profile not in PROFILES:
        raise HTTPException(400, f"Invalid profile: {req.profile}")

    scan_id = uuid.uuid4().hex[:8]
    progress: list = []

    scans[scan_id] = {
        "status": "running",
        "target": req.target,
        "profile": req.profile,
        "progress": progress,
        "result": None,
        "vector": None,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    active_scan_id = scan_id

    config = ScanConfig(
        profile=ScanProfile(req.profile),
        timeout=PROFILES[req.profile]["timeout"],
    )
    pipeline = ProgressTrackingPipeline(config, progress)

    async def _run():
        global active_scan_id
        try:
            obs = await pipeline.run(req.target)
            scans[scan_id]["result"] = observation_to_dict(obs)
            vec = ObservationVectorizer().vectorize(obs)
            scans[scan_id]["vector"] = vec.tolist()
            scans[scan_id]["status"] = "completed"
        except Exception as exc:
            scans[scan_id]["status"] = "error"
            scans[scan_id]["error"] = str(exc)
            progress.append({"type": "error", "message": str(exc)})
        finally:
            active_scan_id = None

    asyncio.create_task(_run())
    return {"scan_id": scan_id}


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Return scan status and results."""
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    s = scans[scan_id]
    return {
        "scan_id": scan_id,
        "status": s["status"],
        "target": s["target"],
        "profile": s["profile"],
        "started_at": s["started_at"],
        "result": s.get("result"),
        "error": s.get("error"),
    }


@app.get("/api/scans/{scan_id}/progress")
async def scan_progress(scan_id: str):
    """SSE stream of scan progress events."""
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")

    scan = scans[scan_id]
    progress = scan["progress"]

    async def generate():
        idx = 0
        while True:
            # Drain all events that have arrived since last check.
            while idx < len(progress):
                evt = progress[idx]
                yield f"data: {json.dumps(evt)}\n\n"
                idx += 1
                if evt.get("type") in ("done", "error"):
                    return

            # If the scan finished between checks, flush remaining events.
            if scan["status"] in ("completed", "error"):
                await asyncio.sleep(0.15)
                while idx < len(progress):
                    yield f"data: {json.dumps(progress[idx])}\n\n"
                    idx += 1
                return

            # Keep-alive comment so the browser knows the stream is alive.
            yield ": keepalive\n\n"
            await asyncio.sleep(0.3)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/scans/{scan_id}/vector")
async def get_vector(scan_id: str):
    """Return the vectorized observation matrix (256x47)."""
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    s = scans[scan_id]
    if s["status"] != "completed":
        raise HTTPException(400, "Scan not completed yet")
    return {"shape": [256, 47], "data": s.get("vector", [])}


# ---------------------------------------------------------------------------
# Run with:  python web/app.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
