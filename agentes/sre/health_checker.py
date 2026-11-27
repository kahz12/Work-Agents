import os
import shutil
import socket
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .. import __version__


class SystemHealthChecker:
    """
    Liveness/readiness probes that check real resources: disk and load always, plus an
    optional TCP port and HTTP URL.
    """

    @staticmethod
    def check_disk(path: str = "/", min_free_mb: float = 100.0) -> Dict[str, Any]:
        """Free space at path. A path that does not exist or cannot be queried is a failed probe."""
        try:
            usage = shutil.disk_usage(path)
        except OSError as exc:
            return {
                "name": "disk",
                "ok": False,
                "path": path,
                "min_free_mb": min_free_mb,
                "detail": f"Could not query the disk at '{path}': {exc.strerror or exc}",
            }
        effective_path = path
        # In containers with a read-only root, and on Termux, '/' reports 0 bytes free even though
        # the working directory has space; fall back to '.' in that case.
        if path == "/" and usage.free == 0:
            cwd_path = os.path.abspath(".")
            cwd_usage = shutil.disk_usage(cwd_path)
            if cwd_usage.free > 0:
                usage = cwd_usage
                effective_path = cwd_path
        free_mb = usage.free / (1024 * 1024)
        ok = free_mb >= min_free_mb
        return {
            "name": "disk",
            "ok": ok,
            "path": effective_path,
            "free_mb": round(free_mb, 2),
            "total_mb": round(usage.total / (1024 * 1024), 2),
            "min_free_mb": min_free_mb,
            "detail": "OK" if ok else f"Free space {free_mb:.1f}MB < {min_free_mb}MB",
        }

    @staticmethod
    def check_tcp(host: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
        """Open (and immediately close) a TCP connection and report whether it succeeded, with latency."""
        start = time.time()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                latency_ms = round((time.time() - start) * 1000, 2)
            return {
                "name": "tcp",
                "ok": True,
                "target": f"{host}:{port}",
                "latency_ms": latency_ms,
                "detail": "TCP connection OK",
            }
        except OSError as exc:
            return {
                "name": "tcp",
                "ok": False,
                "target": f"{host}:{port}",
                "latency_ms": round((time.time() - start) * 1000, 2),
                "detail": f"TCP failed: {exc}",
            }

    @staticmethod
    def check_http(url: str, timeout: float = 3.0, expect_status: int = 200) -> Dict[str, Any]:
        """
        GET url and compare the status code with expect_status. A 4xx or 5xx is still a response,
        not an outage: when it is the expected code (a probe that requires 503 during maintenance,
        for example) the probe passes. status_code is None only when there was no response at all.
        """
        start = time.time()
        try:
            req = urllib.request.Request(url, method="GET", headers={"User-Agent": f"agentes-sre-health/{__version__}"})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    status = getattr(resp, "status", 200)
                    body_len = len(resp.read(1024))
            except urllib.error.HTTPError as exc:
                status = exc.code
                body_len = len(exc.read(1024))
            latency_ms = round((time.time() - start) * 1000, 2)
            ok = status == expect_status
            return {
                "name": "http",
                "ok": ok,
                "url": url,
                "status_code": status,
                "latency_ms": latency_ms,
                "bytes_sampled": body_len,
                "detail": "HTTP OK" if ok else f"Status {status} != {expect_status}",
            }
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return {
                "name": "http",
                "ok": False,
                "url": url,
                "status_code": None,
                "latency_ms": round((time.time() - start) * 1000, 2),
                "detail": f"HTTP failed: {exc}",
            }

    @staticmethod
    def check_health(
        *,
        disk_path: str = "/",
        min_free_mb: float = 100.0,
        tcp_host: Optional[str] = None,
        tcp_port: Optional[int] = None,
        http_url: Optional[str] = None,
        http_expect_status: int = 200,
    ) -> Dict[str, Any]:
        """
        Run the probes and aggregate them. Status:
          HEALTHY   — every probe passes
          DEGRADED  — an external probe (TCP or HTTP) fails, but the disk is fine
          UNHEALTHY — the disk probe, which everything else depends on, fails
        """
        start_time = time.time()
        checks: List[Dict[str, Any]] = []

        disk = SystemHealthChecker.check_disk(disk_path, min_free_mb)
        checks.append(disk)

        load_avg = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)
        checks.append({
            "name": "load",
            "ok": True,
            "load_1m": load_avg[0],
            "detail": f"loadavg 1m={load_avg[0]}",
        })

        if tcp_host is not None and tcp_port is not None:
            checks.append(SystemHealthChecker.check_tcp(tcp_host, tcp_port))

        if http_url:
            checks.append(SystemHealthChecker.check_http(http_url, expect_status=http_expect_status))

        failed = [c for c in checks if not c.get("ok", True)]
        if not failed:
            status = "HEALTHY"
        elif any(c.get("name") == "disk" for c in failed):
            status = "UNHEALTHY"
        else:
            status = "DEGRADED"

        duration = round((time.time() - start_time) * 1000, 2)
        return {
            "status": status,
            "probe_duration_ms": duration,
            "system_load_avg_1m": load_avg[0],
            "python_version": sys.version.split()[0],
            "checks": checks,
            "failed_checks": [c["name"] for c in failed],
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
