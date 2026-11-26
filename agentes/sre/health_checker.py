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
    Inspector SRE de sondas de salud (Liveness / Readiness) con checks reales:
    disco, carga, TCP y HTTP opcionales.
    """

    @staticmethod
    def check_disk(path: str = "/", min_free_mb: float = 100.0) -> Dict[str, Any]:
        """Espacio libre en path. Una ruta que no existe o no se puede consultar es una sonda fallida."""
        try:
            usage = shutil.disk_usage(path)
        except OSError as exc:
            return {
                "name": "disk",
                "ok": False,
                "path": path,
                "min_free_mb": min_free_mb,
                "detail": f"No se pudo consultar el disco en '{path}': {exc.strerror or exc}",
            }
        effective_path = path
        # En contenedores con / de solo lectura o Termux, '/' reporta 0 libre; consultar '.' si tiene espacio.
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
            "detail": "OK" if ok else f"Espacio libre {free_mb:.1f}MB < {min_free_mb}MB",
        }

    @staticmethod
    def check_tcp(host: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
        start = time.time()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                latency_ms = round((time.time() - start) * 1000, 2)
            return {
                "name": "tcp",
                "ok": True,
                "target": f"{host}:{port}",
                "latency_ms": latency_ms,
                "detail": "Conexión TCP OK",
            }
        except OSError as exc:
            return {
                "name": "tcp",
                "ok": False,
                "target": f"{host}:{port}",
                "latency_ms": round((time.time() - start) * 1000, 2),
                "detail": f"TCP falló: {exc}",
            }

    @staticmethod
    def check_http(url: str, timeout: float = 3.0, expect_status: int = 200) -> Dict[str, Any]:
        """
        GET a url y compara el código con expect_status. Un 4xx o un 5xx es una respuesta, no una
        caída: si es el código esperado (una sonda que exige 503 en mantenimiento, por ejemplo),
        la sonda pasa. Solo falla sin código cuando no hay respuesta.
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
                "detail": f"HTTP falló: {exc}",
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
        Agrega sondas de salud. Status:
          HEALTHY   — todas las sondas pasan
          DEGRADED  — falla alguna sonda externa (TCP o HTTP), pero el disco está bien
          UNHEALTHY — falla la sonda de disco, que es la base
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
