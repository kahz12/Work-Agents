import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Optional


class PrometheusExporter:
    """
    Prometheus metrics in the text exposition format, plus an HTTP server for /metrics and
    /healthz. Counters are class-level and guarded by a lock, so handler threads share them.
    """

    _lock = threading.Lock()
    _start_time = time.time()
    _requests_total = 0
    _errors_total = 0

    @classmethod
    def reset(cls) -> None:
        """Reset the counters and the start time."""
        with cls._lock:
            cls._start_time = time.time()
            cls._requests_total = 0
            cls._errors_total = 0

    @classmethod
    def increment(cls, *, error: bool = False) -> None:
        """Count one request, and one error when error=True."""
        with cls._lock:
            cls._requests_total += 1
            if error:
                cls._errors_total += 1

    @classmethod
    def generate_metrics(
        cls,
        requests_total: Optional[int] = None,
        errors_total: Optional[int] = None,
        uptime_seconds: Optional[float] = None,
    ) -> str:
        """
        Text exposition block for a Prometheus scrape of /metrics. Values not passed in are
        taken from the live counters.
        """
        if requests_total is None or errors_total is None or uptime_seconds is None:
            with cls._lock:
                if requests_total is None:
                    requests_total = cls._requests_total
                if errors_total is None:
                    errors_total = cls._errors_total
                if uptime_seconds is None:
                    uptime_seconds = time.time() - cls._start_time

        lines = [
            "# HELP app_requests_total Total number of HTTP requests handled.",
            "# TYPE app_requests_total counter",
            f"app_requests_total {requests_total}",
            "",
            "# HELP app_requests_errors_total Total number of failed requests (5xx / exceptions).",
            "# TYPE app_requests_errors_total counter",
            f"app_requests_errors_total {errors_total}",
            "",
            "# HELP app_uptime_seconds Continuous service uptime in seconds.",
            "# TYPE app_uptime_seconds gauge",
            f"app_uptime_seconds {round(uptime_seconds, 2)}",
            ""
        ]
        return "\n".join(lines)

    @classmethod
    def build_handler(
        cls,
        health_fn: Optional[Callable[[], Dict[str, Any]]] = None,
    ) -> type:
        """
        Request handler class for /metrics and /healthz. health_fn supplies the health payload;
        /healthz answers 200 when its status is HEALTHY or OK and 503 otherwise.
        """
        def _default_health() -> Dict[str, Any]:
            with cls._lock:
                uptime = round(time.time() - cls._start_time, 2)
            return {"status": "HEALTHY", "uptime": uptime}

        resolve_health = health_fn or _default_health

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                # Silence the default per-request stderr line; scrapes would flood the console.
                return

            def _send_bytes(self, status_code: int, content_type: str, body: bytes) -> None:
                self.send_response(status_code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path.startswith("/metrics"):
                    cls.increment()
                    body = cls.generate_metrics().encode("utf-8")
                    self._send_bytes(200, "text/plain; version=0.0.4; charset=utf-8", body)
                    return

                if self.path.startswith("/healthz") or self.path.startswith("/health"):
                    payload = resolve_health()
                    status_code = 200 if str(payload.get("status", "")).upper() in ("HEALTHY", "OK") else 503
                    cls.increment(error=(status_code != 200))
                    body = json.dumps(payload).encode("utf-8")
                    self._send_bytes(status_code, "application/json", body)
                    return

                cls.increment(error=True)
                body = b'{"error":"not found","paths":["/metrics","/healthz"]}'
                self._send_bytes(404, "application/json", body)

        return Handler

    @classmethod
    def serve(
        cls,
        host: str = "127.0.0.1",
        port: int = 9100,
        health_fn: Optional[Callable[[], Dict[str, Any]]] = None,
    ) -> None:
        """
        Serve /metrics and /healthz until Ctrl+C.
        """
        handler = cls.build_handler(health_fn=health_fn)
        server = ThreadingHTTPServer((host, port), handler)
        print(f"SRE endpoints at http://{host}:{port}/metrics and /healthz (Ctrl+C to stop)")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")
        finally:
            server.server_close()
