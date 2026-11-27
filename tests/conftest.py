"""Shared suite configuration: no network access and no dependence on test order."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """No test queries PyPI or OSV. Tests of that logic inject fake responses instead."""
    monkeypatch.setenv("AGENTES_OFFLINE", "1")


class _Handler(BaseHTTPRequestHandler):
    """
    Routes of the test server:

    /json          200 with {"id": 1, "name": "ana"} and the header X-Custom: value
    /list          200 with a JSON list
    /text          200 with plain text
    /status/<n>    status n with {"code": n}
    /broken        500 with a body that is not JSON
    /slow          200 after 0.3 seconds
    /echo          (POST) echoes the method, Content-Type and body it received
    /pypi/<p>/json releases of a fictitious package, with one yanked file and one for Python 2 only
    """

    def log_message(self, fmt, *args):
        # Keep pytest output clean: no per-request line on stderr.
        return

    def _send(self, status, body, content_type="application/json", headers=None):
        data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def _record(self, body=b""):
        self.server.requests.append(SimpleNamespace(
            method=self.command, path=self.path, headers=dict(self.headers.items()), body=body))

    def do_GET(self):
        self._record()
        path = self.path
        if path == "/json":
            self._send(200, {"id": 1, "name": "ana"}, headers={"X-Custom": "value"})
        elif path == "/list":
            self._send(200, [1, 2])
        elif path == "/text":
            self._send(200, b"hello", "text/plain")
        elif path.startswith("/status/"):
            code = int(path.rsplit("/", 1)[1])
            self._send(code, {"code": code})
        elif path == "/broken":
            self._send(500, b"<html>boom</html>", "text/html")
        elif path == "/slow":
            time.sleep(0.3)
            self._send(200, {"id": 1, "name": "slow"})
        elif path.startswith("/pypi/"):
            self._send(200, {"releases": {
                "1.0": [{"requires_python": ">=3.8"}],
                "2.0": [{"requires_python": ">=3.8", "yanked": True}],
                "3.0": [{"requires_python": "<3"}],
                "4.0b1": [{}],
                "broken": [{"requires_python": "not a specifier"}],
            }})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._record(body)
        self._send(200, {"method": "POST", "content_type": self.headers.get("Content-Type"),
                         "body": body.decode("utf-8")})


@pytest.fixture
def http_server():
    """
    Local HTTP server on a free 127.0.0.1 port, to test code that makes requests without real
    network access: API contracts, health probes and package index lookups.
    Yields an object with url (the base, without a trailing slash), port and requests (what it received).
    """
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.requests = []
    # serve_forever checks every poll_interval whether it should stop: with the default (0.5 s)
    # each shutdown() would wait half a second.
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield SimpleNamespace(url=f"http://127.0.0.1:{server.server_address[1]}", port=server.server_address[1],
                              requests=server.requests)
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def closed_port():
    """A 127.0.0.1 port nobody listens on: connecting fails immediately."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    server.server_close()
    return port
