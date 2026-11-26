"""Configuración común de la suite: sin red y sin depender del orden de ejecución."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest


@pytest.fixture(autouse=True)
def _sin_red(monkeypatch):
    """Ningún test consulta PyPI ni OSV. Los que prueban esa lógica inyectan respuestas falsas."""
    monkeypatch.setenv("AGENTES_OFFLINE", "1")


class _Handler(BaseHTTPRequestHandler):
    """
    Rutas del servidor de pruebas:

    /json          200 con {"id": 1, "name": "ana"} y la cabecera X-Custom: valor
    /list          200 con una lista JSON
    /text          200 con texto plano
    /status/<n>    el código n con {"code": n}
    /broken        500 con un cuerpo que no es JSON
    /slow          200 tras 0,3 segundos
    /echo          (POST) devuelve el método, el Content-Type y el cuerpo recibidos
    /pypi/<p>/json releases de un paquete ficticio, con un archivo retirado y uno solo para Python 2
    """

    def log_message(self, fmt, *args):
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
            self._send(200, {"id": 1, "name": "ana"}, headers={"X-Custom": "valor"})
        elif path == "/list":
            self._send(200, [1, 2])
        elif path == "/text":
            self._send(200, b"hola", "text/plain")
        elif path.startswith("/status/"):
            code = int(path.rsplit("/", 1)[1])
            self._send(code, {"code": code})
        elif path == "/broken":
            self._send(500, b"<html>boom</html>", "text/html")
        elif path == "/slow":
            time.sleep(0.3)
            self._send(200, {"id": 1, "name": "lento"})
        elif path.startswith("/pypi/"):
            self._send(200, {"releases": {
                "1.0": [{"requires_python": ">=3.8"}],
                "2.0": [{"requires_python": ">=3.8", "yanked": True}],
                "3.0": [{"requires_python": "<3"}],
                "4.0b1": [{}],
                "rota": [{"requires_python": "no es un especificador"}],
            }})
        else:
            self._send(404, {"error": "no existe"})

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._record(body)
        self._send(200, {"method": "POST", "content_type": self.headers.get("Content-Type"),
                         "body": body.decode("utf-8")})


@pytest.fixture
def http_server():
    """
    Servidor HTTP local en un puerto libre de 127.0.0.1, para probar sin red lo que hace
    peticiones: contratos de API, sondas de salud y consultas a índices de paquetes.
    Devuelve un objeto con url (la base, sin barra final), port y requests (lo recibido).
    """
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.requests = []
    # serve_forever revisa cada poll_interval si debe parar: con el valor por defecto (0,5 s)
    # cada shutdown() espera medio segundo.
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
    """Un puerto de 127.0.0.1 en el que no escucha nadie: conectar falla al momento."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    server.server_close()
    return port
