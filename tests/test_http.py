"""
Tests de lo que hace peticiones HTTP: contratos de API (y el comando contract), sondas de salud
(y el comando health), el índice de PyPI y el exportador de Prometheus. Todo contra el servidor
local de conftest.http_server: ninguno sale a la red.
"""
import json
import os
import socket
import sys
import urllib.request

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentes import __version__  # noqa: E402
from agentes import cli as agentes_cli  # noqa: E402
from agentes.qa.api_contract_testing import APIContractTester  # noqa: E402
from agentes.quality import package_index  # noqa: E402
from agentes.quality.package_index import IndexUnavailable, PackageNotFound  # noqa: E402
from agentes.sre.health_checker import SystemHealthChecker  # noqa: E402
from agentes.sre.prometheus_exporter import PrometheusExporter  # noqa: E402


@pytest.fixture
def run(capsys):
    """Ejecuta el CLI en proceso y devuelve (código, stdout, stderr)."""
    def _run(*argv):
        code = agentes_cli.main(list(argv))
        captured = capsys.readouterr()
        return code, captured.out, captured.err
    return _run


def _checks(result):
    return {(name, status) for name, status, _ in result["assertions"]}


# --- Contratos de API -----------------------------------------------------------------------

def test_contrato_que_se_cumple(http_server):
    result = APIContractTester.request_and_validate(
        f"{http_server.url}/json", expected_schema={"id": int, "name": str}, max_sla_ms=5000,
        expected_headers={"x-custom": "valor"},
    )
    assert result["passed"], result
    assert _checks(result) == {("Status Code", "OK"), ("SLA Latencia", "OK"), ("Headers HTTP", "OK"),
                               ("Esquema JSON", "OK")}
    assert result["response_data"] == {"id": 1, "name": "ana"}
    sent = http_server.requests[0].headers
    assert sent["Accept"] == "application/json" and sent["User-Agent"] == f"agentes-qa-contract/{__version__}"


def test_contrato_con_un_codigo_de_error_esperado(http_server):
    """Un 404 es un HTTPError para urllib, pero si es lo que se espera el contrato se cumple."""
    result = APIContractTester.request_and_validate(f"{http_server.url}/status/404", expected_status=404,
                                                    max_sla_ms=5000)
    assert result["passed"]
    assert result["response_data"] == {"code": 404}
    assert "404" in result["transport_error"]


def test_contrato_que_falla_explica_cada_comprobacion(http_server):
    result = APIContractTester.request_and_validate(
        f"{http_server.url}/status/500", expected_schema={"id": int}, max_sla_ms=5000,
        expected_headers={"X-Falta": "x"}, reject_extra_keys=True,
    )
    assert not result["passed"]
    details = " | ".join(d for _, _, d in result["assertions"])
    assert "Se esperaba 200, se recibió 500" in details
    assert "Falta header requerido 'X-Falta'" in details
    assert "Falta el campo requerido: 'id'" in details


def test_contrato_cabecera_con_otro_valor_y_sla_superado(http_server):
    result = APIContractTester.request_and_validate(
        f"{http_server.url}/slow", max_sla_ms=50, expected_headers={"Content-Type": "text/xml"},
    )
    assert not result["passed"]
    assert ("SLA Latencia", "FALLO") in _checks(result)
    assert any("esperaba 'text/xml', recibió 'application/json'" in d for _, _, d in result["assertions"])


@pytest.mark.parametrize("ruta, esperado", [
    ("/text", {"_raw": "hola"}),
    ("/list", [1, 2]),
    ("/broken", {"_error": "HTTP Error 500: Internal Server Error"}),
])
def test_contrato_respuestas_que_no_son_un_objeto_json(http_server, ruta, esperado):
    result = APIContractTester.request_and_validate(f"{http_server.url}{ruta}", max_sla_ms=5000)
    assert result["response_data"] == esperado


@pytest.mark.parametrize("body, content_type, recibido", [
    ({"a": 1}, "application/json", '{"a": 1}'),
    ("texto plano", None, "texto plano"),
    (b"\x01\x02", None, "\x01\x02"),
])
def test_contrato_envia_el_cuerpo_segun_su_tipo(http_server, body, content_type, recibido):
    result = APIContractTester.request_and_validate(f"{http_server.url}/echo", method="post", body=body,
                                                    headers={"X-Extra": "1"}, max_sla_ms=5000)
    echo = result["response_data"]
    assert echo["method"] == "POST" and echo["body"] == recibido
    if content_type:
        assert echo["content_type"] == content_type
    assert http_server.requests[0].headers["X-Extra"] == "1"


def test_contrato_sin_servidor_no_lanza(closed_port):
    result = APIContractTester.request_and_validate(f"http://127.0.0.1:{closed_port}/x", timeout=2)
    assert not result["passed"] and result["error"]
    assert result["assertions"][0][:2] == ("HTTP Request", "FALLO")


@pytest.mark.parametrize("elapsed", [float("nan"), float("inf"), -1, True, "rápido"])
def test_contrato_latencia_imposible_no_cumple_el_sla(elapsed):
    result = APIContractTester.validate_api_response("/x", 200, {}, {}, elapsed)
    assert not result["passed"]
    assert ("SLA Latencia", "FALLO") in _checks(result)


# --- agentes contract -----------------------------------------------------------------------

def test_cli_contract_cumple_con_esquema_y_cabeceras(run, http_server, tmp_path):
    schema = tmp_path / "schema.json"
    schema.write_text('{"id": "int", "name": "string"}', encoding="utf-8")
    code, out, _ = run("contract", f"{http_server.url}/json", "--schema", str(schema),
                       "--header", "Authorization: Bearer abc", "--max-ms", "5000", "--no-color")
    assert code == 0
    assert "El endpoint cumple el contrato." in out and "Esquema JSON" in out
    assert http_server.requests[0].headers["Authorization"] == "Bearer abc"


def test_cli_contract_que_no_cumple_sale_con_1(run, http_server):
    code, out, _ = run("contract", f"{http_server.url}/status/503", "--max-ms", "5000", "--no-color")
    assert code == 1 and "El endpoint no cumple el contrato." in out


def test_cli_contract_json_y_cuerpo(run, http_server):
    code, out, _ = run("contract", f"{http_server.url}/echo", "--method", "POST", "--body", '{"a": 1}',
                       "--max-ms", "5000", "--json")
    assert code == 0
    assert json.loads(json.loads(out)["response_data"]["body"]) == {"a": 1}
    code, out, _ = run("contract", f"{http_server.url}/echo", "--method", "POST", "--body", "no es json",
                       "--max-ms", "5000", "--json")
    assert json.loads(out)["response_data"]["body"] == "no es json"


@pytest.mark.parametrize("extra, mensaje", [
    (["--header", "sin dos puntos"], "Cabecera mal formada"),
    (["--schema", "{bad"], "no es JSON válido"),
    (["--schema", '{"tags": ["str", "int"]}'], "una lista debe declarar un solo tipo"),
])
def test_cli_contract_errores_de_uso(run, http_server, tmp_path, extra, mensaje):
    if extra[0] == "--schema":
        path = tmp_path / "schema.json"
        path.write_text(extra[1], encoding="utf-8")
        extra = ["--schema", str(path)]
    code, _, err = run("contract", f"{http_server.url}/json", *extra)
    assert code == 2 and mensaje in err


# --- Sondas de salud ------------------------------------------------------------------------

def test_sondas_http_y_tcp(http_server, closed_port):
    assert SystemHealthChecker.check_http(f"{http_server.url}/json")["ok"]
    assert http_server.requests[0].headers["User-Agent"] == f"agentes-sre-health/{__version__}"
    fallida = SystemHealthChecker.check_http(f"http://127.0.0.1:{closed_port}/", timeout=2)
    assert not fallida["ok"] and fallida["status_code"] is None
    assert SystemHealthChecker.check_tcp("127.0.0.1", http_server.port)["ok"]
    assert not SystemHealthChecker.check_tcp("127.0.0.1", closed_port, timeout=2)["ok"]


def test_sonda_http_acepta_el_codigo_esperado_aunque_sea_de_error(http_server):
    """Un 503 es una respuesta, no una caída: si es lo que se espera, la sonda pasa."""
    check = SystemHealthChecker.check_http(f"{http_server.url}/status/503", expect_status=503)
    assert check["ok"] and check["status_code"] == 503
    otro = SystemHealthChecker.check_http(f"{http_server.url}/status/404", expect_status=200)
    assert not otro["ok"] and otro["status_code"] == 404 and otro["detail"] == "Status 404 != 200"


def test_estado_global_segun_que_sonda_falla(http_server, closed_port):
    assert SystemHealthChecker.check_health(min_free_mb=0, http_url=f"{http_server.url}/json")["status"] == "HEALTHY"
    degradado = SystemHealthChecker.check_health(min_free_mb=0, tcp_host="127.0.0.1", tcp_port=closed_port)
    assert degradado["status"] == "DEGRADED" and degradado["failed_checks"] == ["tcp"]
    assert SystemHealthChecker.check_health(min_free_mb=10 ** 12)["status"] == "UNHEALTHY"


def test_disco_inexistente_es_una_sonda_fallida(tmp_path):
    check = SystemHealthChecker.check_disk(str(tmp_path / "no-existe"))
    assert not check["ok"] and "No se pudo consultar el disco" in check["detail"]


def test_cli_health_con_un_disco_inexistente(run, tmp_path):
    code, out, _ = run("health", "--disk", str(tmp_path / "no-existe"), "--no-color")
    assert code == 1 and "UNHEALTHY" in out and "No se pudo consultar el disco" in out


def test_cli_health(run, http_server, closed_port):
    code, out, _ = run("health", "--min-free-mb", "0", "--tcp", f"127.0.0.1:{http_server.port}",
                       "--http", f"{http_server.url}/json", "--no-color")
    assert code == 0 and "HEALTHY: todas las sondas responden." in out
    code, out, _ = run("health", "--min-free-mb", "0", "--tcp", f"127.0.0.1:{closed_port}", "--no-color")
    assert code == 1 and "DEGRADED" in out
    code, out, _ = run("health", "--min-free-mb", str(10 ** 12), "--no-color")
    assert code == 1 and "UNHEALTHY" in out and "Puedes añadir sondas" in out
    code, out, _ = run("health", "--min-free-mb", "0", "--json")
    assert code == 0 and json.loads(out)["status"] == "HEALTHY"


@pytest.mark.parametrize("tcp", ["localhost", "localhost:", ":5432", "localhost:puerto"])
def test_cli_health_tcp_mal_formado(run, tcp):
    code, _, err = run("health", "--tcp", tcp)
    assert code == 2 and "HOST:PUERTO" in err


# --- Índice de PyPI ---------------------------------------------------------------------------

def test_http_get_json_traduce_cada_fallo(http_server, closed_port):
    assert package_index.http_get_json(f"{http_server.url}/json") == {"id": 1, "name": "ana"}
    with pytest.raises(PackageNotFound):
        package_index.http_get_json(f"{http_server.url}/status/404")
    with pytest.raises(IndexUnavailable, match="HTTP 500 en 127.0.0.1"):
        package_index.http_get_json(f"{http_server.url}/status/500")
    with pytest.raises(IndexUnavailable, match="sin conexión con 127.0.0.1"):
        package_index.http_get_json(f"http://127.0.0.1:{closed_port}/", timeout=2)
    with pytest.raises(IndexUnavailable):
        package_index.http_get_json(f"{http_server.url}/text")


def test_http_get_json_con_datos_hace_post(http_server):
    echo = package_index.http_get_json(f"{http_server.url}/echo", data=b'{"q": 1}')
    assert echo == {"method": "POST", "content_type": "application/json", "body": '{"q": 1}'}


def test_pypi_versions_descarta_retiradas_e_incompatibles(http_server, monkeypatch):
    monkeypatch.setattr(package_index, "PYPI_JSON_URL", http_server.url + "/pypi/{name}/json")
    versions = package_index.pypi_versions("Paquete_Ficticio[extra]", python_version="3.12.0")
    # 2.0 solo tiene archivos retirados y 3.0 exige Python 2; unos metadatos ilegibles no descartan.
    assert sorted(versions) == ["1.0", "4.0b1", "rota"]
    assert http_server.requests[0].path == "/pypi/paquete-ficticio/json"
    assert package_index.best_version(versions) == "1.0"
    assert package_index.best_version(versions, ">=2") == "4.0b1"
    assert package_index.best_version(versions, "esto no es un especificador") is None


# --- Exportador de Prometheus -----------------------------------------------------------------

@pytest.fixture
def exporter():
    """Servidor con el manejador de PrometheusExporter; health se cambia desde el test."""
    from http.server import ThreadingHTTPServer
    from threading import Thread

    state = {"health": {"status": "HEALTHY"}}
    PrometheusExporter.reset()
    server = ThreadingHTTPServer(("127.0.0.1", 0), PrometheusExporter.build_handler(lambda: state["health"]))
    Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", state
    finally:
        server.shutdown()
        server.server_close()
        PrometheusExporter.reset()


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def test_exportador_metrics_healthz_y_404(exporter):
    url, state = exporter
    assert _get(f"{url}/healthz") == (200, '{"status": "HEALTHY"}')
    state["health"] = {"status": "UNHEALTHY"}
    assert _get(f"{url}/healthz")[0] == 503
    assert _get(f"{url}/otra")[0] == 404
    status, body = _get(f"{url}/metrics")
    assert status == 200
    # 4 peticiones contadas al generar la respuesta de /metrics; 2 fallidas (el 503 y el 404).
    assert "app_requests_total 4" in body and "app_requests_errors_total 2" in body


def test_exportador_healthz_por_defecto_informa_del_uptime():
    from http.server import ThreadingHTTPServer
    from threading import Thread

    server = ThreadingHTTPServer(("127.0.0.1", 0), PrometheusExporter.build_handler())
    Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
    try:
        status, body = _get(f"http://127.0.0.1:{server.server_address[1]}/health")
    finally:
        server.shutdown()
        server.server_close()
    data = json.loads(body)
    assert status == 200 and data["status"] == "HEALTHY" and data["uptime"] >= 0


def test_serve_se_detiene_con_ctrl_c(monkeypatch, capsys):
    closed = []

    class FakeServer:
        def __init__(self, address, handler):
            self.address = address

        def serve_forever(self):
            raise KeyboardInterrupt

        def server_close(self):
            closed.append(True)

    from agentes.sre import prometheus_exporter
    monkeypatch.setattr(prometheus_exporter, "ThreadingHTTPServer", FakeServer)
    PrometheusExporter.serve(port=9999)
    out = capsys.readouterr().out
    assert "http://127.0.0.1:9999/metrics" in out and "Detenido." in out and closed == [True]


def test_cli_serve_con_el_puerto_ocupado(run):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        code, _, err = run("serve", "--port", str(busy.getsockname()[1]))
    assert code == 2 and "No se pudo abrir 127.0.0.1" in err and "--port" in err
