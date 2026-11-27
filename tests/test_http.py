"""
Tests for everything that makes HTTP requests: API contracts (and the contract command), health
probes (and the health command), the PyPI index and the Prometheus exporter. Everything runs
against the local server from conftest.http_server; nothing reaches the network.
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
    """Run the CLI in-process and return (exit code, stdout, stderr)."""
    def _run(*argv):
        code = agentes_cli.main(list(argv))
        captured = capsys.readouterr()
        return code, captured.out, captured.err
    return _run


def _checks(result):
    return {(name, status) for name, status, _ in result["assertions"]}


# --- API contracts --------------------------------------------------------------------------

def test_contract_that_holds(http_server):
    result = APIContractTester.request_and_validate(
        f"{http_server.url}/json", expected_schema={"id": int, "name": str}, max_sla_ms=5000,
        expected_headers={"x-custom": "value"},
    )
    assert result["passed"], result
    assert _checks(result) == {("Status Code", "OK"), ("Latency SLA", "OK"), ("HTTP Headers", "OK"),
                               ("JSON Schema", "OK")}
    assert result["response_data"] == {"id": 1, "name": "ana"}
    sent = http_server.requests[0].headers
    assert sent["Accept"] == "application/json" and sent["User-Agent"] == f"agentes-qa-contract/{__version__}"


def test_contract_with_an_expected_error_status(http_server):
    """A 404 is an HTTPError for urllib, but when it is what the contract expects, the contract holds."""
    result = APIContractTester.request_and_validate(f"{http_server.url}/status/404", expected_status=404,
                                                    max_sla_ms=5000)
    assert result["passed"]
    assert result["response_data"] == {"code": 404}
    assert "404" in result["transport_error"]


def test_failing_contract_explains_every_check(http_server):
    result = APIContractTester.request_and_validate(
        f"{http_server.url}/status/500", expected_schema={"id": int}, max_sla_ms=5000,
        expected_headers={"X-Missing": "x"}, reject_extra_keys=True,
    )
    assert not result["passed"]
    details = " | ".join(d for _, _, d in result["assertions"])
    assert "Expected 200, got 500" in details
    assert "Missing required header 'X-Missing'" in details
    assert "Missing required field: 'id'" in details


def test_contract_header_with_another_value_and_sla_exceeded(http_server):
    result = APIContractTester.request_and_validate(
        f"{http_server.url}/slow", max_sla_ms=50, expected_headers={"Content-Type": "text/xml"},
    )
    assert not result["passed"]
    assert ("Latency SLA", "FAILED") in _checks(result)
    assert any("expected 'text/xml', got 'application/json'" in d for _, _, d in result["assertions"])


@pytest.mark.parametrize("path, expected", [
    ("/text", {"_raw": "hello"}),
    ("/list", [1, 2]),
    ("/broken", {"_error": "HTTP Error 500: Internal Server Error"}),
])
def test_contract_responses_that_are_not_a_json_object(http_server, path, expected):
    result = APIContractTester.request_and_validate(f"{http_server.url}{path}", max_sla_ms=5000)
    assert result["response_data"] == expected


@pytest.mark.parametrize("body, content_type, received", [
    ({"a": 1}, "application/json", '{"a": 1}'),
    ("plain text", None, "plain text"),
    (b"\x01\x02", None, "\x01\x02"),
])
def test_contract_sends_the_body_according_to_its_type(http_server, body, content_type, received):
    result = APIContractTester.request_and_validate(f"{http_server.url}/echo", method="post", body=body,
                                                    headers={"X-Extra": "1"}, max_sla_ms=5000)
    echo = result["response_data"]
    assert echo["method"] == "POST" and echo["body"] == received
    if content_type:
        assert echo["content_type"] == content_type
    assert http_server.requests[0].headers["X-Extra"] == "1"


def test_contract_without_a_server_does_not_raise(closed_port):
    result = APIContractTester.request_and_validate(f"http://127.0.0.1:{closed_port}/x", timeout=2)
    assert not result["passed"] and result["error"]
    assert result["assertions"][0][:2] == ("HTTP Request", "FAILED")


@pytest.mark.parametrize("elapsed", [float("nan"), float("inf"), -1, True, "fast"])
def test_contract_with_an_impossible_latency_fails_the_sla(elapsed):
    result = APIContractTester.validate_api_response("/x", 200, {}, {}, elapsed)
    assert not result["passed"]
    assert ("Latency SLA", "FAILED") in _checks(result)


# --- agentes contract -----------------------------------------------------------------------

def test_cli_contract_holds_with_schema_and_headers(run, http_server, tmp_path):
    schema = tmp_path / "schema.json"
    schema.write_text('{"id": "int", "name": "string"}', encoding="utf-8")
    code, out, _ = run("contract", f"{http_server.url}/json", "--schema", str(schema),
                       "--header", "Authorization: Bearer abc", "--max-ms", "5000", "--no-color")
    assert code == 0
    assert "The endpoint honours the contract." in out and "JSON Schema" in out
    assert http_server.requests[0].headers["Authorization"] == "Bearer abc"


def test_cli_contract_that_fails_exits_with_1(run, http_server):
    code, out, _ = run("contract", f"{http_server.url}/status/503", "--max-ms", "5000", "--no-color")
    assert code == 1 and "The endpoint does not honour the contract." in out


def test_cli_contract_json_and_body(run, http_server):
    code, out, _ = run("contract", f"{http_server.url}/echo", "--method", "POST", "--body", '{"a": 1}',
                       "--max-ms", "5000", "--json")
    assert code == 0
    assert json.loads(json.loads(out)["response_data"]["body"]) == {"a": 1}
    code, out, _ = run("contract", f"{http_server.url}/echo", "--method", "POST", "--body", "not json",
                       "--max-ms", "5000", "--json")
    assert json.loads(out)["response_data"]["body"] == "not json"


@pytest.mark.parametrize("extra, message", [
    (["--header", "no colon"], "Malformed header"),
    (["--schema", "{bad"], "is not valid JSON"),
    (["--schema", '{"tags": ["str", "int"]}'], "a list must declare exactly one type"),
])
def test_cli_contract_usage_errors(run, http_server, tmp_path, extra, message):
    if extra[0] == "--schema":
        path = tmp_path / "schema.json"
        path.write_text(extra[1], encoding="utf-8")
        extra = ["--schema", str(path)]
    code, _, err = run("contract", f"{http_server.url}/json", *extra)
    assert code == 2 and message in err


# --- Health probes --------------------------------------------------------------------------

def test_http_and_tcp_probes(http_server, closed_port):
    assert SystemHealthChecker.check_http(f"{http_server.url}/json")["ok"]
    assert http_server.requests[0].headers["User-Agent"] == f"agentes-sre-health/{__version__}"
    failed = SystemHealthChecker.check_http(f"http://127.0.0.1:{closed_port}/", timeout=2)
    assert not failed["ok"] and failed["status_code"] is None
    assert SystemHealthChecker.check_tcp("127.0.0.1", http_server.port)["ok"]
    assert not SystemHealthChecker.check_tcp("127.0.0.1", closed_port, timeout=2)["ok"]


def test_http_probe_accepts_the_expected_status_even_if_it_is_an_error(http_server):
    """A 503 is a response, not an outage: when it is what the probe expects, it passes."""
    check = SystemHealthChecker.check_http(f"{http_server.url}/status/503", expect_status=503)
    assert check["ok"] and check["status_code"] == 503
    other = SystemHealthChecker.check_http(f"{http_server.url}/status/404", expect_status=200)
    assert not other["ok"] and other["status_code"] == 404 and other["detail"] == "Status 404 != 200"


def test_overall_status_depends_on_which_probe_fails(http_server, closed_port):
    assert SystemHealthChecker.check_health(min_free_mb=0, http_url=f"{http_server.url}/json")["status"] == "HEALTHY"
    degraded = SystemHealthChecker.check_health(min_free_mb=0, tcp_host="127.0.0.1", tcp_port=closed_port)
    assert degraded["status"] == "DEGRADED" and degraded["failed_checks"] == ["tcp"]
    assert SystemHealthChecker.check_health(min_free_mb=10 ** 12)["status"] == "UNHEALTHY"


def test_missing_disk_is_a_failed_probe(tmp_path):
    check = SystemHealthChecker.check_disk(str(tmp_path / "missing"))
    assert not check["ok"] and "Could not query the disk" in check["detail"]


def test_cli_health_with_a_missing_disk(run, tmp_path):
    code, out, _ = run("health", "--disk", str(tmp_path / "missing"), "--no-color")
    assert code == 1 and "UNHEALTHY" in out and "Could not query the disk" in out


def test_cli_health(run, http_server, closed_port):
    code, out, _ = run("health", "--min-free-mb", "0", "--tcp", f"127.0.0.1:{http_server.port}",
                       "--http", f"{http_server.url}/json", "--no-color")
    assert code == 0 and "HEALTHY: every probe passed." in out
    code, out, _ = run("health", "--min-free-mb", "0", "--tcp", f"127.0.0.1:{closed_port}", "--no-color")
    assert code == 1 and "DEGRADED" in out
    code, out, _ = run("health", "--min-free-mb", str(10 ** 12), "--no-color")
    assert code == 1 and "UNHEALTHY" in out and "Add probes" in out
    code, out, _ = run("health", "--min-free-mb", "0", "--json")
    assert code == 0 and json.loads(out)["status"] == "HEALTHY"


@pytest.mark.parametrize("tcp", ["localhost", "localhost:", ":5432", "localhost:port"])
def test_cli_health_malformed_tcp(run, tcp):
    code, _, err = run("health", "--tcp", tcp)
    assert code == 2 and "HOST:PORT" in err


# --- PyPI index ------------------------------------------------------------------------------

def test_http_get_json_maps_every_failure(http_server, closed_port):
    assert package_index.http_get_json(f"{http_server.url}/json") == {"id": 1, "name": "ana"}
    with pytest.raises(PackageNotFound):
        package_index.http_get_json(f"{http_server.url}/status/404")
    with pytest.raises(IndexUnavailable, match="HTTP 500 from 127.0.0.1"):
        package_index.http_get_json(f"{http_server.url}/status/500")
    with pytest.raises(IndexUnavailable, match="cannot reach 127.0.0.1"):
        package_index.http_get_json(f"http://127.0.0.1:{closed_port}/", timeout=2)
    with pytest.raises(IndexUnavailable):
        package_index.http_get_json(f"{http_server.url}/text")


def test_http_get_json_with_data_makes_a_post(http_server):
    echo = package_index.http_get_json(f"{http_server.url}/echo", data=b'{"q": 1}')
    assert echo == {"method": "POST", "content_type": "application/json", "body": '{"q": 1}'}


def test_pypi_versions_drops_yanked_and_incompatible_releases(http_server, monkeypatch):
    monkeypatch.setattr(package_index, "PYPI_JSON_URL", http_server.url + "/pypi/{name}/json")
    versions = package_index.pypi_versions("Fictitious_Package[extra]", python_version="3.12.0")
    # 2.0 only has yanked files and 3.0 requires Python 2; unreadable metadata does not rule a release out.
    assert sorted(versions) == ["1.0", "4.0b1", "broken"]
    assert http_server.requests[0].path == "/pypi/fictitious-package/json"
    assert package_index.best_version(versions) == "1.0"
    assert package_index.best_version(versions, ">=2") == "4.0b1"
    assert package_index.best_version(versions, "this is not a specifier") is None


# --- Prometheus exporter ---------------------------------------------------------------------

@pytest.fixture
def exporter():
    """Server running PrometheusExporter's handler; the test can change the health payload."""
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


def test_exporter_metrics_healthz_and_404(exporter):
    url, state = exporter
    assert _get(f"{url}/healthz") == (200, '{"status": "HEALTHY"}')
    state["health"] = {"status": "UNHEALTHY"}
    assert _get(f"{url}/healthz")[0] == 503
    assert _get(f"{url}/other")[0] == 404
    status, body = _get(f"{url}/metrics")
    assert status == 200
    # 4 requests counted by the time /metrics renders its response; 2 of them failed (the 503 and the 404).
    assert "app_requests_total 4" in body and "app_requests_errors_total 2" in body


def test_exporter_default_healthz_reports_uptime():
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


def test_serve_stops_on_ctrl_c(monkeypatch, capsys):
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
    assert "http://127.0.0.1:9999/metrics" in out and "Stopped." in out and closed == [True]


def test_cli_serve_with_the_port_in_use(run):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        code, _, err = run("serve", "--port", str(busy.getsockname()[1]))
    assert code == 2 and "Could not listen on 127.0.0.1" in err and "--port" in err
