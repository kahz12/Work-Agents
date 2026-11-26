"""Tests del CLI `agentes`: comandos, códigos de salida, salida JSON y mensajes de error."""
import io
import json
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentes import cli as agentes_cli  # noqa: E402

# Los tokens falsos van partidos en dos literales ("ghp_" "16C7..."): Python los une y el detector
# recibe el token entero, pero el archivo no contiene ninguno completo y la protección de
# secretos de GitHub no bloquea el push.
FAKE_TOKEN = "ghp_" "16C7e42F292c6912E7710c838347Ae178B4a"


@pytest.fixture
def run(capsys):
    """Ejecuta el CLI en proceso y devuelve (código, stdout, stderr)."""
    def _run(*argv):
        code = agentes_cli.main(list(argv))
        captured = capsys.readouterr()
        return code, captured.out, captured.err
    return _run


@pytest.fixture
def project(tmp_path):
    """Proyecto mínimo con un hallazgo de cada tipo."""
    (tmp_path / "app.py").write_text(
        "def get_user(user_id: int) -> dict:\n"
        '    """Devuelve un usuario."""\n'
        '    return {"id": user_id}\n\n\n'
        "def suma(a: int, b: int) -> int:\n"
        '    """Suma."""\n'
        "    return a + b\n",
        encoding="utf-8",
    )
    (tmp_path / "Dockerfile").write_text("FROM python:latest\nUSER root\n", encoding="utf-8")
    (tmp_path / ".env").write_text(f'DEBUG=true\nTOKEN="{FAKE_TOKEN}"\n', encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("requests\nflask>=2.0\n", encoding="utf-8")
    (tmp_path / "app.log").write_text("ok\nTraceback (most recent call last)\n", encoding="utf-8")
    return tmp_path


# --- Pantalla inicial, ayuda y errores de uso ---

def test_sin_argumentos_muestra_todos_los_comandos(run):
    code, out, _ = run()
    assert code == 0
    for name in agentes_cli.COMMAND_NAMES:
        assert name in out
    assert "\033[" not in out, "sin terminal no debe haber códigos de color"


@pytest.mark.parametrize("name", agentes_cli.COMMAND_NAMES + ["serve-sre"])
def test_cada_comando_tiene_ayuda(run, name):
    code, out, _ = run(name, "-h")
    assert code == 0
    assert "Uso: agentes" in out


def test_help_de_un_comando(run):
    code, out, _ = run("help", "pipeline")
    assert code == 0
    assert "--no-fail" in out


def test_comando_desconocido_sugiere_el_parecido(run):
    code, _, err = run("pipelin", ".")
    assert code == 2
    assert "'pipeline'" in err


def test_error_de_argumentos_en_castellano(run):
    code, _, err = run("pipeline")
    assert code == 2
    assert "Faltan argumentos obligatorios" in err


def test_ruta_inexistente_devuelve_2(run, tmp_path):
    code, _, err = run("secrets", str(tmp_path / "no_existe"))
    assert code == 2
    assert "No existe la ruta" in err


def test_atajo_historico_y_alias_se_conservan(run):
    assert run("--list")[0] == 0
    assert run("list")[0] == 0
    code, _, err = run("demo", "qaa")
    assert code == 2 and "'qa'" in err


# --- Analizar ---

def test_pipeline_json_es_el_informe_completo(run, project):
    code, out, _ = run("pipeline", str(project), "-o", str(project / "rep"), "--no-bandit", "--json")
    report = json.loads(out)
    assert code == 1
    assert report["schema"] == "agentes.pipeline.v1"
    assert os.path.isfile(report["artifacts"]["html"])


def test_pipeline_legible_resume_etapas_e_informes(run, project):
    code, out, _ = run("pipeline", str(project), "-o", str(project / "rep"), "--no-bandit")
    assert code == 1
    assert "Secretos" in out and "Informes" in out and "pipeline.html" in out


def test_secrets_falla_y_no_revela_el_valor(run, project):
    code, out, _ = run("secrets", str(project), "--json")
    data = json.loads(out)
    assert code == 1
    assert data["findings"] and all(f["level"] == "ALTO" for f in data["findings"])
    assert FAKE_TOKEN not in out


def test_secrets_proyecto_limpio(run, tmp_path):
    (tmp_path / "ok.py").write_text("X = 1\n", encoding="utf-8")
    code, out, _ = run("secrets", str(tmp_path))
    assert code == 0
    assert "No se encontraron secretos" in out


@pytest.mark.parametrize("filename,rule", [
    ("Dockerfile", "DOCKERFILE"),
    (".env", "ENV"),
    ("app.log", "LOG"),
    ("requirements.txt", "DEPS-PIP"),
])
def test_audit_deduce_el_tipo_por_el_nombre(run, project, filename, rule):
    _, out, _ = run("audit", str(project / filename), "--json")
    findings = json.loads(out)["findings"]
    assert findings and {f["rule_id"] for f in findings} == {rule}


def test_audit_env_no_contamina_el_entorno(run, project):
    assert "DEBUG" not in os.environ
    run("audit", str(project / ".env"))
    assert "DEBUG" not in os.environ and "TOKEN" not in os.environ


def test_audit_directorio_incluye_env_y_logs(run, project):
    code, out, _ = run("audit", str(project), "--json")
    rules = {f.get("rule_id") for f in json.loads(out)["findings"]}
    assert code == 1
    assert {"DOCKERFILE", "ENV", "LOG"} <= rules


def test_audit_tipo_desconocido_pide_type(run, project):
    code, _, err = run("audit", str(project / "app.py"))
    assert code == 2
    assert "--type" in err


def test_audit_type_fuerza_el_auditor(run, tmp_path):
    odd = tmp_path / "contenedor.txt"
    odd.write_text("FROM python:latest\nUSER root\n", encoding="utf-8")
    code, out, _ = run("audit", str(odd), "--type", "docker", "--json")
    assert code == 1
    assert json.loads(out)["findings"]


def test_metrics_json(run, project):
    code, out, _ = run("metrics", str(project), "--json")
    data = json.loads(out)
    assert code == 0
    assert data["totals"]["functions"] == 2
    assert {f["name"] for f in data["functions"]} == {"get_user", "suma"}


LIMPIO = 'def uno() -> int:\n    """Devuelve 1."""\n    return 1\n'


def _es_elogio(recomendacion: str) -> bool:
    return recomendacion.startswith("[EXCELENTE]")


def test_metrics_no_elogia_si_otro_archivo_tiene_problemas(run, tmp_path):
    # Las recomendaciones se calculan archivo por archivo: el elogio de un archivo limpio no
    # puede aparecer junto a los problemas de otro.
    (tmp_path / "limpio.py").write_text(LIMPIO, encoding="utf-8")
    metodos = "".join(f"    def m{i}(self):\n        return {i}\n" for i in range(11))
    (tmp_path / "grande.py").write_text(f"class Grande:\n{metodos}", encoding="utf-8")
    code, out, _ = run("metrics", str(tmp_path), "--json")
    recomendaciones = json.loads(out)["recommendations"]
    assert code == 0
    assert any("SRP" in r for r in recomendaciones)
    assert not any(_es_elogio(r) for r in recomendaciones)


def test_metrics_no_elogia_si_un_archivo_no_se_pudo_analizar(run, tmp_path):
    (tmp_path / "limpio.py").write_text(LIMPIO, encoding="utf-8")
    (tmp_path / "roto.py").write_text("def roto(:\n", encoding="utf-8")
    _, out, _ = run("metrics", str(tmp_path), "--json")
    data = json.loads(out)
    assert any(f["rule_id"] == "METRICS" for f in data["findings"])
    assert not any(_es_elogio(r) for r in data["recommendations"])


CLASE_GRANDE = "class Grande:\n" + "".join(f"    def m{i}(self):\n        return {i}\n" for i in range(11))


def test_metrics_recomendaciones_indican_el_archivo(run, tmp_path):
    # Con varios archivos, "Línea 1" no dice de cuál. Y como las recomendaciones se deduplican
    # por texto, sin el archivo dos archivos con el mismo problema en la misma línea se
    # fundirían en una sola.
    for nombre in ("a.py", "b.py"):
        (tmp_path / nombre).write_text(CLASE_GRANDE, encoding="utf-8")
    _, out, _ = run("metrics", str(tmp_path), "--json")
    srp = [r for r in json.loads(out)["recommendations"] if "SRP" in r]
    assert len(srp) == 2
    assert any("a.py:1]" in r for r in srp) and any("b.py:1]" in r for r in srp)
    assert not any("Línea" in r for r in srp)


def test_metrics_recomendaciones_de_promedios_se_dan_sobre_el_conjunto(run, tmp_path):
    # La documentación y la complejidad media se valoran sobre todo lo analizado, como los
    # totales: valoradas archivo por archivo, la misma recomendación saldría una vez por archivo.
    sin_docs = "".join(f"def f{i}(x):\n    return x + {i}\n" for i in range(30))
    for nombre in ("a.py", "b.py"):
        (tmp_path / nombre).write_text(sin_docs, encoding="utf-8")
    _, out, _ = run("metrics", str(tmp_path), "--json")
    docs = [r for r in json.loads(out)["recommendations"] if r.startswith("[DOCUMENTACION")]
    assert len(docs) == 1


def test_metrics_avisa_de_las_recomendaciones_que_no_muestra(run, tmp_path):
    for nombre in ("a.py", "b.py", "c.py"):
        (tmp_path / nombre).write_text(CLASE_GRANDE, encoding="utf-8")
    total = len(json.loads(run("metrics", str(tmp_path), "--json")[1])["recommendations"])
    code, out, _ = run("metrics", str(tmp_path), "--limit", "1")
    assert code == 0 and total > 1
    recomendaciones = out.split("Recomendaciones", 1)[1]
    assert recomendaciones.count("\n  - ") == 1
    assert f"y {total - 1} más. Usa --limit 0 para verlas todas." in recomendaciones
    _, todas, _ = run("metrics", str(tmp_path), "--limit", "0")
    assert todas.split("Recomendaciones", 1)[1].count("\n  - ") == total
    assert "verlas todas" not in todas


def test_metrics_elogia_un_proyecto_sin_problemas_una_sola_vez(run, tmp_path):
    (tmp_path / "limpio.py").write_text(LIMPIO, encoding="utf-8")
    (tmp_path / "otro.py").write_text(LIMPIO.replace("uno", "otro"), encoding="utf-8")
    _, out, _ = run("metrics", str(tmp_path), "--json")
    recomendaciones = json.loads(out)["recommendations"]
    assert len(recomendaciones) == 1 and _es_elogio(recomendaciones[0])


def _recomendaciones_del_pipeline(run, carpeta):
    _, out, _ = run("pipeline", str(carpeta), "-o", str(carpeta / "rep"), "--no-bandit", "--offline", "--json")
    etapa = next(s for s in json.loads(out)["stages"] if s["name"] == "refactor_metrics")
    return etapa["recommendations"]


def test_pipeline_recomendaciones_indican_el_archivo(run, tmp_path):
    # Mismo criterio que metrics: las de una línea concreta llevan su archivo, relativo a la raíz.
    (tmp_path / "pkg").mkdir()
    for nombre in ("a.py", "b.py"):
        (tmp_path / "pkg" / nombre).write_text(CLASE_GRANDE, encoding="utf-8")
    srp = [r for r in _recomendaciones_del_pipeline(run, tmp_path) if "SRP" in r]
    assert len(srp) == 2
    assert any("pkg/a.py:1]" in r for r in srp) and any("pkg/b.py:1]" in r for r in srp)
    assert not any("Línea" in r for r in srp)


def test_pipeline_recomendaciones_de_promedios_una_sola_vez(run, tmp_path):
    sin_docs = "".join(f"def f{i}(x):\n    return x + {i}\n" for i in range(30))
    for nombre in ("a.py", "b.py"):
        (tmp_path / nombre).write_text(sin_docs, encoding="utf-8")
    recomendaciones = _recomendaciones_del_pipeline(run, tmp_path)
    assert [r for r in recomendaciones if r.startswith("[DOCUMENTACION")] == [
        next(r for r in recomendaciones if r.startswith("[DOCUMENTACION]"))
    ]


def test_pipeline_no_elogia_si_un_archivo_no_se_pudo_analizar(run, tmp_path):
    (tmp_path / "limpio.py").write_text(LIMPIO, encoding="utf-8")
    (tmp_path / "roto.py").write_text("def roto(:\n", encoding="utf-8")
    assert not any(_es_elogio(r) for r in _recomendaciones_del_pipeline(run, tmp_path))


def test_pipeline_elogia_un_proyecto_sin_problemas(run, tmp_path):
    (tmp_path / "limpio.py").write_text(LIMPIO, encoding="utf-8")
    recomendaciones = _recomendaciones_del_pipeline(run, tmp_path)
    assert len(recomendaciones) == 1 and _es_elogio(recomendaciones[0])


# --- Generar y corregir ---

SIN_FUENTE = ["compose", "k8s", "dockerfile", "systemd", "nginx", "caddy", "github-actions", "gitlab-ci"]


def test_generators_cubre_todos_los_tipos_probados():
    con_fuente = {k for k, spec in agentes_cli.GENERATORS.items() if spec[2]}
    assert con_fuente == {"openapi", "swagger", "docs", "diagram", "tests"}
    assert set(agentes_cli.GENERATORS) == set(SIN_FUENTE) | {"helm", "linters"} | con_fuente


@pytest.mark.parametrize("kind", SIN_FUENTE)
def test_generate_sin_fuente(run, tmp_path, kind):
    out_file = tmp_path / "salida" / f"{kind}.out"
    code, out, _ = run("generate", kind, "-o", str(out_file))
    assert code == 0 and "[OK]" in out
    assert out_file.stat().st_size > 0


def test_generate_helm_y_linters_escriben_en_directorio(run, tmp_path):
    assert run("generate", "helm", "-o", str(tmp_path / "chart"), "--service", "api")[0] == 0
    assert (tmp_path / "chart" / "Chart.yaml").is_file()
    assert run("generate", "linters", "-o", str(tmp_path / "cfg"))[0] == 0
    assert (tmp_path / "cfg" / ".flake8").is_file()


@pytest.mark.parametrize("kind,name", [
    ("openapi", "openapi.json"), ("openapi", "openapi.yaml"), ("swagger", "ui.html"),
    ("docs", "DOCS.md"), ("diagram", "diagrama.md"), ("tests", "test_app.py"),
])
def test_generate_con_fuente(run, project, kind, name):
    out_file = project / "gen" / name
    code, _, _ = run("generate", kind, "--source", str(project / "app.py"), "-o", str(out_file))
    assert code == 0
    assert out_file.stat().st_size > 0


def test_generate_tests_pytest_sugiere_pytest(run, project):
    code, out, _ = run("generate", "tests", "--source", str(project / "app.py"),
                       "-o", str(project / "test_p.py"), "--framework", "pytest")
    assert code == 0
    assert "pytest" in out and "agentes test" not in out


def test_generate_no_sobrescribe_sin_force(run, tmp_path):
    target = tmp_path / "docker-compose.yml"
    assert run("generate", "compose", "-o", str(target))[0] == 0
    target.write_text("mio\n", encoding="utf-8")
    code, _, err = run("generate", "compose", "-o", str(target))
    assert code == 2 and "--force" in err
    assert target.read_text(encoding="utf-8") == "mio\n"
    assert run("generate", "compose", "-o", str(target), "--force")[0] == 0
    assert target.read_text(encoding="utf-8") != "mio\n"


def test_generate_linters_conserva_un_pyproject_existente(run, tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'mio'\n", encoding="utf-8")
    code, out, _ = run("generate", "linters", "-o", str(tmp_path))
    assert code == 0
    assert "name = 'mio'" in (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
    assert "Se conserva" in out
    assert (tmp_path / ".flake8").is_file()


def test_generate_sin_tipo_lista_y_con_fuente_ausente_avisa(run):
    code, out, _ = run("generate")
    assert code == 0 and all(kind in out for kind in agentes_cli.GENERATORS)
    code, _, err = run("generate", "openapi")
    assert code == 2 and "--source" in err


@pytest.fixture
def red_simulada(monkeypatch):
    """PyPI y OSV falsos: versiones conocidas y una vulnerabilidad en flask 2.3.3."""
    from agentes.quality import dependency_auditor, vulnerabilities

    monkeypatch.delenv("AGENTES_OFFLINE", raising=False)
    indice = {"requests": ["2.31.0", "2.32.3"], "flask": ["2.0.0", "2.3.3"]}
    monkeypatch.setattr(dependency_auditor, "pypi_versions", lambda name, timeout=10.0: indice[name])

    def osv(deps, timeout=15.0):
        out = {d.key: [] for d in deps}
        for d in deps:
            if d.name == "flask" and d.version == "2.3.3":
                out[d.key] = [vulnerabilities.Vulnerability("GHSA-x", ["CVE-2099-1"], "Fallo de prueba", "ALTO", "3.0.0")]
        return out

    monkeypatch.setattr(vulnerabilities, "query_osv", osv)


def test_fix_dry_run_no_modifica_y_avisa_de_vulnerabilidades(run, project, red_simulada):
    req = project / "requirements.txt"
    before = req.read_text(encoding="utf-8")
    code, out, _ = run("fix", str(req), "--dry-run")
    assert code == 1, "la versión resultante de flask tiene una vulnerabilidad alta"
    assert "requests==2.32.3" in out and "flask==2.3.3" in out
    assert "CVE-2099-1" in out and "3.0.0" in out
    assert req.read_text(encoding="utf-8") == before

    code, out, _ = run("fix", str(req), "--json")
    data = json.loads(out)
    assert data["corrections"] == 2 and data["vulnerabilities"][0]["level"] == "ALTO"
    assert "requests==2.32.3" in req.read_text(encoding="utf-8")


def test_fix_sin_red_no_inventa_versiones(run, project):
    req = project / "requirements.txt"
    before = req.read_text(encoding="utf-8")
    code, _, err = run("fix", str(req))
    assert code == 2 and "sin conexión" in err
    assert req.read_text(encoding="utf-8") == before


def test_vulns_sin_red_y_con_red_simulada(run, project, red_simulada, monkeypatch):
    (project / "requirements.txt").write_text("flask==2.3.3\nrequests>=2\n", encoding="utf-8")
    code, out, _ = run("vulns", str(project), "--json")
    data = json.loads(out)
    assert code == 1
    assert data["dependencies_checked"] == 1 and data["dependencies_unpinned"] == 1
    assert data["findings"][0]["rule_id"] == "VULN-GHSA-x"

    monkeypatch.setenv("AGENTES_OFFLINE", "1")
    code, _, err = run("vulns", str(project))
    assert code == 2 and "sin conexión" in err


# --- Probar ---

def test_test_ejecuta_la_suite_y_falla_si_no_pasa(run, tmp_path):
    (tmp_path / "modz.py").write_text("def doble(x):\n    return x * 2\n", encoding="utf-8")
    suite = tmp_path / "test_modz.py"
    suite.write_text(
        "import unittest\nfrom modz import doble\n\n"
        "class T(unittest.TestCase):\n"
        "    def test_doble(self):\n        self.assertEqual(doble(2), 4)\n",
        encoding="utf-8",
    )
    code, out, _ = run("test", str(suite))
    assert code == 0 and "Todos los tests pasan" in out

    # La suite que falla va en otro archivo. Reescribir el mismo con igual tamaño dentro del
    # mismo segundo hace que Python reutilice el .pyc anterior y ejecute la versión que pasa.
    failing = tmp_path / "test_modz_falla.py"
    failing.write_text(suite.read_text(encoding="utf-8").replace("4)", "5)"), encoding="utf-8")
    code, out, _ = run("test", str(failing), "--json")
    assert code == 1
    assert json.loads(out)["failures"] == 1


def test_testability_con_matriz(run, project):
    code, out, _ = run("testability", str(project / "app.py"), "--matrix", "--json")
    assert code == 0
    assert json.loads(out)["scenarios"]


def test_contract_rechaza_esquemas_no_http(run):
    code, _, err = run("contract", "ftp://ejemplo")
    assert code == 2 and "http" in err


def test_esquema_de_contrato_desde_json():
    schema = agentes_cli._schema_from_json({"id": "int", "tags": ["str"], "owner": {"ok": "bool"}})
    assert schema == {"id": int, "tags": [str], "owner": {"ok": bool}}
    with pytest.raises(agentes_cli.CliError):
        agentes_cli._schema_from_json({"id": "uuid"})


# --- Operar y utilidades ---

def test_sla_codigo_de_salida(run):
    assert run("sla", "--total", "1000", "--errors", "8")[0] == 0
    code, out, _ = run("sla", "--total", "1000", "--errors", "80", "--json")
    assert code == 1 and json.loads(out)["alert"] is True
    assert run("sla", "--total", "10", "--errors", "11")[0] == 2


def test_health_json_y_tcp_mal_formado(run):
    code, out, _ = run("health", "--min-free-mb", "0", "--json")
    assert code == 0 and json.loads(out)["status"] == "HEALTHY"
    assert run("health", "--tcp", "sin_puerto")[0] == 2


def test_password_check_hash_y_verify(run, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO("abc\n"))
    code, out, _ = run("password", "check", "--stdin")
    assert code == 1 and "débil" in out

    strong = "Un4-Clave_Larga!2026"
    monkeypatch.setattr(sys, "stdin", io.StringIO(strong + "\n"))
    code, out, _ = run("password", "hash", "--stdin")
    hashed = out.strip()
    assert code == 0 and ":" in hashed and strong not in hashed

    monkeypatch.setattr(sys, "stdin", io.StringIO(strong + "\n"))
    assert run("password", "verify", hashed, "--stdin")[0] == 0
    monkeypatch.setattr(sys, "stdin", io.StringIO("otra\n"))
    assert run("password", "verify", hashed, "--stdin")[0] == 1
    assert run("password", "verify")[0] == 2


def test_doctor_json(run):
    code, out, _ = run("doctor", "--json")
    data = json.loads(out)
    assert code == 0
    assert {c["name"] for c in data["checks"]} >= {"Python", "PyYAML", "bandit"}


def test_no_color_y_force_color(run, monkeypatch):
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.delenv("NO_COLOR", raising=False)
    try:
        assert "\033[" in run("sla", "--total", "10", "--errors", "0")[1]
        assert "\033[" not in run("sla", "--total", "10", "--errors", "0", "--no-color")[1]
    finally:
        agentes_cli.ui.set_color(None)


def test_la_salida_del_cli_no_lleva_emojis(run, project):
    textos = [run()[1], run("list")[1], run("doctor")[1], run("generate")[1],
              run("pipeline", str(project), "-o", str(project / "rep"), "--no-bandit")[1],
              run("sla", "--total", "10", "--errors", "9")[1]]
    for texto in textos:
        assert not any(ord(ch) >= 0x2600 for ch in texto), "la interfaz del CLI no usa emojis ni pictogramas"


def test_cli_offline_y_no_color_no_filtran_al_proceso(tmp_path, monkeypatch):
    src = tmp_path / "ok.py"
    src.write_text("def uno():\n    return 1\n", encoding="utf-8")
    rep = tmp_path / "rep"

    monkeypatch.delenv("AGENTES_OFFLINE", raising=False)
    agentes_cli.ui.set_color(None)

    assert agentes_cli.main(["analyze", str(src), "-o", str(rep), "--no-bandit", "--offline", "--no-color"]) == 0
    assert "AGENTES_OFFLINE" not in os.environ
    assert agentes_cli.ui._color is None

    monkeypatch.setenv("AGENTES_OFFLINE", "0")
    agentes_cli.ui.set_color(True)
    assert agentes_cli.main(["analyze", str(src), "-o", str(rep), "--no-bandit", "--offline", "--no-color"]) == 0
    assert os.environ.get("AGENTES_OFFLINE") == "0"
    assert agentes_cli.ui._color is True
    agentes_cli.ui.set_color(None)


# --- Pantalla inicial y errores inesperados (casos límite) ---

def test_help_de_un_comando_que_no_existe(run):
    code, _, err = run("help", "despliega")
    assert code == 2 and "No hay ayuda para 'despliega'" in err


@pytest.mark.parametrize("error, codigo, mensaje", [
    (KeyboardInterrupt, 130, "Interrumpido."),
    (BrokenPipeError, 0, ""),
    (RuntimeError("se rompió algo"), 1, "Error inesperado: se rompió algo"),
])
def test_errores_durante_un_comando(run, monkeypatch, error, codigo, mensaje):
    from agentes.sre.alerting_engine import AlertingEngine

    def falla(*args, **kwargs):
        raise error

    monkeypatch.setattr(AlertingEngine, "evaluate_error_rate", falla)
    code, _, err = run("sla", "--total", "10", "--errors", "1")
    assert code == codigo and mensaje in err


def test_agentes_debug_muestra_la_traza(run, monkeypatch):
    from agentes.sre.alerting_engine import AlertingEngine

    monkeypatch.setattr(AlertingEngine, "evaluate_error_rate", lambda *a, **k: 1 / 0)
    monkeypatch.setenv("AGENTES_DEBUG", "1")
    with pytest.raises(ZeroDivisionError):
        run("sla", "--total", "10", "--errors", "1")


# --- Analizar (casos límite) ---

def test_pipeline_baseline_y_write_baseline_a_la_vez(run, project, tmp_path):
    code, _, err = run("pipeline", str(project), "--baseline", "a.json", "--write-baseline", "b.json")
    assert code == 2 and "no se pueden usar a la vez" in err


def test_pipeline_baseline_que_no_es_una_linea_base(run, project, tmp_path):
    bad = tmp_path / "otra.json"
    bad.write_text('{"schema": "otra cosa"}', encoding="utf-8")
    code, _, err = run("pipeline", str(project), "--baseline", str(bad), "-o", str(tmp_path / "r"))
    assert code == 2 and "no es una línea base de agentes" in err


def test_pipeline_avisa_de_entradas_sin_usar_silenciados_y_recorte(run, project, tmp_path):
    baseline = tmp_path / "base.json"
    assert run("pipeline", str(project), "--write-baseline", str(baseline), "-o", str(tmp_path / "r"))[0] == 0
    # El secreto del .env deja de estar: su entrada de la línea base queda sin usar.
    (project / ".env").write_text("DEBUG=true\n", encoding="utf-8")
    (project / "otro.py").write_text("import os\n\nos.system('ls')  # agentes: ignore - comando fijo\n", encoding="utf-8")
    code, out, _ = run("pipeline", str(project), "--baseline", str(baseline), "--max-files", "1",
                       "-o", str(tmp_path / "r"), "--offline", "--no-bandit", "--no-color")
    assert "entradas ya no aparecen: regenera la línea base" in out
    assert "archivos .py quedaron fuera por --max-files" in out


def test_pipeline_texto_informa_de_los_silenciados_y_del_openapi(run, tmp_path):
    (tmp_path / "api.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n\n\n@app.route('/users')\ndef users():\n"
        "    \"\"\"Lista.\"\"\"\n    return []\n\n\ndef run(cmd):\n    \"\"\"Doc.\"\"\"\n"
        "    import subprocess\n    return subprocess.run(cmd, shell=True)  # agentes: ignore - fijo\n",
        encoding="utf-8")
    code, out, _ = run("pipeline", str(tmp_path), "-o", str(tmp_path / "r"), "--offline", "--no-bandit", "--no-color")
    assert code == 0
    assert "silenciados en su línea" in out
    assert "OpenAPI" in out and (tmp_path / "r" / "openapi.json").is_file()


def test_secrets_texto_recuerda_rotar_lo_publicado(run, project):
    code, out, _ = run("secrets", str(project), "--no-color")
    assert code == 1 and "rótalo además de borrarlo" in out


def test_audit_cabeceras_de_una_url(run, http_server, closed_port):
    code, out, _ = run("audit", f"{http_server.url}/json", "--json")
    data = json.loads(out)
    assert data["kind"] == "cabeceras HTTP" and data["findings"]
    assert all(f["rule_id"] == "HTTP-HEADERS" for f in data["findings"])
    # Una respuesta de error también trae cabeceras que auditar.
    assert json.loads(run("audit", f"{http_server.url}/status/404", "--json")[1])["findings"]
    code, _, err = run("audit", f"http://127.0.0.1:{closed_port}/")
    assert code == 2 and "No se pudo conectar" in err


def test_audit_errores_de_uso(run, project):
    code, _, err = run("audit", str(project / "Dockerfile"), "--type", "headers")
    assert code == 2 and "necesita una URL" in err
    code, _, err = run("audit", str(project), "--type", "docker")
    assert code == 2 and "--type solo se aplica a un archivo" in err


def test_vulns_sin_manifiestos(run, tmp_path):
    code, _, err = run("vulns", str(tmp_path))
    assert code == 2 and "No hay manifiestos de dependencias" in err


def test_vulns_texto_con_restricciones_que_bloquean_la_correccion(run, tmp_path, red_simulada):
    (tmp_path / "requirements.txt").write_text("flask==2.3.3\nrequests>=2\n", encoding="utf-8")
    (tmp_path / "requirements-base.txt").write_text("flask>=2,<3\n", encoding="utf-8")
    code, out, _ = run("vulns", str(tmp_path), "--no-color")
    assert code == 1
    assert "dependencias sin versión exacta no se pueden comprobar" in out
    assert "Restricciones que impiden instalar la corrección" in out and "necesita 3.0.0" in out
    assert "Actualiza cada paquete al menos a la versión corregida" in out


def test_vulns_si_osv_no_responde(run, tmp_path, red_simulada, monkeypatch):
    from agentes.quality import vulnerabilities

    def caido(deps, timeout=15.0):
        raise vulnerabilities.VulnDBUnavailable("tiempo agotado")

    monkeypatch.setattr(vulnerabilities, "query_osv", caido)
    (tmp_path / "requirements.txt").write_text("flask==2.3.3\n", encoding="utf-8")
    code, _, err = run("vulns", str(tmp_path))
    assert code == 2 and "No se pudo consultar OSV: tiempo agotado" in err


def test_metrics_sin_archivos_y_con_rendimiento(run, tmp_path):
    code, _, err = run("metrics", str(tmp_path))
    assert code == 2 and "No hay archivos .py" in err
    (tmp_path / "m.py").write_text('"""Doc."""\n\n\ndef f(cola):\n    """Doc."""\n    while cola:\n'
                                   "        cola.pop(0)\n", encoding="utf-8")
    data = json.loads(run("metrics", str(tmp_path), "--json")[1])
    assert any(f["rule_id"] == "PERF" for f in data["findings"])


# --- Generar y corregir (casos límite) ---

def test_generate_openapi_de_una_fuente_rota_o_sin_rutas(run, tmp_path):
    broken = tmp_path / "rota.py"
    broken.write_text("def (:\n", encoding="utf-8")
    code, _, err = run("generate", "openapi", "--source", str(broken), "-o", str(tmp_path / "oa.json"))
    assert code == 2 and "No se pudo leer" in err
    plain = tmp_path / "plano.py"
    plain.write_text("def calcula(x):\n    return x\n", encoding="utf-8")
    code, out, err = run("generate", "openapi", "--source", str(plain), "-o", str(tmp_path / "oa.json"), "--no-color")
    assert code == 0 and "No se detectó ninguna ruta" in out + err


def test_generate_tests_salida_por_defecto_y_fuente_invalida(run, tmp_path):
    source = tmp_path / "calc.py"
    source.write_text("def doble(x):\n    return x * 2\n", encoding="utf-8")
    assert run("generate", "tests", "--source", str(source))[0] == 0
    assert (tmp_path / "test_calc.py").is_file()
    broken = tmp_path / "rota.py"
    broken.write_text("def (:\n", encoding="utf-8")
    code, _, err = run("generate", "tests", "--source", str(broken), "-o", str(tmp_path / "t.py"))
    assert code == 2 and "revisa que sea Python válido" in err


def test_generate_tests_record_avisa_y_falla_si_el_modulo_no_carga(run, tmp_path):
    source = tmp_path / "calc.py"
    source.write_text("def doble(x):\n    return x * 2\n", encoding="utf-8")
    code, out, err = run("generate", "tests", "--source", str(source), "-o", str(tmp_path / "t1.py"), "--record",
                         "--no-color")
    assert code == 0
    assert "--record importa y ejecuta" in out + err and "fijan el comportamiento actual" in out + err
    broken = tmp_path / "explota.py"
    broken.write_text("raise RuntimeError('no cargo')\n\n\ndef f(x):\n    return x\n", encoding="utf-8")
    code, _, err = run("generate", "tests", "--source", str(broken), "-o", str(tmp_path / "t2.py"), "--record")
    assert code == 2 and "Genera la suite sin --record" in err


def test_generate_linters_no_sobrescribe(run, tmp_path):
    out_dir = tmp_path / "cfg"
    assert run("generate", "linters", "-o", str(out_dir))[0] == 0
    code, out, err = run("generate", "linters", "-o", str(out_dir), "--no-color")
    assert code == 0 and "Se conserva" in out + err and "No se generó ningún archivo." in out + err


def test_fix_default_version_avisa_de_que_no_tiene_efecto(run, project):
    code, out, err = run("fix", str(project / "requirements.txt"), "--default-version", "1.0", "--no-color")
    assert "--default-version ya no tiene efecto" in out + err
    assert code == 2, "sin conexión no se puede fijar nada"


def test_fix_texto_sin_cambios_sin_resolver_y_aplicado(run, tmp_path, red_simulada, monkeypatch):
    from agentes.quality import dependency_auditor
    from agentes.quality.package_index import PackageNotFound

    indice = {"requests": ["2.31.0", "2.32.3"]}

    def pypi(name, timeout=10.0):
        if name not in indice:
            raise PackageNotFound(name)
        return indice[name]

    monkeypatch.setattr(dependency_auditor, "pypi_versions", pypi)
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.32.3\n", encoding="utf-8")
    code, out, _ = run("fix", str(req), "--no-color")
    assert code == 0 and "no tiene versiones que fijar" in out

    req.write_text("requests>=2\nno-existe>=1\n", encoding="utf-8")
    code, out, _ = run("fix", str(req), "--no-color")
    assert "Sin cambios" in out and "no-existe" in out
    assert "1 correcciones aplicadas" in out
    assert req.read_text(encoding="utf-8").startswith("requests==2.32.3")


def test_fix_si_osv_no_responde_lo_dice(run, tmp_path, red_simulada, monkeypatch):
    from agentes.quality import vulnerabilities

    def caido(deps, timeout=15.0):
        raise vulnerabilities.VulnDBUnavailable("tiempo agotado")

    monkeypatch.setattr(vulnerabilities, "query_osv", caido)
    req = tmp_path / "requirements.txt"
    req.write_text("requests>=2\n", encoding="utf-8")
    code, out, err = run("fix", str(req), "--dry-run", "--no-color")
    assert code == 0 and "No se pudo consultar OSV: tiempo agotado" in out + err


# --- Probar (casos límite) ---

def test_test_sin_tests_o_con_la_suite_rota(run, tmp_path):
    vacia = tmp_path / "test_vacia.py"
    vacia.write_text("x = 1\n", encoding="utf-8")
    code, out, _ = run("test", str(vacia), "--no-color")
    assert code == 1 and "No se encontró ningún test unittest" in out
    rota = tmp_path / "test_rota.py"
    rota.write_text("def (:\n", encoding="utf-8")
    # unittest no falla al descubrirla: la suite rota cuenta como una prueba con error.
    code, out, _ = run("test", str(rota), "--no-color")
    assert code == 1 and "SyntaxError" in out
    data = json.loads(run("test", str(rota), "--json")[1])
    assert (data["tests_run"], data["errors"]) == (1, 1)


def test_test_muestra_los_fallos_y_la_calidad_de_la_suite(run, tmp_path):
    (tmp_path / "modq.py").write_text("def triple(x):\n    return x * 3\n", encoding="utf-8")
    suite = tmp_path / "test_modq.py"
    suite.write_text(
        "import unittest\nfrom modq import triple\n\n"
        "class T(unittest.TestCase):\n"
        "    def test_triple(self):\n        self.assertEqual(triple(2), 7)\n"
        "    def test_tautologia(self):\n        self.assertTrue(True)\n",
        encoding="utf-8",
    )
    code, out, _ = run("test", str(suite), "--no-color")
    assert code == 1
    assert "Tests que no pasan" in out and "AssertionError" in out and "--verbose" in out
    assert "Calidad de la suite" in out and "WEAK-ASSERT" in out
    assert "1 tests no pasan." in out
    code, out, _ = run("test", str(suite), "--verbose", "--no-color")
    assert "Traceback" in out


def test_testability_en_texto_con_y_sin_matriz(run, project):
    code, out, _ = run("testability", str(project / "app.py"), "--no-color")
    assert code == 0 and "Añade --matrix" in out and "agentes generate tests --source" in out
    code, out, _ = run("testability", str(project / "app.py"), "--matrix", "--limit", "1", "--no-color")
    assert "Escenarios de prueba sugeridos" in out and "Usa --limit 0 para verlos todos." in out


# --- Operar y utilidades (casos límite) ---

def test_sla_sin_trafico(run):
    code, out, err = run("sla", "--total", "0", "--errors", "0", "--no-color")
    assert code == 0 and "Sin tráfico registrado" in out + err


def _stdin(monkeypatch, texto):
    monkeypatch.setattr(sys, "stdin", io.StringIO(texto))


def test_password_check_json(run, monkeypatch):
    _stdin(monkeypatch, "Tr0mb0n-Azul-Lluvia\n")
    code, out, _ = run("password", "check", "--stdin", "--json")
    data = json.loads(out)
    assert code == 0 and data["strength"] in ("aceptable", "fuerte") and data["breaches"] is None


def test_password_hash_avisa_por_stderr_y_deja_solo_el_hash_en_stdout(run, monkeypatch):
    from agentes.defensive import auth_manager

    monkeypatch.setattr(auth_manager, "HAS_ARGON2", False)
    monkeypatch.setattr(auth_manager, "HAS_BCRYPT", False)
    _stdin(monkeypatch, "corta\n")
    code, out, err = run("password", "hash", "--stdin")
    assert code == 0
    assert out.strip().startswith("pbkdf2:sha256:600000:") and len(out.strip().splitlines()) == 1
    assert "la contraseña es débil" in err and "se usa PBKDF2" in err


def test_password_hash_json(run, monkeypatch):
    _stdin(monkeypatch, "Tr0mb0n-Azul-Lluvia\n")
    data = json.loads(run("password", "hash", "--stdin", "--json")[1])
    assert data["hash"].startswith(f"{data['backend'].split(':')[0]}:")


def test_password_verify_pide_regenerar_un_hash_antiguo(run, monkeypatch):
    from agentes.defensive import auth_manager
    from agentes.defensive.auth_manager import AuthManager

    monkeypatch.setattr(auth_manager, "HAS_ARGON2", False)
    monkeypatch.setattr(auth_manager, "HAS_BCRYPT", False)
    antiguo = AuthManager.hash_password("Correcta-123", iterations=1000)
    _stdin(monkeypatch, "Correcta-123\n")
    code, out, err = run("password", "verify", antiguo, "--stdin", "--no-color")
    assert code == 0 and "coincide" in out and "Regenéralo" in out + err
    _stdin(monkeypatch, "Correcta-123\n")
    assert json.loads(run("password", "verify", antiguo, "--stdin", "--json")[1]) == {"valid": True, "needs_rehash": True}
    _stdin(monkeypatch, "Otra-456\n")
    code, out, err = run("password", "verify", antiguo, "--stdin", "--no-color")
    assert code == 1 and "no coincide" in out + err


def test_password_vacia_o_que_no_coincide_al_repetirla(run, monkeypatch):
    _stdin(monkeypatch, "\n")
    code, _, err = run("password", "check", "--stdin")
    assert code == 2 and "La contraseña está vacía." in err
    respuestas = iter(["Primera-123", "Segunda-456"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(respuestas))
    code, _, err = run("password", "hash")
    assert code == 2 and "no coinciden" in err


def test_demo_desconocida_sugiere_la_mas_parecida(run):
    code, _, err = run("demo", "defensiv")
    assert code == 2 and "¿Querías decir 'defensive'?" in err


def test_demo_all_ejecuta_las_ocho_y_escribe_fuera_del_paquete(run, tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTES_WORKDIR", str(tmp_path))
    code, out, _ = run("demo", "all")
    assert code == 0
    for agente, artefacto in [
        ("devops", "docker-compose.yml"), ("docs", "openapi.json"), ("hardening", "Dockerfile.hardened"),
        ("qa", "qa_report.html"), ("quality", "results.sarif"), ("refactor", "sample_monolith.py"),
        ("sre", "sample_app.log"),
    ]:
        assert (tmp_path / agente / artefacto).is_file(), (agente, artefacto)
    assert "Agente QA ejecutado exitosamente." in out


def test_atajo_nombre_de_agente_lanza_su_demo(run, tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTES_WORKDIR", str(tmp_path))
    assert run("docs")[0] == 0
    assert (tmp_path / "docs" / "swagger_ui.html").is_file()


def test_doctor_en_texto_segun_lo_instalado(run, monkeypatch):
    from agentes.cli import ops

    monkeypatch.setattr(ops, "_module_available", lambda name: name != "argon2")
    code, out, _ = run("doctor", "--no-color")
    assert code == 0 and "Listo para usar" in out and 'pip install -e ".[all]"' in out
    monkeypatch.setattr(ops, "_module_available", lambda name: name != "yaml")
    code, out, _ = run("doctor", "--no-color")
    assert code == 1 and "Faltan componentes obligatorios." in out


def test_module_available_no_lanza_con_nombres_raros():
    from agentes.cli import ops

    assert ops._module_available("json")
    assert not ops._module_available("no_existe_este_modulo")
    assert not ops._module_available("no_existe.submodulo")
