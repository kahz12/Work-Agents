"""Tests unitarios ligeros del núcleo compartido y CLI."""
import json
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def test_schema_bool_not_int():
    from agentes.common.schema import validate_typed_schema
    ok, errs = validate_typed_schema({"age": True}, {"age": int})
    assert not ok
    assert errs


def test_schema_nested_and_extra():
    from agentes.common.schema import validate_typed_schema
    ok, _ = validate_typed_schema({"u": {"n": "a"}}, {"u": {"n": str}})
    assert ok
    bad, errs = validate_typed_schema({"n": "x", "e": 1}, {"n": str}, reject_extra_keys=True)
    assert not bad


def test_reporting_writes_artifacts(tmp_path):
    from agentes.common.reporting import build_pipeline_report, findings_to_sarif, write_html_summary, write_json_report
    report = build_pipeline_report(str(tmp_path), [{"name": "t", "status": "ok", "summary": "x", "findings_count": 0}])
    jp = write_json_report(report, str(tmp_path / "r.json"))
    hp = write_html_summary(report, str(tmp_path / "r.html"))
    sp = findings_to_sarif("T", [{"file": "a.py", "line": 1, "level": "ALTO", "message": "m"}], str(tmp_path / "r.sarif"))
    assert os.path.isfile(jp) and os.path.isfile(hp) and os.path.isfile(sp)
    assert json.loads(open(jp).read())["schema"] == "agentes.pipeline.v1"


def test_cli_list_exit_0():
    import agentes_cli
    assert agentes_cli.main(["list"]) == 0


def test_csrf_with_colons():
    from agentes.defensive.auth_manager import AuthManager
    tok = AuthManager.create_csrf_token("s", "a:b:c")
    assert AuthManager.verify_csrf_token(tok, "s", "a:b:c")


def test_sast_detects_hardcoded_secret(tmp_path):
    from agentes.quality.static_checker import StaticCodeAnalyzer
    p = tmp_path / "bad.py"
    p.write_text('API_KEY = "supersecretvalue123"\n', encoding="utf-8")
    issues = StaticCodeAnalyzer.analyze_python_file(str(p), prefer_bandit=False)
    assert any("secreto" in i[2].lower() or "API_KEY" in i[2] for i in issues)


def test_openapi_fastapi_decorator(tmp_path):
    from agentes.docs.openapi_generator import OpenAPIGenerator
    p = tmp_path / "app.py"
    p.write_text(
        'app = None\n'
        '@app.get("/items")\n'
        'def list_items():\n'
        '    """Lista."""\n'
        '    return []\n',
        encoding="utf-8",
    )
    spec = OpenAPIGenerator.generate_openapi_spec(str(p))
    assert "/items" in spec["paths"]
    assert "get" in spec["paths"]["/items"]


# --- Garantías de sanitización HTML, cobertura total de archivos y motor SAST ---

def test_html_summary_escapa_contenido_hostil(tmp_path):
    """El reporte HTML no debe ejecutar lo que venga del código escaneado."""
    from agentes.common.reporting import build_pipeline_report, write_html_summary
    payload = "<script>alert(1)</script>"
    report = build_pipeline_report(
        str(tmp_path / payload),
        [{"name": payload, "status": "ok", "summary": payload, "findings_count": 0}],
    )
    out = write_html_summary(report, str(tmp_path / "r.html"))
    body = open(out, encoding="utf-8").read()
    assert payload not in body
    assert "&lt;script&gt;" in body


def test_pipeline_no_recorta_por_defecto(tmp_path):
    """Sin max_files se escanean todos los archivos: no hay un límite implícito."""
    from agentes.common.orchestrator import run_pipeline
    for i in range(250):
        (tmp_path / f"f{i:03d}.py").write_text(f'PASSWORD = "hardcodedsecret{i:03d}"\n', encoding="utf-8")
    report, _ = run_pipeline(
        str(tmp_path), agents_root=ROOT, output_dir=str(tmp_path / "rep"),
        fail_on_high=False, prefer_bandit=False,
    )
    assert report["files_scanned"] == 250
    assert report["files_skipped"] == 0
    # Garantizar que el recorrido completo incluye también los últimos archivos ordenados alfabéticamente.
    tarde = [f for f in report["findings"] if f["file"].endswith("f249.py")]
    assert tarde, "el último archivo no aparece en los hallazgos"


def test_pipeline_declara_lo_que_no_escaneo(tmp_path):
    """Con max_files el recorte queda escrito en el reporte, no en silencio."""
    from agentes.common.orchestrator import run_pipeline
    for i in range(30):
        (tmp_path / f"f{i:02d}.py").write_text("x = 1\n", encoding="utf-8")
    report, _ = run_pipeline(
        str(tmp_path), agents_root=ROOT, output_dir=str(tmp_path / "rep"),
        fail_on_high=False, max_files=10, prefer_bandit=False,
    )
    assert report["files_scanned"] == 10
    assert report["files_skipped"] == 20
    sast = next(s for s in report["stages"] if s["name"] == "quality_sast")
    assert "20 archivos NO escaneados" in sast["summary"]


def test_pipeline_motor_por_defecto_intacto(tmp_path):
    """Con el motor por defecto (Bandit si está instalado) el pipeline también informa de los hallazgos."""
    from agentes.common.orchestrator import run_pipeline
    (tmp_path / "app.py").write_text('import subprocess\nsubprocess.Popen("ls", shell=True)\n', encoding="utf-8")
    report, _ = run_pipeline(
        str(tmp_path), agents_root=ROOT, output_dir=str(tmp_path / "rep"), fail_on_high=False
    )
    sast = next(s for s in report["stages"] if s["name"] == "quality_sast")
    assert sast["engine"] in ("bandit+ast", "ast")
    assert sast["findings_count"] >= 1


def _declared_packages():
    """Lee [tool.setuptools].packages sin depender de tomllib (3.11+)."""
    try:
        import tomllib
    except ImportError:  # En Python anterior a 3.11 tomllib aún no forma parte de la biblioteca estándar.
        tomllib = None
    path = os.path.join(ROOT, "pyproject.toml")
    if tomllib is not None:
        with open(path, "rb") as fh:
            return set(tomllib.load(fh)["tool"]["setuptools"]["packages"])
    import re
    body = open(path, encoding="utf-8").read()
    block = re.search(r"^packages = \[(.*?)\]", body, re.S | re.M)
    assert block, "no se encontró la lista packages en pyproject.toml"
    return set(re.findall(r'"([^"]+)"', block.group(1)))


def test_paquetes_de_agentes_declarados_para_el_wheel():
    """pip install . debe llevarse los 8 agentes, no solo agentes.common."""
    declared = _declared_packages()
    for agent in ("cli", "common", "qa", "quality", "defensive", "devops", "docs", "hardening", "refactor", "sre"):
        assert f"agentes.{agent}" in declared, f"agentes.{agent} no va en el wheel"
        assert os.path.isfile(os.path.join(ROOT, "agentes", agent, "__init__.py"))


def test_no_quedan_paquetes_de_nivel_superior_genericos():
    """Todo vive bajo agentes/: nada de un paquete 'common' suelto en site-packages."""
    declared = _declared_packages()
    assert all(p == "agentes" or p.startswith("agentes.") for p in declared), declared


def test_la_libreria_no_manipula_sys_path():
    """Los imports internos son relativos; ningún módulo de agentes/ toca sys.path."""
    import glob
    for path in glob.glob(os.path.join(ROOT, "agentes", "**", "*.py"), recursive=True):
        if os.path.basename(path) == "test_runner.py":
            continue  # ejecuta suites de terceros y necesita su directorio en sys.path
        if os.path.basename(path) == "expected_values.py":
            continue  # el sys.path que toca es el del proceso hijo que graba resultados
        if os.path.basename(path) == "call_plan.py":
            continue  # el sys.path que toca es el de la suite que genera, no el de agentes
        body = open(path, encoding="utf-8").read()
        assert "sys.path.insert" not in body, path


def test_output_dir_cae_al_cwd_si_la_instalacion_es_solo_lectura(tmp_path, monkeypatch):
    from agentes.common import workspace
    monkeypatch.setattr(workspace.os, "access", lambda p, m: False)
    monkeypatch.delenv("AGENTES_WORKDIR", raising=False)
    monkeypatch.chdir(tmp_path)
    out = workspace.agent_output_dir(os.path.join(ROOT, "agentes", "qa", "main.py"))
    assert out == str(tmp_path / "qa")
    assert os.path.isdir(out)


def test_output_dir_respeta_AGENTES_WORKDIR(tmp_path, monkeypatch):
    from agentes.common import workspace
    monkeypatch.setenv("AGENTES_WORKDIR", str(tmp_path / "wd"))
    out = workspace.agent_output_dir(os.path.join(ROOT, "agentes", "qa", "main.py"))
    assert out == str(tmp_path / "wd" / "qa")


# --- Resiliencia ante fuentes ilegibles, permisos restringidos e invariantes de auditoría ---

def test_pipeline_sobrevive_a_un_py_que_no_parsea(tmp_path):
    """Un solo fuente roto no puede tumbar el pipeline y perder el reporte entero."""
    from agentes.common.orchestrator import run_pipeline
    (tmp_path / "aaa_roto.py").write_text("def (:\n", encoding="utf-8")
    (tmp_path / "zzz.py").write_text('PASSWORD = "secreto123456"\n', encoding="utf-8")
    report, _ = run_pipeline(
        str(tmp_path), agents_root=ROOT, output_dir=str(tmp_path / "rep"),
        fail_on_high=False, prefer_bandit=False,
    )
    assert os.path.isfile(str(tmp_path / "rep" / "pipeline.json"))
    roto = str(tmp_path / "aaa_roto.py")
    assert any(f["file"] == roto and "sintaxis" in f["message"] for f in report["findings"])
    metrics = next(s for s in report["stages"] if s["name"] == "refactor_metrics")
    assert any("aaa_roto.py" in e for e in metrics["errors"])
    # El fallo de análisis sintáctico en un módulo no debe impedir la detección de secretos en módulos válidos.
    assert any(f.get("rule_id") == "SECRET" for f in report["findings"])

    # Con un framework web, la etapa de OpenAPI también informa del archivo que no se pudo leer.
    (tmp_path / "web.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    report, _ = run_pipeline(
        str(tmp_path), agents_root=ROOT, output_dir=str(tmp_path / "rep"),
        fail_on_high=False, prefer_bandit=False,
    )
    docs = next(s for s in report["stages"] if s["name"] == "documentation")
    assert docs["status"] == "fail" and docs["errors"]


def test_openapi_no_lanza_con_fuente_ilegible(tmp_path):
    from agentes.docs.openapi_generator import OpenAPIGenerator
    roto = tmp_path / "r.py"
    roto.write_text("def (:\n", encoding="utf-8")
    spec = OpenAPIGenerator.generate_openapi_spec(str(roto))
    assert spec["x-agentes-errors"]
    assert OpenAPIGenerator.generate_openapi_spec(str(tmp_path / "no.py"))["x-agentes-errors"]


def test_testgen_no_lanza_con_fuente_ilegible(tmp_path):
    from agentes.qa.test_generator import QATestGenerator
    roto = tmp_path / "r.py"
    roto.write_text("def (:\n", encoding="utf-8")
    assert QATestGenerator.generate_test_suite(str(roto), str(tmp_path / "t.py")) == ""


def test_dockerfile_user_no_root_no_es_falso_positivo(tmp_path):
    """'nonroot' contiene 'root' y '1000' contiene '0': no vale buscar subcadenas."""
    from agentes.hardening.container_hardening import ContainerHardening

    def avisa_de_root(linea):
        p = tmp_path / ("Dockerfile" + linea.replace(" ", "_").replace(":", "-"))
        p.write_text(f"FROM python:3.12-slim\n{linea}\n", encoding="utf-8")
        return any("root" in f[2] or "usuario" in f[2] for f in ContainerHardening.audit_dockerfile(str(p)))

    for correcto in ("USER appuser", "USER nonroot", "USER app10", "USER 1000", "USER 1000:1000"):
        assert not avisa_de_root(correcto), correcto
    for inseguro in ("USER root", "USER 0", "USER root:root"):
        assert avisa_de_root(inseguro), inseguro


def test_systemd_directiva_comentada_o_desactivada_no_cuenta(tmp_path):
    from agentes.hardening.service_hardening import ServiceHardening

    def limpio(body):
        p = tmp_path / (str(abs(hash(body))) + ".service")
        p.write_text(body, encoding="utf-8")
        r = ServiceHardening.audit_systemd_service(str(p))
        return bool(r) and r[0][1] == "OK"

    completo = "[Service]\nNoNewPrivileges=true\nProtectHome=true\nPrivateTmp=true\nProtectSystem=strict\n"
    assert limpio(completo)
    assert limpio("[Service]\nNoNewPrivileges = true\nProtectHome = true\nPrivateTmp = true\nProtectSystem = full\n")
    assert not limpio("[Service]\n# NoNewPrivileges=true\n# ProtectHome=true\n# PrivateTmp=true\n# ProtectSystem=strict\n")
    assert not limpio(completo.replace("ProtectSystem=strict", "ProtectSystem=false"))
    assert not limpio(completo.replace("NoNewPrivileges=true", "NoNewPrivileges=no"))


def test_escaneo_de_secretos_no_silencia_ficheros_ilegibles(tmp_path):
    from agentes.defensive.config_manager import ConfigManager
    d = tmp_path / "soy_un_dir"
    d.mkdir()
    for ruta in (str(d), str(tmp_path / "no_existe.py")):
        r = ConfigManager.scan_file_for_secrets(ruta)
        assert r and "ERROR" in r[0][1], ruta


def test_load_env_file(tmp_path):
    """load_env_file devuelve las variables del .env sin comillas ni espacios y sin las líneas mal formadas."""
    from agentes.defensive.config_manager import ConfigManager
    env = tmp_path / ".env"
    env.write_text('# comentario\nAPI_KEY="secreto"\nVACIO=\nMAL_FORMADA\nESPACIOS = con espacios \n', encoding="utf-8")
    assert ConfigManager.load_env_file(str(env)) == {
        "API_KEY": "secreto", "VACIO": "", "ESPACIOS": "con espacios",
    }


# --- Detección de secretos: corpus de positivos y negativos ---

# Los tokens falsos van partidos en dos literales ("ghp_" "16C7..."): Python los une y el detector
# recibe el token entero, pero el archivo no contiene ninguno completo y la protección de
# secretos de GitHub no bloquea el push.
SECRETOS_REALES = [
    ("aws access key id", 'AWS_KEY = "AKIA' 'IOSFODNN7EXAMPLE"'),
    ("aws temp key", 'k = "ASIA' 'IOSFODNN7EXAMPLE"'),
    ("aws secret key", 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'),
    ("github pat", 'tok = "ghp_' '16C7e42F292c6912E7710c838347Ae178B4a"'),
    ("github fine-grained", 'tok = "github_pat_' '11ABCDEFG0abcdefghijkl_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"'),
    ("slack bot", 'S = "xox' 'b-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"'),
    ("slack webhook", 'u = "https://hooks.slack.com/' 'services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"'),
    ("stripe", 'S = "sk_live_' '4eC39HqLyjWDarjtT1zdp7dc"'),
    ("google api", 'G = "AIza' 'SyC93bGF5ANjEHVfLbSGJVQoxCvXBMDGF4o"'),
    ("openai", 'O = "sk-proj-' 'abcdefghijklmnopqrstuvwxyz0123456789ABCD"'),
    ("anthropic", 'A = "sk-ant-' 'api03-abcdefghijklmnopqrstuvwxyz0123456789"'),
    ("sendgrid", 'S = "SG.' 'ngeVfQFYQlKU0ufo8x5d1A.TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopyDO0QSwM"'),
    ("npm", 'N = "npm_' 'abcdefghijklmnopqrstuvwxyz0123456789"'),
    ("clave privada PEM", "-----BEGIN RSA PRIVATE KEY-----"),
    ("clave privada ssh", "-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("jwt", 'j = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"'),
    ("postgres con clave", 'DB = "postgresql://usuario:MiClaveSecreta@db.example.com:5432/prod"'),
    ("mongodb con clave", 'DB = "mongodb+srv://admin:p4ssw0rd@cluster0.mongodb.net/test"'),
    ("basic auth", 'headers = {"Authorization": "Basic dXNlcjpwYXNzd29yZDEyMw=="}'),
    ("token en dict", 'cfg = {"token": "ghp_' 'abcdefghijklmnopqrstuvwxyz0123456789"}'),
    ("token en yaml", 'auth_token: "abcdef1234567890abcdef1234"'),
    ("client_secret", 'client_secret = "abcdefghij0123456789ABCDEFGHIJ"'),
    ("passphrase", 'passphrase = "correcthorsebatterystaple"'),
]

NO_SON_SECRETOS = [
    ("desde entorno", 'API_KEY = os.environ["API_KEY"]'),
    ("desde getenv", 'password = os.getenv("DB_PASSWORD")'),
    ("desde config", 'token = config.get("token")'),
    ("placeholder <>", 'password = "<tu-password-aqui>"'),
    ("placeholder xxx", 'api_key = "xxxxxxxxxxxx"'),
    ("placeholder your-", 'secret = "your-secret-here"'),
    ("format string", 'password = "%s"'),
    ("f-string", 'token = f"{prefix}-{suffix}"'),
    ("vacio", 'password = ""'),
    ("nombra un campo", 'password_field_name = "password"'),
    ("comentario", '# password = "esto es un ejemplo"'),
    ("url sin credencial", 'DB = "postgresql://db.example.com:5432/prod"'),
    ("import", "from mymodule import secret_manager"),
    ("literal corto", 'token = "abc"'),
    ("ruta a fichero", 'key_path = "/etc/ssl/private/server.key"'),
]


@pytest.mark.parametrize("etiqueta,contenido", SECRETOS_REALES, ids=[x[0] for x in SECRETOS_REALES])
def test_detecta_secreto(tmp_path, etiqueta, contenido):
    from agentes.defensive.config_manager import ConfigManager
    p = tmp_path / "c.py"
    p.write_text(contenido + "\n", encoding="utf-8")
    assert ConfigManager.scan_file_for_secrets(str(p)), etiqueta


@pytest.mark.parametrize("etiqueta,contenido", NO_SON_SECRETOS, ids=[x[0] for x in NO_SON_SECRETOS])
def test_no_es_falso_positivo(tmp_path, etiqueta, contenido):
    from agentes.defensive.config_manager import ConfigManager
    p = tmp_path / "c.py"
    p.write_text(contenido + "\n", encoding="utf-8")
    assert not ConfigManager.scan_file_for_secrets(str(p)), etiqueta


def test_sast_detecta_secretos_en_dict_y_kwargs(tmp_path):
    """El motor AST detecta secretos también en literales dict y en argumentos con nombre."""
    from agentes.quality.static_checker import StaticCodeAnalyzer

    def halla(code):
        p = tmp_path / (str(abs(hash(code))) + ".py")
        p.write_text(code + "\n", encoding="utf-8")
        return any("secreto" in i[2].lower() for i in StaticCodeAnalyzer.analyze_python_file(str(p), prefer_bandit=False))

    assert halla('cfg = {"token": "ghp_abcdefghijklmnopqrstuvwxyz0123"}')
    assert halla('conectar(password="MiClaveSuperSecreta")')
    assert halla('self.api_key = "abcdef1234567890abcdef"')
    assert not halla('API_KEY = os.environ["API_KEY"]')
    assert not halla('password = "changeme"')
    assert not halla('password_field_name = "password"')


def test_la_version_no_se_desincroniza():
    """agentes.__version__ es la fuente única; pyproject la toma de ahí."""
    pyproject = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    assert 'version = {attr = "agentes.__version__"}' in pyproject
    assert "\nversion = " not in pyproject.split("[tool.setuptools.dynamic]")[0], \
        "pyproject no debe fijar la versión a mano"


def test_cli_expone_version():
    import subprocess
    r = subprocess.run(
        [sys.executable, os.path.join(ROOT, "agentes_cli.py"), "--version"],
        capture_output=True, text=True,
    )
    from agentes import __version__
    assert r.returncode == 0
    assert __version__ in (r.stdout + r.stderr)


# --- Integridad de reportes SARIF/HTML y cobertura integral multiarchivo ---

def test_sarif_rutas_relativas_y_html_lista_hallazgos(tmp_path):
    from agentes.common.reporting import build_pipeline_report, findings_to_sarif, write_html_summary

    nested = tmp_path / "pkg" / "mod.py"
    nested.parent.mkdir(parents=True)
    nested.write_text("x = 1\n", encoding="utf-8")

    findings = [{
        "file": str(nested),
        "line": 7,
        "level": "ALTO",
        "rule_id": "SAST-ALTO",
        "message": "<script>xss</script>",
    }]
    sarif_path = findings_to_sarif("T", findings, str(tmp_path / "out.sarif"), base_dir=str(tmp_path))
    sarif = json.loads(open(sarif_path, encoding="utf-8").read())
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "pkg/mod.py"

    report = build_pipeline_report(str(tmp_path), [{"name": "quality", "status": "fail", "summary": "1", "findings_count": 1}])
    report["findings"] = findings
    html_path = write_html_summary(report, str(tmp_path / "out.html"))
    html_body = open(html_path, encoding="utf-8").read()
    assert "Hallazgos (1)" in html_body
    assert "pkg/mod.py" in html_body
    assert "SAST-ALTO" in html_body
    assert "<script>xss</script>" not in html_body
    assert "&lt;script&gt;xss&lt;/script&gt;" in html_body


def test_pipeline_multiarchivo_secrets_metricas_openapi_e_infra(tmp_path):
    from agentes.common.orchestrator import run_pipeline

    pkg = tmp_path / "app"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "routes_a.py").write_text(
        'from fastapi import APIRouter\n'
        'router = APIRouter()\n'
        '@router.get("/users")\n'
        'def list_users():\n'
        '    """Lista usuarios."""\n'
        '    if True:\n'
        '        return []\n',
        encoding="utf-8",
    )
    (pkg / "routes_b.py").write_text(
        'from fastapi import APIRouter\n'
        'router = APIRouter()\n'
        '@router.post("/orders")\n'
        'def create_order(item_id: int):\n'
        '    """Crea orden."""\n'
        '    return {"id": item_id}\n'
        'def get_helper():\n'
        '    """Helper interno: no es un endpoint aunque empiece por get_."""\n'
        '    return 1\n',
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text('GITHUB_TOKEN="ghp_' '16C7e42F292c6912E7710c838347Ae178B4a"\n', encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nUSER root\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("requests\n", encoding="utf-8")

    rep_dir = tmp_path / "rep"
    report, code = run_pipeline(
        str(tmp_path), agents_root=ROOT, output_dir=str(rep_dir),
        fail_on_high=True, prefer_bandit=False,
    )
    assert code == 1

    # El esquema OpenAPI fusiona los endpoints declarados en todos los submódulos del paquete.
    spec = json.loads((rep_dir / "openapi.json").read_text(encoding="utf-8"))
    assert "/users" in spec["paths"]
    assert "/orders" in spec["paths"]
    assert "/helper" not in spec["paths"], "en el pipeline solo cuentan los decoradores"

    # Los archivos de entorno (.env) se analizan junto al código Python para detectar credenciales expuestas.
    secrets_stage = next(s for s in report["stages"] if s["name"] == "defensive_secrets")
    assert secrets_stage["extra_config_files"] >= 1
    assert any(f["rule_id"] == "SECRET" and f["file"].endswith(".env") for f in report["findings"])

    # Las métricas estructurales se agregan sobre la totalidad de módulos del proyecto, no solo __init__.py.
    metrics_stage = next(s for s in report["stages"] if s["name"] == "refactor_metrics")
    assert metrics_stage["metrics"]["functions_count"] == 3

    # Los manifiestos de contenedores y dependencias se procesan dentro del análisis integral.
    infra_stage = next(s for s in report["stages"] if s["name"] == "infra_and_deps")
    assert infra_stage["files_scanned"] >= 2
    assert any(f["rule_id"] == "DOCKERFILE" for f in report["findings"])
    assert any(f["rule_id"] == "DEPS-PIP" for f in report["findings"])


def test_sast_annassign_y_descuento_self_cls(tmp_path):
    from agentes.quality.static_checker import StaticCodeAnalyzer

    p = tmp_path / "ann.py"
    p.write_text(
        'API_KEY: str = "supersecretvalue123"\n'
        'class Svc:\n'
        '    def metodo(self, a, b, c, d, e):\n'
        '        """Cinco params reales aparte de self."""\n'
        '        return a\n'
        '    @classmethod\n'
        '    def construir(cls, a, b, c, d, e):\n'
        '        """Cinco params reales aparte de cls."""\n'
        '        return a\n',
        encoding="utf-8",
    )
    issues = StaticCodeAnalyzer.analyze_python_file(str(p), prefer_bandit=False)
    assert any("API_KEY" in msg for _, _, msg in issues)
    assert not any("argumentos" in msg for _, _, msg in issues)


def test_dependency_auditor_extras_y_marcadores(tmp_path):
    from agentes.quality.dependency_auditor import DependencyAuditor

    req = tmp_path / "requirements.txt"
    req.write_text(
        'uvicorn[standard]>=0.27 ; python_version >= "3.10" # server\n'
        'requests[security] ; sys_platform != "win32"\n',
        encoding="utf-8",
    )
    findings = DependencyAuditor.audit_requirements_txt(str(req))
    assert any("uvicorn[standard]>=0.27" in f[0] for f in findings)
    assert any("requests[security]" in f[0] for f in findings)

    indice = {"uvicorn": ["0.26.0", "0.27.0", "0.30.1", "0.31.0rc1"], "requests": ["2.31.0", "2.32.3"]}
    _, count = DependencyAuditor.auto_fix_requirements_txt(str(req), index=lambda n: indice[n.split("[")[0]])
    assert count == 2
    fixed = req.read_text(encoding="utf-8")
    # La última versión estable que cumple el rango, no el límite inferior ni una prerrelease.
    assert 'uvicorn[standard]==0.30.1 ; python_version >= "3.10" # server' in fixed
    assert 'requests[security]==2.32.3 ; sys_platform != "win32"' in fixed


def test_qa_test_generator_clases_y_type_hints(tmp_path):
    from agentes.qa.test_generator import QATestGenerator
    from agentes.qa.test_runner import QATestRunner

    src = tmp_path / "calc_mod.py"
    src.write_text(
        'from typing import List, Dict\n'
        'class Calc:\n'
        '    def __init__(self, base: int = 10):\n'
        '        self.base = base\n'
        '    def combinar(self, items: List[int], mapa: Dict[str, int], activo: bool):\n'
        '        return len(items) + len(mapa) + (self.base if activo else 0)\n',
        encoding="utf-8",
    )
    tst = tmp_path / "test_calc_mod.py"
    QATestGenerator.generate_test_suite(str(src), str(tst))
    body = tst.read_text(encoding="utf-8")

    # Verificar que los métodos de instancia se invoquen sobre el objeto instanciado y no como funciones libres.
    # base tiene valor por defecto: no se pasa y el constructor usa el suyo.
    assert "result = combinar(" not in body
    assert "obj = Calc()" in body
    # Los contenedores anotados llevan un elemento de su tipo: con uno vacío, items[0] fallaría.
    assert 'obj.combinar([1], {"sample": 1}, True)' in body

    res = QATestRunner.run_unittest_suite(str(tst))
    assert res["tests_run"] == 1
    assert res["pass_rate_percentage"] == 100.0
    assert res["coverage"]["functions_tested"] == 1


def test_refactor_sin_doble_conteo_y_mermaid_valido(tmp_path):
    from agentes.refactor.architecture_diagram import ArchitectureDiagramGenerator
    from agentes.refactor.code_metrics import CodeMetricsCalculator
    from agentes.refactor.solid_checker import SOLIDChecker

    mod = tmp_path / "nested_mod.py"
    mod.write_text(
        'def outer(x):\n'
        '    if x > 0:\n'
        '        pass\n'
        '    def inner(y):\n'
        '        if y == 1:\n'
        '            return 1\n'
        '        if y == 2:\n'
        '            return 2\n'
        '        if y == 3:\n'
        '            return 3\n'
        '        return 0\n'
        '    return inner(x)\n'
        'class Big:\n'
        + "".join(f"    def m{i}(self): pass\n" for i in range(7)),
        encoding="utf-8",
    )

    metrics = CodeMetricsCalculator.calculate_file_metrics(str(mod))
    by_name = {name: (cyc, cog) for name, _, cyc, cog in metrics["function_details"]}
    assert by_name["outer"] == (2, 1)
    assert by_name["inner"] == (4, 3)

    solid = SOLIDChecker.audit_file(str(mod))
    assert not any(f[1] == "OCP" for f in solid)

    diagram = ArchitectureDiagramGenerator.generate_mermaid_diagram(str(mod))
    assert "+..." not in diagram
    assert "%% +2 métodos adicionales en Big" in diagram


# --- Controles defensivos de seguridad, manejo de tokens y análisis estático AST ---

def test_input_sanitizer_path_canonico_y_punto(tmp_path):
    from agentes.defensive.input_sanitizer import InputSanitizer

    assert InputSanitizer.sanitize_filename(".") == "file_default"
    base = tmp_path / "sandbox"
    base.mkdir()
    ok = InputSanitizer.validate_safe_path(str(base), "sub/file.txt")
    assert ok is not None and ok.endswith("sandbox/sub/file.txt")
    assert InputSanitizer.validate_safe_path(str(base), "../../etc/passwd") is None
    assert InputSanitizer.validate_safe_path(str(base), "/etc/passwd") is None
    assert InputSanitizer.validate_safe_path(str(base), "a\x00b") is None


def test_config_manager_env_protegido_y_redaccion_secretos(tmp_path, monkeypatch):
    from agentes.defensive.config_manager import ConfigManager

    monkeypatch.setenv("EXISTING_VAR", "original")
    monkeypatch.delenv("LD_PRELOAD", raising=False)
    monkeypatch.delenv("SAFE_NEW_VAR", raising=False)

    env = tmp_path / ".env"
    env.write_text(
        'LD_PRELOAD=/tmp/evil.so\n'
        'PYTHONPATH=/tmp/evil\n'
        'EXISTING_VAR=override_attempt\n'
        'SAFE_NEW_VAR=valor_seguro\n',
        encoding="utf-8",
    )
    loaded = ConfigManager.load_env_file(str(env))
    assert "LD_PRELOAD" not in loaded
    assert "PYTHONPATH" not in loaded
    assert "LD_PRELOAD" not in os.environ
    assert os.environ["EXISTING_VAR"] == "original"
    assert loaded["SAFE_NEW_VAR"] == "valor_seguro"

    secret_val = "ghp_" "16C7e42F292c6912E7710c838347Ae178B4a"
    sec_file = tmp_path / "sec.py"
    sec_file.write_text(f'TOKEN = "{secret_val}"\n', encoding="utf-8")
    hits = ConfigManager.scan_file_for_secrets(str(sec_file))
    assert hits
    assert secret_val not in hits[0][2]
    assert "***REDACTED***" in hits[0][2]


def test_auth_manager_alg_none_sin_fuga_y_rate_limiter_acotado():
    import base64
    import hashlib
    import hmac

    from agentes.defensive.auth_manager import AuthManager, RateLimiter

    # Un token con algoritmo 'none' debe rechazarse explícitamente incluso si la firma HMAC coincide.
    hdr = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    pld = base64.urlsafe_b64encode(b'{"user":"admin"}').decode().rstrip("=")
    sig = base64.urlsafe_b64encode(
        hmac.new(b"secret", f"{hdr}.{pld}".encode(), hashlib.sha256).digest()
    ).decode().rstrip("=")
    ok, _, msg = AuthManager.verify_secure_token(f"{hdr}.{pld}.{sig}", "secret")
    assert not ok
    assert "Algoritmo" in msg

    # Los mensajes de rechazo hacia el consumidor no deben exponer trazas de pila ni detalles internos.
    ok_bad, _, msg_bad = AuthManager.verify_secure_token("aaa.bbb.ccc", "secret")
    assert not ok_bad
    assert "Traceback" not in msg_bad

    rl = RateLimiter(max_requests=2, window_seconds=60, max_tracked_keys=3)
    for ip in ("ip1", "ip2", "ip3", "ip4"):
        rl.is_allowed(ip)
    assert len(rl.requests) <= 3


def test_sast_reglas_seguridad_y_concurrencia(tmp_path):
    from agentes.quality.static_checker import StaticCodeAnalyzer

    code = (
        'import hashlib, os, random, requests, time, yaml\n'
        'from urllib.request import urlopen\n'
        'def f(x=[]):\n'
        '    """Demo."""\n'
        '    os.system("id")\n'
        '    yaml.load("a: 1")\n'
        '    cur.execute("SELECT * FROM u WHERE id={}".format(x))\n'
        '    requests.get("https://example.com", verify=False)\n'
        '    urlopen("https://example.com")\n'
        '    hashlib.md5(b"abc")\n'
        '    session_token = "".join(random.choice("ab") for _ in range(8))\n'
        '    if os.path.exists(x):\n'
        '        fh = open(f"/tmp/{x}")\n'
        '        fh.close()\n'
        '    try:\n'
        '        pass\n'
        '    except Exception:\n'
        '        pass\n'
        'async def job():\n'
        '    """Async."""\n'
        '    time.sleep(1)\n'
    )
    p = tmp_path / "sast_cases.py"
    p.write_text(code, encoding="utf-8")
    issues = StaticCodeAnalyzer.analyze_python_file(str(p), prefer_bandit=False)
    msgs = [m for _, _, m in issues]

    assert any("os.system" in m for m in msgs)
    assert any("yaml.load" in m for m in msgs)
    assert any(".format" in m for m in msgs)
    assert any("verify=False" in m for m in msgs)
    assert any("timeout" in m and "HTTP" in m for m in msgs)
    assert any("urlopen" in m and "timeout" in m for m in msgs)
    assert any("hashlib.md5" in m for m in msgs)
    assert any("random" in m and "secrets" in m for m in msgs)
    assert any("Path.resolve" in m for m in msgs)
    assert any("context manager" in m for m in msgs)
    assert any("defecto mutable" in m for m in msgs)
    assert any("except Exception: pass" in m for m in msgs)
    assert any("async def" in m for m in msgs)

    # Comprobar que el archivo existe y después escribirlo es una condición de carrera TOCTOU.
    # Leerlo no: lo peor que pasa es un FileNotFoundError.
    p2 = tmp_path / "toctou.py"
    p2.write_text(
        'import os\n'
        'def leer(ruta):\n'
        '    """Lee."""\n'
        '    if os.path.exists(ruta):\n'
        '        with open(ruta) as f:\n'
        '            return f.read()\n'
        'def crear(ruta, modo):\n'
        '    """Crea."""\n'
        '    if not os.path.exists(ruta):\n'
        '        with open(ruta, "w") as f:\n'
        '            f.write("x")\n'
        '    if os.path.isfile(ruta):\n'
        '        with open(ruta, mode=modo) as f:\n'
        '            f.write("y")\n',
        encoding="utf-8",
    )
    issues2 = StaticCodeAnalyzer.analyze_python_file(str(p2), prefer_bandit=False)
    assert sorted(line for line, _, m in issues2 if "TOCTOU" in m) == [10, 13]
    assert not any("context manager" in m for _, _, m in issues2)


# --- Reglas arquitectónicas SOLID, contratos de memoria e higiene de fiabilidad y rendimiento ---

def test_solid_checker_arquitectura_y_fiabilidad(tmp_path):
    from agentes.refactor.solid_checker import SOLIDChecker

    bad = tmp_path / "arch_bad.py"
    bad.write_text(
        'from dataclasses import dataclass\n'
        'ESTADO = 0\n'
        '@dataclass\n'
        'class ConfigSinSlots:\n'
        '    nombre: str\n'
        '@dataclass(frozen=True, slots=True)\n'
        'class ConfigInmutable:\n'
        '    nombre: str\n'
        'def anidada(a, b, items=[]):\n'
        '    global ESTADO\n'
        '    if a:\n'
        '        for x in items:\n'
        '            while b:\n'
        '                if x > 0:\n'
        '                    ESTADO += 1\n'
        'def fallos(v):\n'
        '    try:\n'
        '        return int(v)\n'
        '    except ValueError:\n'
        '        raise RuntimeError("sin from")\n'
        'def silencia(v):\n'
        '    try:\n'
        '        return int(v)\n'
        '    except Exception:\n'
        '        return None\n'
        'def plano_elif(op):\n'
        '    if op == 1:\n'
        '        return 1\n'
        '    elif op == 2:\n'
        '        return 2\n'
        '    elif op == 3:\n'
        '        return 3\n'
        '    elif op == 4:\n'
        '        return 4\n'
        '    return 0\n',
        encoding="utf-8",
    )

    findings = SOLIDChecker.audit_file(str(bad))
    principles = {p for _, p, _, _ in findings}
    assert "GUARD" in principles
    assert "EXCEPTION-HYGIENE" in principles
    assert "STATE-SAFETY" in principles
    assert "DATA-CONTRACT" in principles

    # Las cadenas elif evalúan al mismo nivel de profundidad lógica: activan OCP sin inflar GUARD.
    assert not any(p == "GUARD" and "plano_elif" in msg for _, p, _, msg in findings)
    # Una clase dataclass con slots=True elimina __dict__ por instancia y queda exenta de DATA-CONTRACT.
    assert not any(p == "DATA-CONTRACT" and "ConfigInmutable" in msg for _, p, _, msg in findings)
    # Verificar que el auditor identifique simultáneamente estado global mutable y parámetros mutables por defecto.
    state_msgs = [msg for _, p, _, msg in findings if p == "STATE-SAFETY"]
    assert any("defecto mutable" in m for m in state_msgs)
    assert any("global" in m for m in state_msgs)
    # Tanto relanzar sin preservar __cause__ como retornar None en un ExceptHandler degradan la observabilidad.
    exc_msgs = [msg for _, p, _, msg in findings if p == "EXCEPTION-HYGIENE"]
    assert any("from exc" in m for m in exc_msgs)
    assert any("silenciosamente" in m for m in exc_msgs)

    # El encadenamiento explícito con 'from exc' conserva la excepción origen y no se marca.
    good_chain = tmp_path / "chain_ok.py"
    good_chain.write_text(
        'def parse(v):\n'
        '    try:\n'
        '        return int(v)\n'
        '    except ValueError as exc:\n'
        '        raise RuntimeError("invalido") from exc\n',
        encoding="utf-8",
    )
    assert not any(p == "EXCEPTION-HYGIENE" for _, p, _, _ in SOLIDChecker.audit_file(str(good_chain)))


def test_code_metrics_rendimiento_memoria_e_io(tmp_path):
    from agentes.refactor.code_metrics import CodeMetricsCalculator
    from agentes.refactor.refactor_suggester import RefactorSuggester
    from agentes.refactor.solid_checker import SOLIDChecker

    perf_file = tmp_path / "perf_issues.py"
    perf_file.write_text(
        'import re, time, requests\n'
        'def cuello_botella(items, path, cur):\n'
        '    out = ""\n'
        '    cola = list(items)\n'
        '    while cola:\n'
        '        first = cola.pop(0)\n'
        '        if first is None:\n'
        '            cola.insert(0, first)\n'
        '    with open(path) as f:\n'
        '        lines = f.readlines()\n'
        '    for item in items:\n'
        '        if item in ["A", "B", "C", "D", "E", "F", "G", "H", "I"]:\n'
        '            pat = re.compile(r"\\d+")\n'
        '            out += str(item)\n'
        '            requests.get("https://example.com", timeout=5)\n'
        '            cur.execute("SELECT 1")\n'
        '    return out, lines\n'
        'async def tarea():\n'
        '    time.sleep(0.1)\n',
        encoding="utf-8",
    )

    metrics = CodeMetricsCalculator.calculate_file_metrics(str(perf_file))
    perf = metrics["performance_findings"]
    assert perf == CodeMetricsCalculator.audit_performance(str(perf_file))

    categories = {cat for _, cat, _, _ in perf}
    assert "IMPACTO ALTO - COMPLEJIDAD BIG-O" in categories
    assert "IMPACTO MEDIO - HUELLA DE MEMORIA" in categories
    assert "IMPACTO ALTO - I/O BLOQUEANTE" in categories

    msgs = [m for _, _, _, m in perf]
    assert any(".pop(0)" in m for m in msgs)
    assert any(".insert(0" in m for m in msgs)
    assert any("set" in m and "O(1)" in m for m in msgs)
    assert any("re.compile" in m for m in msgs)
    assert any(".readlines()" in m for m in msgs)
    assert any("join" in m for m in msgs)
    assert any("async def" in m and "time.sleep" in m for m in msgs)
    assert any("Connection Pooling" in m or "Session" in m for m in msgs)
    assert any("N+1" in m for m in msgs)

    solid_findings = SOLIDChecker.audit_file(str(perf_file))
    recs = RefactorSuggester.generate_recommendations(metrics, solid_findings)
    assert any("[IMPACTO ALTO - COMPLEJIDAD BIG-O" in r for r in recs)
    assert any("[IMPACTO MEDIO - HUELLA DE MEMORIA" in r for r in recs)
    assert any("[IMPACTO ALTO - I/O BLOQUEANTE" in r for r in recs)


def test_refactor_recomendaciones_situan_cada_aviso():
    """Sin archivo se indica la línea; con location, el archivo y la línea."""
    from agentes.refactor.refactor_suggester import RefactorSuggester

    metrics = {"comment_ratio": 0.0, "code_loc": 80, "avg_cyclomatic_complexity": 7.0,
               "performance_findings": [(9, "IMPACTO MEDIO - HUELLA DE MEMORIA", "MEDIO", "readlines")]}
    solid = [(7, "SRP", "MEDIO", "Clase grande")]

    sueltas = RefactorSuggester.generate_recommendations(metrics, solid)
    assert any(r.startswith("[DISEÑO SRP - Línea 7]") for r in sueltas)
    assert any(r.startswith("[IMPACTO MEDIO - HUELLA DE MEMORIA - Línea 9]") for r in sueltas)

    situadas = RefactorSuggester.generate_recommendations(metrics, solid, location="pkg/mod.py")
    assert any(r.startswith("[DISEÑO SRP - pkg/mod.py:7]") for r in situadas)
    assert any(r.startswith("[IMPACTO MEDIO - HUELLA DE MEMORIA - pkg/mod.py:9]") for r in situadas)
    # Las recomendaciones de todo el archivo también dicen de cuál son.
    assert any(r.startswith("[REFACTOR - pkg/mod.py]") for r in situadas)
    assert any(r.startswith("[DOCUMENTACION - pkg/mod.py]") for r in situadas)
    assert not any("Línea" in r for r in situadas)


# --- Auditoría de testabilidad, generación adversaria y calidad de suites de prueba ---

def test_qa_testability_audit_y_matriz_escenarios(tmp_path):
    from agentes.qa.test_generator import QATestGenerator

    src = tmp_path / "smelly_service.py"
    src.write_text(
        'import requests, time\n'
        'CACHE = []\n'
        'class Repo:\n'
        '    pass\n'
        'def procesar(uid, precio):\n'
        '    global CACHE\n'
        '    repo = Repo()\n'
        '    ts = time.time()\n'
        '    if precio < 0:\n'
        '        raise ValueError("Precio negativo")\n'
        '    r = requests.get(f"https://example.com/{uid}", timeout=5)\n'
        '    CACHE.append((uid, ts, repo, r))\n'
        '    return precio\n'
        'async def sync_item(item_id):\n'
        '    if not item_id:\n'
        '        raise KeyError("id requerido")\n'
        '    return {"id": item_id}\n',
        encoding="utf-8",
    )

    smells = QATestGenerator.audit_testability(str(src))
    codes = {c for _, c, _, _ in smells}
    assert "HARDCODED-DEP" in codes
    assert "GLOBAL-STATE" in codes
    assert "MIXED-IO" in codes
    assert "NON-DETERMINISTIC" in codes

    matrix = QATestGenerator.build_scenario_matrix(str(src))
    cats = {s["category"] for s in matrix}
    assert "[HAPPY PATH]" in cats
    assert "[BOUNDARY / EDGE CASE]" in cats
    assert "[ADVERSARIAL / ERROR]" in cats
    assert "[CONCURRENCY / I/O FAULT]" in cats

    # Cada ruta nominal debe generar al menos tres escenarios de frontera, hostiles o de concurrencia.
    happy_count = sum(1 for s in matrix if s["category"] == "[HAPPY PATH]")
    non_happy_count = len(matrix) - happy_count
    assert non_happy_count >= happy_count * 3


def test_qa_generate_pytest_suite_ejecutable_y_limpia(tmp_path):
    import subprocess

    from agentes.qa.test_generator import QATestGenerator
    from agentes.qa.test_runner import QATestRunner

    mod = tmp_path / "calc_adv.py"
    mod.write_text(
        'import urllib.request\n'
        'def sumar(a, b):\n'
        '    return a + b\n'
        'def calcular_descuento(precio, porcentaje):\n'
        '    if porcentaje < 0 or porcentaje > 100:\n'
        '        raise ValueError("Porcentaje inválido")\n'
        '    return precio * (1 - porcentaje / 100)\n'
        'def descargar(url):\n'
        '    if not url:\n'
        '        raise ValueError("url vacia")\n'
        '    return urllib.request.urlopen(url, timeout=1).read()\n'
        'async def tarea_async(uid):\n'
        '    if uid is None:\n'
        '        return 0\n'
        '    return uid * 2\n',
        encoding="utf-8",
    )

    test_out = tmp_path / "test_calc_adv.py"
    QATestGenerator.generate_pytest_suite(str(mod), str(test_out))
    body = test_out.read_text(encoding="utf-8")

    assert "@pytest.fixture" in body and "yield" in body
    assert "@pytest.mark.parametrize" in body and "ids=[" in body
    assert "# Arrange" in body and "# Act" in body and "# Assert" in body
    assert "pytest.raises(ValueError, match=" in body
    assert "autospec=True" in body
    assert "asyncio.CancelledError" in body and "asyncio.gather" in body

    # La suite generada debe superar el propio auditor de calidad sin emitir antipatrones estructurales.
    qa_audit = QATestRunner.audit_test_suite_quality(str(test_out))
    assert qa_audit["findings"] == []
    assert qa_audit["uses_parametrize"] is True
    assert qa_audit["uses_fixtures"] is True
    assert qa_audit["assertions_count"] > 0

    # Ejecutar pytest sobre el módulo emitido para validar sintaxis, aislamiento e invariantes en tiempo de ejecución.
    run = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", str(test_out)],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
    )
    assert run.returncode == 0, run.stdout + "\n" + run.stderr


def test_qa_runner_audita_antipatrones_sdet(tmp_path):
    from agentes.qa.test_runner import QATestRunner

    bad_test = tmp_path / "test_bad_sdet.py"
    bad_test.write_text(
        'import time, pytest, requests\n'
        'from unittest.mock import MagicMock, patch\n'
        'def test_vacio():\n'
        '    x = 1 + 1\n'
        'def test_tautologia_y_raises():\n'
        '    assert True\n'
        '    with pytest.raises(Exception):\n'
        '        int("x")\n'
        '    with pytest.raises(ValueError):\n'
        '        int("y")\n'
        'def test_io_sin_mock():\n'
        '    time.sleep(0.01)\n'
        '    requests.get("https://example.com", timeout=1)\n'
        '    assert 1 == 1\n'
        'def test_mock_fragil():\n'
        '    m = MagicMock()\n'
        '    with patch("mod._interno"):\n'
        '        assert m is not None\n',
        encoding="utf-8",
    )

    audit = QATestRunner.audit_test_suite_quality(str(bad_test))
    codes = {c for _, c, _, _ in audit["findings"]}
    assert "WEAK-ASSERT" in codes
    assert "GENERIC-RAISES" in codes
    assert "UNISOLATED-IO" in codes
    assert "UNSAFE-MOCK" in codes


def test_api_contract_adversarial_y_reporte_sdet(tmp_path):
    from agentes.qa.api_contract_testing import APIContractTester
    from agentes.qa.qa_reporter import QAReporter

    # Un SLA negativo, NaN o infinito carece de semántica temporal válida y debe rechazarse en la validación.
    for bad_ms in (-5.0, float("nan"), float("inf")):
        res = APIContractTester.validate_api_response("/x", 200, {}, {}, bad_ms, expected_status=200, max_sla_ms=500.0)
        assert not res["passed"]

    # Validar coincidencia insensible a mayúsculas en cabeceras esperadas y detección de cabeceras ausentes.
    hdr_ok = APIContractTester.validate_api_response(
        "/x", 200, {"ok": True}, {"Content-Type": "application/json; charset=utf-8"}, 10.0,
        expected_headers={"content-type": "application/json"},
    )
    assert hdr_ok["passed"]
    hdr_fail = APIContractTester.validate_api_response(
        "/x", 200, {"ok": True}, {}, 10.0,
        expected_headers={"X-Request-Id": "abc"},
    )
    assert not hdr_fail["passed"]

    # Verificar que la batería adversaria cubra estructuras vacías, tipos incompatibles, valores nulos y extremos numéricos.
    payloads = APIContractTester.generate_adversarial_payloads({"id": int, "score": float, "name": str, "tags": list})
    labels = {name for name, _ in payloads}
    assert {"empty_payload", "non_dict_null", "null_fields", "bool_as_int_or_type_trap", "extreme_nan_giant"}.issubset(labels)

    # Escapar secuencias HTML activas al renderizar nombres de endpoints en el informe.
    html_p = QAReporter.generate_html_report(
        {"tests_run": 1, "passed": 1, "failures": 0, "errors": 0, "pass_rate_percentage": 100.0},
        [{"endpoint": "<script>alert(1)</script>", "elapsed_ms": 5, "passed": True}],
        str(tmp_path / "qa.html"),
    )
    html_body = open(html_p, encoding="utf-8").read()
    assert "<script>alert(1)</script>" not in html_body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_body

    # Confirmar que el informe integral organiza testabilidad, matriz de escenarios y suite generada en secciones diferenciadas.
    fixture = os.path.join(ROOT, "agentes", "qa", "fixtures", "sample_app.py")
    rpt = QAReporter.generate_adversarial_qa_report(
        fixture,
        str(tmp_path / "test_sample_app_adv.py"),
        str(tmp_path / "qa_adv.md"),
    )
    md = open(rpt, encoding="utf-8").read()
    assert "## 1. Defectos de Testabilidad (Code Smells para QA)" in md
    assert "## 2. Matriz de Escenarios de Prueba" in md
    assert "## 3. Suite de Pruebas Lista para Producción" in md


def test_orchestrator_excluye_venv_custom_y_caches(tmp_path):
    from agentes.common.orchestrator import run_pipeline

    (tmp_path / "app.py").write_text('def ok():\n    """Ok."""\n    return 1\n', encoding="utf-8")

    # Simular entornos virtuales con nombre arbitrario o marcador pyvenv.cfg junto con directorios de caché.
    v313 = tmp_path / "venv313"
    v313.mkdir()
    (v313 / "leak.py").write_text('API_KEY = "ghp_' '16C7e42F292c6912E7710c838347Ae178B4a"\n', encoding="utf-8")

    custom_env = tmp_path / "custom_env"
    custom_env.mkdir()
    (custom_env / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    (custom_env / "lib.py").write_text('eval("1+1")\n', encoding="utf-8")

    mypy_c = tmp_path / ".mypy_cache"
    mypy_c.mkdir()
    (mypy_c / "cached.json").write_text('{"token": "ghp_' '16C7e42F292c6912E7710c838347Ae178B4a"}\n', encoding="utf-8")

    report, _ = run_pipeline(
        str(tmp_path),
        agents_root=ROOT,
        output_dir=str(tmp_path / "rep"),
        fail_on_high=False,
        prefer_bandit=False,
    )
    assert report["python_files"] == 1
    assert report["files_scanned"] == 1
    assert not any("venv313" in f["file"] or "custom_env" in f["file"] or ".mypy_cache" in f["file"] for f in report["findings"])


def test_precision_heuristica_sin_falsos_positivos(tmp_path):
    from agentes.defensive.config_manager import ConfigManager
    from agentes.qa.test_generator import QATestGenerator
    from agentes.quality.static_checker import StaticCodeAnalyzer
    from agentes.refactor.solid_checker import SOLIDChecker

    # El escáner de secretos descarta etiquetas UI y constantes autodescriptivas sin omitir credenciales reales.
    ui_py = tmp_path / "ui.py"
    ui_py.write_text(
        'Label("Password:", classes="field-label")\n'
        'Label("Enter password:", classes="field-label")\n'
        'AUTHENTIC = "authentic"\n'
        'PASSWORD = "password"\n',
        encoding="utf-8",
    )
    assert ConfigManager.scan_file_for_secrets(str(ui_py)) == []

    prod_secret = tmp_path / "prod_cfg.py"
    prod_secret.write_text(
        'auth_token = "abcdef1234567890abcdef1234"\n',
        encoding="utf-8",
    )
    assert len(ConfigManager.scan_file_for_secrets(str(prod_secret))) == 1

    test_secret_file = tmp_path / "test_auth.py"
    test_secret_file.write_text(
        'api_key = "fake_test_secret_1234"\n'
        + 'real_key = "' + "sk_live_" + '51H0abcdef1234567890abcd"\n',
        encoding="utf-8",
    )
    hits_test_secret = ConfigManager.scan_file_for_secrets(str(test_secret_file))
    assert len(hits_test_secret) == 1
    assert hits_test_secret[0][0] == 2

    # El analizador estático omite reglas de documentación, aserciones y secretos genéricos dentro de suites de prueba.
    test_sast = tmp_path / "test_sample.py"
    test_sast.write_text(
        'def test_algo():\n'
        '    token = "dummy_token_value_123456"\n'
        '    assert token.startswith("dummy")\n',
        encoding="utf-8",
    )
    assert StaticCodeAnalyzer.analyze_python_file(str(test_sast), prefer_bandit=False) == []
    assert StaticCodeAnalyzer.analyze_python_file(str(test_sast), prefer_bandit=True) == []

    prod_sast = tmp_path / "prod.py"
    prod_sast.write_text(
        'def prod_fn(x):\n    assert x > 0\n    return x\n'
        'def test_helper():\n    return 1\n',
        encoding="utf-8",
    )
    prod_issues = StaticCodeAnalyzer.analyze_python_file(str(prod_sast), prefer_bandit=False)
    msgs_prod = "\n".join(m for _, _, m in prod_issues)
    assert "prod_fn" in msgs_prod
    assert "test_helper" not in msgs_prod
    assert "assert" in msgs_prod

    # La auditoría de testabilidad restringe HARDCODED-DEP a clientes, servicios y repositorios externos concretos.
    widgets_py = tmp_path / "widgets.py"
    widgets_py.write_text(
        'def render():\n'
        '    t = Table()\n'
        '    p = Panel("hola")\n'
        '    lbl = Label("ok")\n'
        '    parser = ArgumentParser()\n'
        '    client = OpenAIClient()\n'
        '    repo = UserRepository()\n'
        '    raise SystemExit(0)\n',
        encoding="utf-8",
    )
    qa_findings = QATestGenerator.audit_testability(str(widgets_py))
    hardcoded = [f for f in qa_findings if f[1] == "HARDCODED-DEP"]
    hardcoded_msgs = "\n".join(f[3] for f in hardcoded)
    assert len(hardcoded) == 2
    assert "OpenAIClient" in hardcoded_msgs
    assert "UserRepository" in hardcoded_msgs
    for widget in ("Table", "Panel", "Label", "ArgumentParser", "SystemExit"):
        assert widget not in hardcoded_msgs

    # El encadenamiento de excepciones exime relanzamientos directos de la variable capturada y salidas de proceso controladas.
    exc_py = tmp_path / "exc_cases.py"
    exc_py.write_text(
        'def f():\n'
        '    """Doc."""\n'
        '    try:\n'
        '        return 1\n'
        '    except ValueError as e:\n'
        '        raise e\n'
        '\n'
        'def g():\n'
        '    """Doc."""\n'
        '    try:\n'
        '        return 1\n'
        '    except KeyboardInterrupt:\n'
        '        raise SystemExit(130)\n'
        '\n'
        'def h():\n'
        '    """Doc."""\n'
        '    try:\n'
        '        return 1\n'
        '    except ValueError:\n'
        '        raise RuntimeError("fallo")\n',
        encoding="utf-8",
    )
    solid_findings = SOLIDChecker.audit_file(str(exc_py))
    hygiene = [f for f in solid_findings if f[1] == "EXCEPTION-HYGIENE"]
    assert len(hygiene) == 1
    assert hygiene[0][0] == 20


def test_parse_env_file_y_audit_env_no_mutan_environ(tmp_path, monkeypatch):
    from agentes.common import audits
    from agentes.defensive.config_manager import ConfigManager

    env_path = tmp_path / ".env"
    env_path.write_text('CUSTOM_APP_TOKEN="secreto1234567890"\nDEBUG=true\n', encoding="utf-8")
    monkeypatch.delenv("CUSTOM_APP_TOKEN", raising=False)
    monkeypatch.setenv("KEEP_EXISTING_ENV", "intacto")

    parsed = ConfigManager.parse_env_file(str(env_path))
    assert parsed == {"CUSTOM_APP_TOKEN": "secreto1234567890", "DEBUG": "true"}
    assert "CUSTOM_APP_TOKEN" not in os.environ

    def _forbid_load(*_args, **_kwargs):
        raise AssertionError("audit_env no debe invocar load_env_file ni mutar os.environ")

    monkeypatch.setattr(ConfigManager, "load_env_file", staticmethod(_forbid_load))
    findings = audits.audit_env(str(env_path))
    assert findings
    assert os.environ.get("KEEP_EXISTING_ENV") == "intacto"
    assert "CUSTOM_APP_TOKEN" not in os.environ


def test_prometheus_exporter_conteo_exacto_y_concurrencia():
    import threading
    import urllib.error
    import urllib.request
    from concurrent.futures import ThreadPoolExecutor
    from http.server import ThreadingHTTPServer

    from agentes.sre.prometheus_exporter import PrometheusExporter

    PrometheusExporter.reset()
    state = {"healthy": True}

    def health():
        return {"status": "HEALTHY" if state["healthy"] else "UNHEALTHY"}

    server = ThreadingHTTPServer(("127.0.0.1", 0), PrometheusExporter.build_handler(health))
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def fetch(path: str) -> int:
        url = f"http://127.0.0.1:{port}{path}"
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                resp.read()
                return resp.status
        except urllib.error.HTTPError as exc:
            exc.read()
            return exc.code

    try:
        with ThreadPoolExecutor(max_workers=6) as pool:
            futs = [pool.submit(fetch, "/healthz") for _ in range(10)]
            statuses = [f.result() for f in futs]
        assert statuses == [200] * 10

        state["healthy"] = False
        with ThreadPoolExecutor(max_workers=6) as pool:
            statuses_503 = [f.result() for f in [pool.submit(fetch, "/healthz") for _ in range(4)]]
            statuses_404 = [f.result() for f in [pool.submit(fetch, "/no-existe") for _ in range(4)]]
        assert statuses_503 == [503] * 4
        assert statuses_404 == [404] * 4

        assert fetch("/metrics") == 200
        metrics_text = PrometheusExporter.generate_metrics()
        # 10 (/healthz 200) + 4 (/healthz 503) + 4 (/no-existe 404) + 1 (/metrics 200) = 19 peticiones, 8 errores
        assert "app_requests_total 19\n" in metrics_text
        assert "app_requests_errors_total 8\n" in metrics_text
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        PrometheusExporter.reset()


def test_sarif_reglas_granulares_y_driver_rules(tmp_path):
    from agentes import __version__
    from agentes.common.reporting import findings_to_sarif

    findings = [
        {"file": "a.py", "line": 2, "level": "CRITICO", "rule_id": "SAST-CRITICO", "message": "Uso de función de riesgo dinámico 'eval()'."},
        {"file": "a.py", "line": 5, "level": "ALTO", "rule_id": "SAST-ALTO", "message": "Posible SQL injection: f-string en execute()."},
        {"file": "b.py", "line": 3, "level": "ALTO", "rule_id": "SECRET", "message": "Token de GitHub: ghp***REDACTED***"},
        {"file": "b.py", "line": 4, "level": "ALTO", "rule_id": "SECRET", "message": "Clave de acceso AWS (AKIA): AKI***REDACTED***"},
        {"file": "deploy.yaml", "line": 1, "level": "ALTO", "rule_id": "K8S-WORKLOAD", "message": "Falta runAsNonRoot"},
    ]
    out = findings_to_sarif("AGENTES-Pipeline", findings, str(tmp_path / "out.sarif"))
    sarif = json.loads(open(out, encoding="utf-8").read())
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["version"] == __version__
    rule_ids = [r["ruleId"] for r in sarif["runs"][0]["results"]]
    assert rule_ids == ["SAST-EVAL", "SAST-SQLI", "SECRET-GITHUB", "SECRET-AWS", "K8S-WORKLOAD"]
    declared = {r["id"] for r in driver["rules"]}
    assert set(rule_ids) <= declared


def test_github_actions_generator_moderno(tmp_path):
    from agentes.devops.github_actions_generator import GitHubActionsGenerator

    wf = tmp_path / "devsecops.yml"
    GitHubActionsGenerator.generate_workflow(str(wf))
    text = wf.read_text(encoding="utf-8")
    assert "contents: read" in text
    assert "security-events: write" not in text
    assert "python-version: '3.12'" in text
    assert "ruff check ." in text
    assert "bandit" in text


def test_submodulos_modularizados_cli_y_qa_importables():
    import importlib

    cli_mods = ("common", "analyze", "generate", "testing", "ops", "parser")
    for mod in cli_mods:
        loaded = importlib.import_module(f"agentes.cli.{mod}")
        assert loaded is not None

    qa_mods = ("ast_inspector", "testability", "sample_values", "emitters", "test_generator")
    for mod in qa_mods:
        loaded = importlib.import_module(f"agentes.qa.{mod}")
        assert loaded is not None

    from agentes import cli as cli_pkg
    from agentes.qa.emitters import emit_unittest_call_tests, render_pytest_suite
    from agentes.qa.test_generator import QATestGenerator, TestabilityAuditor, UnitTestGenerator

    assert callable(cli_pkg.main)
    assert callable(QATestGenerator.generate_test_suite)
    assert callable(QATestGenerator.generate_pytest_suite)
    assert callable(emit_unittest_call_tests)
    assert callable(render_pytest_suite)
    assert TestabilityAuditor is not None and UnitTestGenerator is not None
