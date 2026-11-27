"""Lightweight unit tests for the shared core and the CLI."""
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
    sp = findings_to_sarif("T", [{"file": "a.py", "line": 1, "level": "HIGH", "message": "m"}], str(tmp_path / "r.sarif"))
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
    assert any("secret" in i[2].lower() or "API_KEY" in i[2] for i in issues)


def test_openapi_fastapi_decorator(tmp_path):
    from agentes.docs.openapi_generator import OpenAPIGenerator
    p = tmp_path / "app.py"
    p.write_text(
        'app = None\n'
        '@app.get("/items")\n'
        'def list_items():\n'
        '    """List items."""\n'
        '    return []\n',
        encoding="utf-8",
    )
    spec = OpenAPIGenerator.generate_openapi_spec(str(p))
    assert "/items" in spec["paths"]
    assert "get" in spec["paths"]["/items"]


# --- HTML escaping, full file coverage and the SAST engine ---

def test_html_summary_escapes_hostile_content(tmp_path):
    """The HTML report must never execute anything coming from the scanned code."""
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


def test_pipeline_does_not_truncate_by_default(tmp_path):
    """Without max_files every file is scanned: there is no implicit limit."""
    from agentes.common.orchestrator import run_pipeline
    for i in range(250):
        (tmp_path / f"f{i:03d}.py").write_text(f'PASSWORD = "hardcodedsecret{i:03d}"\n', encoding="utf-8")
    report, _ = run_pipeline(
        str(tmp_path), agents_root=ROOT, output_dir=str(tmp_path / "rep"),
        fail_on_high=False, prefer_bandit=False,
    )
    assert report["files_scanned"] == 250
    assert report["files_skipped"] == 0
    # The walk must reach the alphabetically last files too.
    last = [f for f in report["findings"] if f["file"].endswith("f249.py")]
    assert last, "the last file does not appear in the findings"


def test_pipeline_states_what_it_did_not_scan(tmp_path):
    """With max_files the truncation is written into the report, not silent."""
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
    assert "20 files NOT scanned" in sast["summary"]


def test_pipeline_default_engine_still_reports_findings(tmp_path):
    """With the default engine (Bandit when installed) the pipeline still reports findings."""
    from agentes.common.orchestrator import run_pipeline
    (tmp_path / "app.py").write_text('import subprocess\nsubprocess.Popen("ls", shell=True)\n', encoding="utf-8")
    report, _ = run_pipeline(
        str(tmp_path), agents_root=ROOT, output_dir=str(tmp_path / "rep"), fail_on_high=False
    )
    sast = next(s for s in report["stages"] if s["name"] == "quality_sast")
    assert sast["engine"] in ("bandit+ast", "ast")
    assert sast["findings_count"] >= 1


def _declared_packages():
    """Read [tool.setuptools].packages without requiring tomllib (3.11+)."""
    try:
        import tomllib
    except ImportError:  # tomllib joined the standard library in Python 3.11.
        tomllib = None
    path = os.path.join(ROOT, "pyproject.toml")
    if tomllib is not None:
        with open(path, "rb") as fh:
            return set(tomllib.load(fh)["tool"]["setuptools"]["packages"])
    import re
    body = open(path, encoding="utf-8").read()
    block = re.search(r"^packages = \[(.*?)\]", body, re.S | re.M)
    assert block, "the packages list was not found in pyproject.toml"
    return set(re.findall(r'"([^"]+)"', block.group(1)))


def test_agent_packages_are_declared_for_the_wheel():
    """pip install . must ship all 8 agents, not just agentes.common."""
    declared = _declared_packages()
    for agent in ("cli", "common", "qa", "quality", "defensive", "devops", "docs", "hardening", "refactor", "sre"):
        assert f"agentes.{agent}" in declared, f"agentes.{agent} is missing from the wheel"
        assert os.path.isfile(os.path.join(ROOT, "agentes", agent, "__init__.py"))


def test_no_generic_top_level_packages_are_installed():
    """Everything lives under agentes/: no stray 'common' package in site-packages."""
    declared = _declared_packages()
    assert all(p == "agentes" or p.startswith("agentes.") for p in declared), declared


def test_the_library_does_not_touch_sys_path():
    """Internal imports are relative; no module under agentes/ modifies sys.path."""
    import glob
    for path in glob.glob(os.path.join(ROOT, "agentes", "**", "*.py"), recursive=True):
        if os.path.basename(path) == "test_runner.py":
            continue  # runs third-party suites and needs their directory on sys.path
        if os.path.basename(path) == "expected_values.py":
            continue  # the sys.path it touches belongs to the child process that records results
        if os.path.basename(path) == "call_plan.py":
            continue  # the sys.path it touches is the generated suite's, not agentes'
        body = open(path, encoding="utf-8").read()
        assert "sys.path.insert" not in body, path


def test_output_dir_falls_back_to_cwd_for_a_read_only_install(tmp_path, monkeypatch):
    from agentes.common import workspace
    monkeypatch.setattr(workspace.os, "access", lambda p, m: False)
    monkeypatch.delenv("AGENTES_WORKDIR", raising=False)
    monkeypatch.chdir(tmp_path)
    out = workspace.agent_output_dir(os.path.join(ROOT, "agentes", "qa", "main.py"))
    assert out == str(tmp_path / "qa")
    assert os.path.isdir(out)


def test_output_dir_honours_AGENTES_WORKDIR(tmp_path, monkeypatch):
    from agentes.common import workspace
    monkeypatch.setenv("AGENTES_WORKDIR", str(tmp_path / "wd"))
    out = workspace.agent_output_dir(os.path.join(ROOT, "agentes", "qa", "main.py"))
    assert out == str(tmp_path / "wd" / "qa")


# --- Resilience against unreadable sources, restricted permissions and audit invariants ---

def test_pipeline_survives_a_py_file_that_does_not_parse(tmp_path):
    """A single broken source must not take down the pipeline and lose the whole report."""
    from agentes.common.orchestrator import run_pipeline
    (tmp_path / "aaa_broken.py").write_text("def (:\n", encoding="utf-8")
    (tmp_path / "zzz.py").write_text('PASSWORD = "secret123456"\n', encoding="utf-8")
    report, _ = run_pipeline(
        str(tmp_path), agents_root=ROOT, output_dir=str(tmp_path / "rep"),
        fail_on_high=False, prefer_bandit=False,
    )
    assert os.path.isfile(str(tmp_path / "rep" / "pipeline.json"))
    broken = str(tmp_path / "aaa_broken.py")
    assert any(f["file"] == broken and "Syntax error" in f["message"] for f in report["findings"])
    metrics = next(s for s in report["stages"] if s["name"] == "refactor_metrics")
    assert any("aaa_broken.py" in e for e in metrics["errors"])
    # A parse failure in one module must not prevent secret detection in the valid ones.
    assert any(f.get("rule_id") == "SECRET" for f in report["findings"])

    # With a web framework, the OpenAPI stage also reports the file it could not read.
    (tmp_path / "web.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    report, _ = run_pipeline(
        str(tmp_path), agents_root=ROOT, output_dir=str(tmp_path / "rep"),
        fail_on_high=False, prefer_bandit=False,
    )
    docs = next(s for s in report["stages"] if s["name"] == "documentation")
    assert docs["status"] == "fail" and docs["errors"]


def test_openapi_does_not_raise_on_an_unreadable_source(tmp_path):
    from agentes.docs.openapi_generator import OpenAPIGenerator
    broken = tmp_path / "r.py"
    broken.write_text("def (:\n", encoding="utf-8")
    spec = OpenAPIGenerator.generate_openapi_spec(str(broken))
    assert spec["x-agentes-errors"]
    assert OpenAPIGenerator.generate_openapi_spec(str(tmp_path / "no.py"))["x-agentes-errors"]


def test_test_generator_does_not_raise_on_an_unreadable_source(tmp_path):
    from agentes.qa.test_generator import QATestGenerator
    broken = tmp_path / "r.py"
    broken.write_text("def (:\n", encoding="utf-8")
    assert QATestGenerator.generate_test_suite(str(broken), str(tmp_path / "t.py")) == ""


def test_dockerfile_non_root_user_is_not_a_false_positive(tmp_path):
    """'nonroot' contains 'root' and '1000' contains '0': substring matching is not enough."""
    from agentes.hardening.container_hardening import ContainerHardening

    def warns_about_root(line):
        p = tmp_path / ("Dockerfile" + line.replace(" ", "_").replace(":", "-"))
        p.write_text(f"FROM python:3.12-slim\n{line}\n", encoding="utf-8")
        return any("root" in f[2] or "user given" in f[2] for f in ContainerHardening.audit_dockerfile(str(p)))

    for fine in ("USER appuser", "USER nonroot", "USER app10", "USER 1000", "USER 1000:1000"):
        assert not warns_about_root(fine), fine
    for unsafe in ("USER root", "USER 0", "USER root:root"):
        assert warns_about_root(unsafe), unsafe


def test_systemd_commented_or_disabled_directives_do_not_count(tmp_path):
    from agentes.hardening.service_hardening import ServiceHardening

    def clean(body):
        p = tmp_path / (str(abs(hash(body))) + ".service")
        p.write_text(body, encoding="utf-8")
        r = ServiceHardening.audit_systemd_service(str(p))
        return bool(r) and r[0][1] == "OK"

    complete = "[Service]\nNoNewPrivileges=true\nProtectHome=true\nPrivateTmp=true\nProtectSystem=strict\n"
    assert clean(complete)
    assert clean("[Service]\nNoNewPrivileges = true\nProtectHome = true\nPrivateTmp = true\nProtectSystem = full\n")
    assert not clean("[Service]\n# NoNewPrivileges=true\n# ProtectHome=true\n# PrivateTmp=true\n# ProtectSystem=strict\n")
    assert not clean(complete.replace("ProtectSystem=strict", "ProtectSystem=false"))
    assert not clean(complete.replace("NoNewPrivileges=true", "NoNewPrivileges=no"))


def test_secret_scan_does_not_silence_unreadable_files(tmp_path):
    from agentes.defensive.config_manager import ConfigManager
    d = tmp_path / "i_am_a_dir"
    d.mkdir()
    for path in (str(d), str(tmp_path / "missing.py")):
        r = ConfigManager.scan_file_for_secrets(path)
        assert r and "error" in r[0][1].lower(), path


def test_load_env_file(tmp_path):
    """load_env_file returns the .env variables without quotes or surrounding spaces, skipping malformed lines."""
    from agentes.defensive.config_manager import ConfigManager
    env = tmp_path / ".env"
    env.write_text('# comment\nAPI_KEY="secret"\nEMPTY=\nMALFORMED\nSPACES = with spaces \n', encoding="utf-8")
    assert ConfigManager.load_env_file(str(env)) == {
        "API_KEY": "secret", "EMPTY": "", "SPACES": "with spaces",
    }


# --- Secret detection: corpus of positives and negatives ---

# Fake tokens are split into two literals ("ghp_" "16C7..."): Python joins them and the detector
# sees the whole token, but the file never contains a complete one, so GitHub's secret
# protection does not block the push.
REAL_SECRETS = [
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
    ("PEM private key", "-----BEGIN RSA PRIVATE KEY-----"),
    ("ssh private key", "-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("jwt", 'j = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"'),
    ("postgres with password", 'DB = "postgresql://user:MySecretPassword@db.example.com:5432/prod"'),
    ("mongodb with password", 'DB = "mongodb+srv://admin:p4ssw0rd@cluster0.mongodb.net/test"'),
    ("basic auth", 'headers = {"Authorization": "Basic dXNlcjpwYXNzd29yZDEyMw=="}'),
    ("token in a dict", 'cfg = {"token": "ghp_' 'abcdefghijklmnopqrstuvwxyz0123456789"}'),
    ("token in yaml", 'auth_token: "abcdef1234567890abcdef1234"'),
    ("client_secret", 'client_secret = "abcdefghij0123456789ABCDEFGHIJ"'),
    ("passphrase", 'passphrase = "correcthorsebatterystaple"'),
]

NOT_SECRETS = [
    ("from environment", 'API_KEY = os.environ["API_KEY"]'),
    ("from getenv", 'password = os.getenv("DB_PASSWORD")'),
    ("from config", 'token = config.get("token")'),
    ("placeholder <>", 'password = "<your-password-here>"'),
    ("placeholder xxx", 'api_key = "xxxxxxxxxxxx"'),
    ("placeholder your-", 'secret = "your-secret-here"'),
    ("format string", 'password = "%s"'),
    ("f-string", 'token = f"{prefix}-{suffix}"'),
    ("empty", 'password = ""'),
    ("names a field", 'password_field_name = "password"'),
    ("comment", '# password = "this is an example"'),
    ("url without credentials", 'DB = "postgresql://db.example.com:5432/prod"'),
    ("import", "from mymodule import secret_manager"),
    ("short literal", 'token = "abc"'),
    ("path to a file", 'key_path = "/etc/ssl/private/server.key"'),
]


@pytest.mark.parametrize("label,content", REAL_SECRETS, ids=[x[0] for x in REAL_SECRETS])
def test_detects_the_secret(tmp_path, label, content):
    from agentes.defensive.config_manager import ConfigManager
    p = tmp_path / "c.py"
    p.write_text(content + "\n", encoding="utf-8")
    assert ConfigManager.scan_file_for_secrets(str(p)), label


@pytest.mark.parametrize("label,content", NOT_SECRETS, ids=[x[0] for x in NOT_SECRETS])
def test_is_not_a_false_positive(tmp_path, label, content):
    from agentes.defensive.config_manager import ConfigManager
    p = tmp_path / "c.py"
    p.write_text(content + "\n", encoding="utf-8")
    assert not ConfigManager.scan_file_for_secrets(str(p)), label


def test_sast_detects_secrets_in_dicts_and_kwargs(tmp_path):
    """The AST engine also finds secrets in dict literals and keyword arguments."""
    from agentes.quality.static_checker import StaticCodeAnalyzer

    def finds(code):
        p = tmp_path / (str(abs(hash(code))) + ".py")
        p.write_text(code + "\n", encoding="utf-8")
        return any("secret" in i[2].lower() for i in StaticCodeAnalyzer.analyze_python_file(str(p), prefer_bandit=False))

    assert finds('cfg = {"token": "ghp_abcdefghijklmnopqrstuvwxyz0123"}')
    assert finds('connect(password="MySuperSecretPassword")')
    assert finds('self.api_key = "abcdef1234567890abcdef"')
    assert not finds('API_KEY = os.environ["API_KEY"]')
    assert not finds('password = "changeme"')
    assert not finds('password_field_name = "password"')


def test_the_version_cannot_drift():
    """agentes.__version__ is the single source of truth; pyproject reads it from there."""
    pyproject = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    assert 'version = {attr = "agentes.__version__"}' in pyproject
    assert "\nversion = " not in pyproject.split("[tool.setuptools.dynamic]")[0], \
        "pyproject must not hardcode the version"


def test_cli_exposes_the_version():
    import subprocess
    r = subprocess.run(
        [sys.executable, os.path.join(ROOT, "agentes_cli.py"), "--version"],
        capture_output=True, text=True,
    )
    from agentes import __version__
    assert r.returncode == 0
    assert __version__ in (r.stdout + r.stderr)


# --- SARIF/HTML report integrity and multi-file coverage ---

def test_sarif_uses_relative_paths_and_html_lists_findings(tmp_path):
    from agentes.common.reporting import build_pipeline_report, findings_to_sarif, write_html_summary

    nested = tmp_path / "pkg" / "mod.py"
    nested.parent.mkdir(parents=True)
    nested.write_text("x = 1\n", encoding="utf-8")

    findings = [{
        "file": str(nested),
        "line": 7,
        "level": "HIGH",
        "rule_id": "SAST-HIGH",
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
    assert "Findings (1)" in html_body
    assert "pkg/mod.py" in html_body
    assert "SAST-HIGH" in html_body
    assert "<script>xss</script>" not in html_body
    assert "&lt;script&gt;xss&lt;/script&gt;" in html_body


def test_multi_file_pipeline_secrets_metrics_openapi_and_infra(tmp_path):
    from agentes.common.orchestrator import run_pipeline

    pkg = tmp_path / "app"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "routes_a.py").write_text(
        'from fastapi import APIRouter\n'
        'router = APIRouter()\n'
        '@router.get("/users")\n'
        'def list_users():\n'
        '    """List users."""\n'
        '    if True:\n'
        '        return []\n',
        encoding="utf-8",
    )
    (pkg / "routes_b.py").write_text(
        'from fastapi import APIRouter\n'
        'router = APIRouter()\n'
        '@router.post("/orders")\n'
        'def create_order(item_id: int):\n'
        '    """Create an order."""\n'
        '    return {"id": item_id}\n'
        'def get_helper():\n'
        '    """Internal helper: not an endpoint even though it starts with get_."""\n'
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

    # The OpenAPI spec merges the endpoints declared across every submodule of the package.
    spec = json.loads((rep_dir / "openapi.json").read_text(encoding="utf-8"))
    assert "/users" in spec["paths"]
    assert "/orders" in spec["paths"]
    assert "/helper" not in spec["paths"], "in the pipeline only decorators declare routes"

    # .env files are scanned alongside the Python code for exposed credentials.
    secrets_stage = next(s for s in report["stages"] if s["name"] == "defensive_secrets")
    assert secrets_stage["extra_config_files"] >= 1
    assert any(f["rule_id"] == "SECRET" and f["file"].endswith(".env") for f in report["findings"])

    # Structural metrics aggregate every module in the project, not just __init__.py.
    metrics_stage = next(s for s in report["stages"] if s["name"] == "refactor_metrics")
    assert metrics_stage["metrics"]["functions_count"] == 3

    # Container and dependency manifests are part of the full analysis.
    infra_stage = next(s for s in report["stages"] if s["name"] == "infra_and_deps")
    assert infra_stage["files_scanned"] >= 2
    assert any(f["rule_id"] == "DOCKERFILE" for f in report["findings"])
    assert any(f["rule_id"] == "DEPS-PIP" for f in report["findings"])


def test_sast_annotated_assignment_and_self_cls_are_not_counted(tmp_path):
    from agentes.quality.static_checker import StaticCodeAnalyzer

    p = tmp_path / "ann.py"
    p.write_text(
        'API_KEY: str = "supersecretvalue123"\n'
        'class Svc:\n'
        '    def method(self, a, b, c, d, e):\n'
        '        """Five real parameters besides self."""\n'
        '        return a\n'
        '    @classmethod\n'
        '    def build(cls, a, b, c, d, e):\n'
        '        """Five real parameters besides cls."""\n'
        '        return a\n',
        encoding="utf-8",
    )
    issues = StaticCodeAnalyzer.analyze_python_file(str(p), prefer_bandit=False)
    assert any("API_KEY" in msg for _, _, msg in issues)
    assert not any("arguments" in msg for _, _, msg in issues)


def test_dependency_auditor_extras_and_markers(tmp_path):
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

    index = {"uvicorn": ["0.26.0", "0.27.0", "0.30.1", "0.31.0rc1"], "requests": ["2.31.0", "2.32.3"]}
    _, count = DependencyAuditor.auto_fix_requirements_txt(str(req), index=lambda n: index[n.split("[")[0]])
    assert count == 2
    fixed = req.read_text(encoding="utf-8")
    # The latest stable version within the range: neither the lower bound nor a pre-release.
    assert 'uvicorn[standard]==0.30.1 ; python_version >= "3.10" # server' in fixed
    assert 'requests[security]==2.32.3 ; sys_platform != "win32"' in fixed


def test_qa_test_generator_classes_and_type_hints(tmp_path):
    from agentes.qa.test_generator import QATestGenerator
    from agentes.qa.test_runner import QATestRunner

    src = tmp_path / "calc_mod.py"
    src.write_text(
        'from typing import List, Dict\n'
        'class Calc:\n'
        '    def __init__(self, base: int = 10):\n'
        '        self.base = base\n'
        '    def combine(self, items: List[int], mapping: Dict[str, int], enabled: bool):\n'
        '        return len(items) + len(mapping) + (self.base if enabled else 0)\n',
        encoding="utf-8",
    )
    tst = tmp_path / "test_calc_mod.py"
    QATestGenerator.generate_test_suite(str(src), str(tst))
    body = tst.read_text(encoding="utf-8")

    # Instance methods are called on a constructed object, never as free functions.
    # base has a default value, so it is not passed and the constructor uses its own.
    assert "result = combine(" not in body
    assert "obj = Calc()" in body
    # Annotated containers get one element of their type: with an empty one, items[0] would fail.
    assert 'obj.combine([1], {"sample": 1}, True)' in body

    res = QATestRunner.run_unittest_suite(str(tst))
    assert res["tests_run"] == 1
    assert res["pass_rate_percentage"] == 100.0
    assert res["coverage"]["functions_tested"] == 1


def test_refactor_does_not_double_count_and_mermaid_is_valid(tmp_path):
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
    assert "%% +2 more methods in Big" in diagram


# --- Defensive security controls, token handling and AST static analysis ---

def test_input_sanitizer_canonical_path_and_dot(tmp_path):
    from agentes.defensive.input_sanitizer import InputSanitizer

    assert InputSanitizer.sanitize_filename(".") == "file_default"
    base = tmp_path / "sandbox"
    base.mkdir()
    ok = InputSanitizer.validate_safe_path(str(base), "sub/file.txt")
    assert ok is not None and ok.endswith("sandbox/sub/file.txt")
    assert InputSanitizer.validate_safe_path(str(base), "../../etc/passwd") is None
    assert InputSanitizer.validate_safe_path(str(base), "/etc/passwd") is None
    assert InputSanitizer.validate_safe_path(str(base), "a\x00b") is None


def test_config_manager_protected_env_and_secret_redaction(tmp_path, monkeypatch):
    from agentes.defensive.config_manager import ConfigManager

    monkeypatch.setenv("EXISTING_VAR", "original")
    monkeypatch.delenv("LD_PRELOAD", raising=False)
    monkeypatch.delenv("SAFE_NEW_VAR", raising=False)

    env = tmp_path / ".env"
    env.write_text(
        'LD_PRELOAD=/tmp/evil.so\n'
        'PYTHONPATH=/tmp/evil\n'
        'EXISTING_VAR=override_attempt\n'
        'SAFE_NEW_VAR=safe_value\n',
        encoding="utf-8",
    )
    loaded = ConfigManager.load_env_file(str(env))
    assert "LD_PRELOAD" not in loaded
    assert "PYTHONPATH" not in loaded
    assert "LD_PRELOAD" not in os.environ
    assert os.environ["EXISTING_VAR"] == "original"
    assert loaded["SAFE_NEW_VAR"] == "safe_value"

    secret_val = "ghp_" "16C7e42F292c6912E7710c838347Ae178B4a"
    sec_file = tmp_path / "sec.py"
    sec_file.write_text(f'TOKEN = "{secret_val}"\n', encoding="utf-8")
    hits = ConfigManager.scan_file_for_secrets(str(sec_file))
    assert hits
    assert secret_val not in hits[0][2]
    assert "***REDACTED***" in hits[0][2]


def test_auth_manager_rejects_alg_none_without_leaks_and_bounds_the_rate_limiter():
    import base64
    import hashlib
    import hmac

    from agentes.defensive.auth_manager import AuthManager, RateLimiter

    # A token with algorithm 'none' must be rejected explicitly, even when the HMAC signature matches.
    hdr = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    pld = base64.urlsafe_b64encode(b'{"user":"admin"}').decode().rstrip("=")
    sig = base64.urlsafe_b64encode(
        hmac.new(b"secret", f"{hdr}.{pld}".encode(), hashlib.sha256).digest()
    ).decode().rstrip("=")
    ok, _, msg = AuthManager.verify_secure_token(f"{hdr}.{pld}.{sig}", "secret")
    assert not ok
    assert "algorithm" in msg

    # Rejection messages returned to the caller must not expose stack traces or internal details.
    ok_bad, _, msg_bad = AuthManager.verify_secure_token("aaa.bbb.ccc", "secret")
    assert not ok_bad
    assert "Traceback" not in msg_bad

    rl = RateLimiter(max_requests=2, window_seconds=60, max_tracked_keys=3)
    for ip in ("ip1", "ip2", "ip3", "ip4"):
        rl.is_allowed(ip)
    assert len(rl.requests) <= 3


def test_sast_security_and_concurrency_rules(tmp_path):
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
    assert any("mutable default" in m for m in msgs)
    assert any("except Exception: pass" in m for m in msgs)
    assert any("async def" in m for m in msgs)

    # Checking that the file exists and then writing it is a TOCTOU race condition.
    # Reading it is not: the worst outcome is a FileNotFoundError.
    p2 = tmp_path / "toctou.py"
    p2.write_text(
        'import os\n'
        'def read(path):\n'
        '    """Read."""\n'
        '    if os.path.exists(path):\n'
        '        with open(path) as f:\n'
        '            return f.read()\n'
        'def create(path, mode):\n'
        '    """Create."""\n'
        '    if not os.path.exists(path):\n'
        '        with open(path, "w") as f:\n'
        '            f.write("x")\n'
        '    if os.path.isfile(path):\n'
        '        with open(path, mode=mode) as f:\n'
        '            f.write("y")\n',
        encoding="utf-8",
    )
    issues2 = StaticCodeAnalyzer.analyze_python_file(str(p2), prefer_bandit=False)
    assert sorted(line for line, _, m in issues2 if "TOCTOU" in m) == [10, 13]
    assert not any("context manager" in m for _, _, m in issues2)


# --- SOLID architecture rules, memory contracts, reliability and performance hygiene ---

def test_solid_checker_architecture_and_reliability(tmp_path):
    from agentes.refactor.solid_checker import SOLIDChecker

    bad = tmp_path / "arch_bad.py"
    bad.write_text(
        'from dataclasses import dataclass\n'
        'STATE = 0\n'
        '@dataclass\n'
        'class ConfigWithoutSlots:\n'
        '    name: str\n'
        '@dataclass(frozen=True, slots=True)\n'
        'class ImmutableConfig:\n'
        '    name: str\n'
        'def nested(a, b, items=[]):\n'
        '    global STATE\n'
        '    if a:\n'
        '        for x in items:\n'
        '            while b:\n'
        '                if x > 0:\n'
        '                    STATE += 1\n'
        'def failures(v):\n'
        '    try:\n'
        '        return int(v)\n'
        '    except ValueError:\n'
        '        raise RuntimeError("no from")\n'
        'def silences(v):\n'
        '    try:\n'
        '        return int(v)\n'
        '    except Exception:\n'
        '        return None\n'
        'def flat_elif(op):\n'
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

    # An elif chain sits at a single logical depth: it may trigger OCP but must not inflate GUARD.
    assert not any(p == "GUARD" and "flat_elif" in msg for _, p, _, msg in findings)
    # A dataclass with slots=True has no per-instance __dict__, so DATA-CONTRACT does not apply.
    assert not any(p == "DATA-CONTRACT" and "ImmutableConfig" in msg for _, p, _, msg in findings)
    # The auditor reports both global mutable state and mutable default parameters.
    state_msgs = [msg for _, p, _, msg in findings if p == "STATE-SAFETY"]
    assert any("Mutable default" in m for m in state_msgs)
    assert any("global" in m for m in state_msgs)
    # Re-raising without keeping __cause__ and returning None from a handler both hurt observability.
    exc_msgs = [msg for _, p, _, msg in findings if p == "EXCEPTION-HYGIENE"]
    assert any("from exc" in m for m in exc_msgs)
    assert any("silently" in m for m in exc_msgs)

    # Explicit chaining with 'from exc' keeps the original exception and is not flagged.
    good_chain = tmp_path / "chain_ok.py"
    good_chain.write_text(
        'def parse(v):\n'
        '    try:\n'
        '        return int(v)\n'
        '    except ValueError as exc:\n'
        '        raise RuntimeError("invalid") from exc\n',
        encoding="utf-8",
    )
    assert not any(p == "EXCEPTION-HYGIENE" for _, p, _, _ in SOLIDChecker.audit_file(str(good_chain)))


def test_code_metrics_performance_memory_and_io(tmp_path):
    from agentes.refactor.code_metrics import CodeMetricsCalculator
    from agentes.refactor.refactor_suggester import RefactorSuggester
    from agentes.refactor.solid_checker import SOLIDChecker

    perf_file = tmp_path / "perf_issues.py"
    perf_file.write_text(
        'import re, time, requests\n'
        'def bottleneck(items, path, cur):\n'
        '    out = ""\n'
        '    queue = list(items)\n'
        '    while queue:\n'
        '        first = queue.pop(0)\n'
        '        if first is None:\n'
        '            queue.insert(0, first)\n'
        '    with open(path) as f:\n'
        '        lines = f.readlines()\n'
        '    for item in items:\n'
        '        if item in ["A", "B", "C", "D", "E", "F", "G", "H", "I"]:\n'
        '            pat = re.compile(r"\\d+")\n'
        '            out += str(item)\n'
        '            requests.get("https://example.com", timeout=5)\n'
        '            cur.execute("SELECT 1")\n'
        '    return out, lines\n'
        'async def task():\n'
        '    time.sleep(0.1)\n',
        encoding="utf-8",
    )

    metrics = CodeMetricsCalculator.calculate_file_metrics(str(perf_file))
    perf = metrics["performance_findings"]
    assert perf == CodeMetricsCalculator.audit_performance(str(perf_file))

    categories = {cat for _, cat, _, _ in perf}
    assert "HIGH IMPACT - BIG-O COMPLEXITY" in categories
    assert "MEDIUM IMPACT - MEMORY FOOTPRINT" in categories
    assert "HIGH IMPACT - BLOCKING I/O" in categories

    msgs = [m for _, _, _, m in perf]
    assert any(".pop(0)" in m for m in msgs)
    assert any(".insert(0" in m for m in msgs)
    assert any("set" in m and "O(1)" in m for m in msgs)
    assert any("re.compile" in m for m in msgs)
    assert any(".readlines()" in m for m in msgs)
    assert any("join" in m for m in msgs)
    assert any("async def" in m and "time.sleep" in m for m in msgs)
    assert any("connection pooling" in m or "Session" in m for m in msgs)
    assert any("N+1" in m for m in msgs)

    solid_findings = SOLIDChecker.audit_file(str(perf_file))
    recs = RefactorSuggester.generate_recommendations(metrics, solid_findings)
    assert any("[HIGH IMPACT - BIG-O COMPLEXITY" in r for r in recs)
    assert any("[MEDIUM IMPACT - MEMORY FOOTPRINT" in r for r in recs)
    assert any("[HIGH IMPACT - BLOCKING I/O" in r for r in recs)


def test_refactor_recommendations_locate_every_warning():
    """Without a file the line is given; with location, the file and the line."""
    from agentes.refactor.refactor_suggester import RefactorSuggester

    metrics = {"comment_ratio": 0.0, "code_loc": 80, "avg_cyclomatic_complexity": 7.0,
               "performance_findings": [(9, "MEDIUM IMPACT - MEMORY FOOTPRINT", "MEDIUM", "readlines")]}
    solid = [(7, "SRP", "MEDIUM", "Big class")]

    bare = RefactorSuggester.generate_recommendations(metrics, solid)
    assert any(r.startswith("[DESIGN SRP - Line 7]") for r in bare)
    assert any(r.startswith("[MEDIUM IMPACT - MEMORY FOOTPRINT - Line 9]") for r in bare)

    located = RefactorSuggester.generate_recommendations(metrics, solid, location="pkg/mod.py")
    assert any(r.startswith("[DESIGN SRP - pkg/mod.py:7]") for r in located)
    assert any(r.startswith("[MEDIUM IMPACT - MEMORY FOOTPRINT - pkg/mod.py:9]") for r in located)
    # Whole-file recommendations say which file they are about too.
    assert any(r.startswith("[REFACTOR - pkg/mod.py]") for r in located)
    assert any(r.startswith("[DOCUMENTATION - pkg/mod.py]") for r in located)
    assert not any("Line" in r for r in located)


# --- Testability audit, adversarial generation and test-suite quality ---

def test_qa_testability_audit_and_scenario_matrix(tmp_path):
    from agentes.qa.test_generator import QATestGenerator

    src = tmp_path / "smelly_service.py"
    src.write_text(
        'import requests, time\n'
        'CACHE = []\n'
        'class Repo:\n'
        '    pass\n'
        'def process(uid, price):\n'
        '    global CACHE\n'
        '    repo = Repo()\n'
        '    ts = time.time()\n'
        '    if price < 0:\n'
        '        raise ValueError("Negative price")\n'
        '    r = requests.get(f"https://example.com/{uid}", timeout=5)\n'
        '    CACHE.append((uid, ts, repo, r))\n'
        '    return price\n'
        'async def sync_item(item_id):\n'
        '    if not item_id:\n'
        '        raise KeyError("id required")\n'
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

    # Every nominal path must yield at least three boundary, hostile or concurrency scenarios.
    happy_count = sum(1 for s in matrix if s["category"] == "[HAPPY PATH]")
    non_happy_count = len(matrix) - happy_count
    assert non_happy_count >= happy_count * 3


def test_qa_generated_pytest_suite_runs_and_is_clean(tmp_path):
    import subprocess

    from agentes.qa.test_generator import QATestGenerator
    from agentes.qa.test_runner import QATestRunner

    mod = tmp_path / "calc_adv.py"
    mod.write_text(
        'import urllib.request\n'
        'def add(a, b):\n'
        '    return a + b\n'
        'def calculate_discount(price, percent):\n'
        '    if percent < 0 or percent > 100:\n'
        '        raise ValueError("Invalid percentage")\n'
        '    return price * (1 - percent / 100)\n'
        'def download(url):\n'
        '    if not url:\n'
        '        raise ValueError("empty url")\n'
        '    return urllib.request.urlopen(url, timeout=1).read()\n'
        'async def async_task(uid):\n'
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

    # The generated suite must pass the suite quality audit without a single anti-pattern.
    qa_audit = QATestRunner.audit_test_suite_quality(str(test_out))
    assert qa_audit["findings"] == []
    assert qa_audit["uses_parametrize"] is True
    assert qa_audit["uses_fixtures"] is True
    assert qa_audit["assertions_count"] > 0

    # Run pytest on the emitted module to check its syntax, isolation and runtime behaviour.
    run = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", str(test_out)],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
    )
    assert run.returncode == 0, run.stdout + "\n" + run.stderr


def test_qa_runner_audits_sdet_antipatterns(tmp_path):
    from agentes.qa.test_runner import QATestRunner

    bad_test = tmp_path / "test_bad_sdet.py"
    bad_test.write_text(
        'import time, pytest, requests\n'
        'from unittest.mock import MagicMock, patch\n'
        'def test_empty():\n'
        '    x = 1 + 1\n'
        'def test_tautology_and_raises():\n'
        '    assert True\n'
        '    with pytest.raises(Exception):\n'
        '        int("x")\n'
        '    with pytest.raises(ValueError):\n'
        '        int("y")\n'
        'def test_io_without_mock():\n'
        '    time.sleep(0.01)\n'
        '    requests.get("https://example.com", timeout=1)\n'
        '    assert 1 == 1\n'
        'def test_fragile_mock():\n'
        '    m = MagicMock()\n'
        '    with patch("mod._internal"):\n'
        '        assert m is not None\n',
        encoding="utf-8",
    )

    audit = QATestRunner.audit_test_suite_quality(str(bad_test))
    codes = {c for _, c, _, _ in audit["findings"]}
    assert "WEAK-ASSERT" in codes
    assert "GENERIC-RAISES" in codes
    assert "UNISOLATED-IO" in codes
    assert "UNSAFE-MOCK" in codes


def test_api_contract_adversarial_payloads_and_sdet_report(tmp_path):
    from agentes.qa.api_contract_testing import APIContractTester
    from agentes.qa.qa_reporter import QAReporter

    # A negative, NaN or infinite latency has no meaning as a duration and must fail validation.
    for bad_ms in (-5.0, float("nan"), float("inf")):
        res = APIContractTester.validate_api_response("/x", 200, {}, {}, bad_ms, expected_status=200, max_sla_ms=500.0)
        assert not res["passed"]

    # Expected headers match case-insensitively, and missing headers are detected.
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

    # The adversarial set covers empty structures, wrong types, nulls and numeric extremes.
    payloads = APIContractTester.generate_adversarial_payloads({"id": int, "score": float, "name": str, "tags": list})
    labels = {name for name, _ in payloads}
    assert {"empty_payload", "non_dict_null", "null_fields", "bool_as_int_or_type_trap", "extreme_nan_giant"}.issubset(labels)

    # Active HTML in endpoint names is escaped when the report is rendered.
    html_p = QAReporter.generate_html_report(
        {"tests_run": 1, "passed": 1, "failures": 0, "errors": 0, "pass_rate_percentage": 100.0},
        [{"endpoint": "<script>alert(1)</script>", "elapsed_ms": 5, "passed": True}],
        str(tmp_path / "qa.html"),
    )
    html_body = open(html_p, encoding="utf-8").read()
    assert "<script>alert(1)</script>" not in html_body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_body

    # The full report has separate sections for testability, the scenario matrix and the generated suite.
    fixture = os.path.join(ROOT, "agentes", "qa", "fixtures", "sample_app.py")
    rpt = QAReporter.generate_adversarial_qa_report(
        fixture,
        str(tmp_path / "test_sample_app_adv.py"),
        str(tmp_path / "qa_adv.md"),
    )
    md = open(rpt, encoding="utf-8").read()
    assert "## 1. Testability Defects (QA Code Smells)" in md
    assert "## 2. Test Scenario Matrix" in md
    assert "## 3. Production-Ready Test Suite" in md


def test_orchestrator_skips_custom_venvs_and_caches(tmp_path):
    from agentes.common.orchestrator import run_pipeline

    (tmp_path / "app.py").write_text('def ok():\n    """Ok."""\n    return 1\n', encoding="utf-8")

    # Virtual environments with arbitrary names or a pyvenv.cfg marker, plus tool cache directories.
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


def test_heuristic_precision_without_false_positives(tmp_path):
    from agentes.defensive.config_manager import ConfigManager
    from agentes.qa.test_generator import QATestGenerator
    from agentes.quality.static_checker import StaticCodeAnalyzer
    from agentes.refactor.solid_checker import SOLIDChecker

    # The secret scanner ignores UI labels and self-describing constants without missing real credentials.
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

    # Inside test suites the static analyser skips the docstring, assert and generic-secret rules.
    test_sast = tmp_path / "test_sample.py"
    test_sast.write_text(
        'def test_something():\n'
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

    # The testability audit limits HARDCODED-DEP to concrete external clients, services and repositories.
    widgets_py = tmp_path / "widgets.py"
    widgets_py.write_text(
        'def render():\n'
        '    t = Table()\n'
        '    p = Panel("hello")\n'
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

    # Exception chaining is not required when re-raising the caught variable or raising a controlled process exit.
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
        '        raise RuntimeError("failure")\n',
        encoding="utf-8",
    )
    solid_findings = SOLIDChecker.audit_file(str(exc_py))
    hygiene = [f for f in solid_findings if f[1] == "EXCEPTION-HYGIENE"]
    assert len(hygiene) == 1
    assert hygiene[0][0] == 20


def test_parse_env_file_and_audit_env_leave_environ_untouched(tmp_path, monkeypatch):
    from agentes.common import audits
    from agentes.defensive.config_manager import ConfigManager

    env_path = tmp_path / ".env"
    env_path.write_text('CUSTOM_APP_TOKEN="secret1234567890"\nDEBUG=true\n', encoding="utf-8")
    monkeypatch.delenv("CUSTOM_APP_TOKEN", raising=False)
    monkeypatch.setenv("KEEP_EXISTING_ENV", "intact")

    parsed = ConfigManager.parse_env_file(str(env_path))
    assert parsed == {"CUSTOM_APP_TOKEN": "secret1234567890", "DEBUG": "true"}
    assert "CUSTOM_APP_TOKEN" not in os.environ

    def _forbid_load(*_args, **_kwargs):
        raise AssertionError("audit_env must neither call load_env_file nor modify os.environ")

    monkeypatch.setattr(ConfigManager, "load_env_file", staticmethod(_forbid_load))
    findings = audits.audit_env(str(env_path))
    assert findings
    assert os.environ.get("KEEP_EXISTING_ENV") == "intact"
    assert "CUSTOM_APP_TOKEN" not in os.environ


def test_prometheus_exporter_exact_counts_under_concurrency():
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
            statuses_404 = [f.result() for f in [pool.submit(fetch, "/missing") for _ in range(4)]]
        assert statuses_503 == [503] * 4
        assert statuses_404 == [404] * 4

        assert fetch("/metrics") == 200
        metrics_text = PrometheusExporter.generate_metrics()
        # 10 (/healthz 200) + 4 (/healthz 503) + 4 (/missing 404) + 1 (/metrics 200) = 19 requests, 8 errors
        assert "app_requests_total 19\n" in metrics_text
        assert "app_requests_errors_total 8\n" in metrics_text
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        PrometheusExporter.reset()


def test_sarif_specific_rules_and_driver_rules(tmp_path):
    from agentes import __version__
    from agentes.common.reporting import findings_to_sarif

    findings = [
        {"file": "a.py", "line": 2, "level": "CRITICAL", "rule_id": "SAST-CRITICAL",
         "message": "Use of the dynamic code execution function 'eval()'."},
        {"file": "a.py", "line": 5, "level": "HIGH", "rule_id": "SAST-HIGH", "message": "Possible SQL injection: f-string in execute()."},
        {"file": "b.py", "line": 3, "level": "HIGH", "rule_id": "SECRET", "message": "GitHub token: ghp***REDACTED***"},
        {"file": "b.py", "line": 4, "level": "HIGH", "rule_id": "SECRET", "message": "AWS access key (AKIA): AKI***REDACTED***"},
        {"file": "deploy.yaml", "line": 1, "level": "HIGH", "rule_id": "K8S-WORKLOAD", "message": "Missing runAsNonRoot"},
    ]
    out = findings_to_sarif("AGENTES-Pipeline", findings, str(tmp_path / "out.sarif"))
    sarif = json.loads(open(out, encoding="utf-8").read())
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["version"] == __version__
    rule_ids = [r["ruleId"] for r in sarif["runs"][0]["results"]]
    assert rule_ids == ["SAST-EVAL", "SAST-SQLI", "SECRET-GITHUB", "SECRET-AWS", "K8S-WORKLOAD"]
    declared = {r["id"] for r in driver["rules"]}
    assert set(rule_ids) <= declared


def test_github_actions_generator_is_current(tmp_path):
    from agentes.devops.github_actions_generator import GitHubActionsGenerator

    wf = tmp_path / "devsecops.yml"
    GitHubActionsGenerator.generate_workflow(str(wf))
    text = wf.read_text(encoding="utf-8")
    assert "contents: read" in text
    assert "security-events: write" not in text
    assert "python-version: '3.12'" in text
    assert "ruff check ." in text
    assert "bandit" in text


def test_cli_and_qa_submodules_are_importable():
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
