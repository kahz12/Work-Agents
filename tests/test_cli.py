"""Tests for the `agentes` CLI: commands, exit codes, JSON output and error messages."""
import io
import json
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentes import cli as agentes_cli  # noqa: E402

# Fake tokens are split into two literals ("ghp_" "16C7..."): Python joins them and the detector
# sees the whole token, but the file never contains a complete one, so GitHub's secret
# protection does not block the push.
FAKE_TOKEN = "ghp_" "16C7e42F292c6912E7710c838347Ae178B4a"


@pytest.fixture
def run(capsys):
    """Run the CLI in-process and return (exit code, stdout, stderr)."""
    def _run(*argv):
        code = agentes_cli.main(list(argv))
        captured = capsys.readouterr()
        return code, captured.out, captured.err
    return _run


@pytest.fixture
def project(tmp_path):
    """Minimal project with one finding of each kind."""
    (tmp_path / "app.py").write_text(
        "def get_user(user_id: int) -> dict:\n"
        '    """Return a user."""\n'
        '    return {"id": user_id}\n\n\n'
        "def add(a: int, b: int) -> int:\n"
        '    """Add two numbers."""\n'
        "    return a + b\n",
        encoding="utf-8",
    )
    (tmp_path / "Dockerfile").write_text("FROM python:latest\nUSER root\n", encoding="utf-8")
    (tmp_path / ".env").write_text(f'DEBUG=true\nTOKEN="{FAKE_TOKEN}"\n', encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("requests\nflask>=2.0\n", encoding="utf-8")
    (tmp_path / "app.log").write_text("ok\nTraceback (most recent call last)\n", encoding="utf-8")
    return tmp_path


# --- Overview screen, help and usage errors ---

def test_no_arguments_lists_every_command(run):
    code, out, _ = run()
    assert code == 0
    for name in agentes_cli.COMMAND_NAMES:
        assert name in out
    assert "\033[" not in out, "without a terminal there must be no colour codes"


@pytest.mark.parametrize("name", agentes_cli.COMMAND_NAMES + ["serve-sre"])
def test_every_command_has_help(run, name):
    code, out, _ = run(name, "-h")
    assert code == 0
    assert "Usage: agentes" in out


def test_help_for_a_command(run):
    code, out, _ = run("help", "pipeline")
    assert code == 0
    assert "--no-fail" in out


def test_unknown_command_suggests_the_closest_one(run):
    code, _, err = run("pipelin", ".")
    assert code == 2
    assert "'pipeline'" in err


def test_argument_errors_are_readable(run):
    code, _, err = run("pipeline")
    assert code == 2
    assert "The following arguments are required" in err


def test_missing_path_exits_with_2(run, tmp_path):
    code, _, err = run("secrets", str(tmp_path / "missing"))
    assert code == 2
    assert "Path does not exist" in err


def test_legacy_shortcut_and_aliases_still_work(run):
    assert run("--list")[0] == 0
    assert run("list")[0] == 0
    code, _, err = run("demo", "qaa")
    assert code == 2 and "'qa'" in err


# --- Analyse ---

def test_pipeline_json_is_the_full_report(run, project):
    code, out, _ = run("pipeline", str(project), "-o", str(project / "rep"), "--no-bandit", "--json")
    report = json.loads(out)
    assert code == 1
    assert report["schema"] == "agentes.pipeline.v1"
    assert os.path.isfile(report["artifacts"]["html"])


def test_readable_pipeline_summarises_stages_and_reports(run, project):
    code, out, _ = run("pipeline", str(project), "-o", str(project / "rep"), "--no-bandit")
    assert code == 1
    assert "Secrets" in out and "Reports" in out and "pipeline.html" in out


def test_secrets_fails_without_revealing_the_value(run, project):
    code, out, _ = run("secrets", str(project), "--json")
    data = json.loads(out)
    assert code == 1
    assert data["findings"] and all(f["level"] == "HIGH" for f in data["findings"])
    assert FAKE_TOKEN not in out


def test_secrets_on_a_clean_project(run, tmp_path):
    (tmp_path / "ok.py").write_text("X = 1\n", encoding="utf-8")
    code, out, _ = run("secrets", str(tmp_path))
    assert code == 0
    assert "No secrets found" in out


@pytest.mark.parametrize("filename,rule", [
    ("Dockerfile", "DOCKERFILE"),
    (".env", "ENV"),
    ("app.log", "LOG"),
    ("requirements.txt", "DEPS-PIP"),
])
def test_audit_infers_the_kind_from_the_name(run, project, filename, rule):
    _, out, _ = run("audit", str(project / filename), "--json")
    findings = json.loads(out)["findings"]
    assert findings and {f["rule_id"] for f in findings} == {rule}


def test_audit_env_does_not_pollute_the_environment(run, project):
    assert "DEBUG" not in os.environ
    run("audit", str(project / ".env"))
    assert "DEBUG" not in os.environ and "TOKEN" not in os.environ


def test_audit_directory_includes_env_and_logs(run, project):
    code, out, _ = run("audit", str(project), "--json")
    rules = {f.get("rule_id") for f in json.loads(out)["findings"]}
    assert code == 1
    assert {"DOCKERFILE", "ENV", "LOG"} <= rules


def test_audit_unknown_kind_asks_for_type(run, project):
    code, _, err = run("audit", str(project / "app.py"))
    assert code == 2
    assert "--type" in err


def test_audit_type_forces_the_auditor(run, tmp_path):
    odd = tmp_path / "container.txt"
    odd.write_text("FROM python:latest\nUSER root\n", encoding="utf-8")
    code, out, _ = run("audit", str(odd), "--type", "docker", "--json")
    assert code == 1
    assert json.loads(out)["findings"]


def test_metrics_json(run, project):
    code, out, _ = run("metrics", str(project), "--json")
    data = json.loads(out)
    assert code == 0
    assert data["totals"]["functions"] == 2
    assert {f["name"] for f in data["functions"]} == {"get_user", "add"}


CLEAN = 'def one() -> int:\n    """Return 1."""\n    return 1\n'


def _is_praise(recommendation: str) -> bool:
    return recommendation.startswith("[EXCELLENT]")


def test_metrics_does_not_praise_when_another_file_has_problems(run, tmp_path):
    # Recommendations are computed file by file: praise for a clean file must not appear next
    # to another file's problems.
    (tmp_path / "clean.py").write_text(CLEAN, encoding="utf-8")
    methods = "".join(f"    def m{i}(self):\n        return {i}\n" for i in range(11))
    (tmp_path / "big.py").write_text(f"class Big:\n{methods}", encoding="utf-8")
    code, out, _ = run("metrics", str(tmp_path), "--json")
    recommendations = json.loads(out)["recommendations"]
    assert code == 0
    assert any("SRP" in r for r in recommendations)
    assert not any(_is_praise(r) for r in recommendations)


def test_metrics_does_not_praise_when_a_file_could_not_be_analysed(run, tmp_path):
    (tmp_path / "clean.py").write_text(CLEAN, encoding="utf-8")
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    _, out, _ = run("metrics", str(tmp_path), "--json")
    data = json.loads(out)
    assert any(f["rule_id"] == "METRICS" for f in data["findings"])
    assert not any(_is_praise(r) for r in data["recommendations"])


BIG_CLASS = "class Big:\n" + "".join(f"    def m{i}(self):\n        return {i}\n" for i in range(11))


def test_metrics_recommendations_name_the_file(run, tmp_path):
    # With several files, "Line 1" does not say which one. And since recommendations are
    # deduplicated by text, without the file name two files with the same problem on the same
    # line would collapse into one.
    for name in ("a.py", "b.py"):
        (tmp_path / name).write_text(BIG_CLASS, encoding="utf-8")
    _, out, _ = run("metrics", str(tmp_path), "--json")
    srp = [r for r in json.loads(out)["recommendations"] if "SRP" in r]
    assert len(srp) == 2
    assert any("a.py:1]" in r for r in srp) and any("b.py:1]" in r for r in srp)
    assert not any("Line" in r for r in srp)


def test_metrics_average_based_recommendations_apply_to_the_whole_run(run, tmp_path):
    # Documentation density and average complexity are judged over everything analysed, like the
    # totals: judged file by file, the same recommendation would appear once per file.
    undocumented = "".join(f"def f{i}(x):\n    return x + {i}\n" for i in range(30))
    for name in ("a.py", "b.py"):
        (tmp_path / name).write_text(undocumented, encoding="utf-8")
    _, out, _ = run("metrics", str(tmp_path), "--json")
    docs = [r for r in json.loads(out)["recommendations"] if r.startswith("[DOCUMENTATION")]
    assert len(docs) == 1


def test_metrics_says_how_many_recommendations_it_hides(run, tmp_path):
    for name in ("a.py", "b.py", "c.py"):
        (tmp_path / name).write_text(BIG_CLASS, encoding="utf-8")
    total = len(json.loads(run("metrics", str(tmp_path), "--json")[1])["recommendations"])
    code, out, _ = run("metrics", str(tmp_path), "--limit", "1")
    assert code == 0 and total > 1
    recommendations = out.split("Recommendations", 1)[1]
    assert recommendations.count("\n  - ") == 1
    assert f"and {total - 1} more. Use --limit 0 to show them all." in recommendations
    _, everything, _ = run("metrics", str(tmp_path), "--limit", "0")
    assert everything.split("Recommendations", 1)[1].count("\n  - ") == total
    assert "show them all" not in everything


def test_metrics_praises_a_clean_project_exactly_once(run, tmp_path):
    (tmp_path / "clean.py").write_text(CLEAN, encoding="utf-8")
    (tmp_path / "other.py").write_text(CLEAN.replace("one", "other"), encoding="utf-8")
    _, out, _ = run("metrics", str(tmp_path), "--json")
    recommendations = json.loads(out)["recommendations"]
    assert len(recommendations) == 1 and _is_praise(recommendations[0])


def _pipeline_recommendations(run, folder):
    _, out, _ = run("pipeline", str(folder), "-o", str(folder / "rep"), "--no-bandit", "--offline", "--json")
    stage = next(s for s in json.loads(out)["stages"] if s["name"] == "refactor_metrics")
    return stage["recommendations"]


def test_pipeline_recommendations_name_the_file(run, tmp_path):
    # Same rule as metrics: line-specific recommendations carry their file, relative to the root.
    (tmp_path / "pkg").mkdir()
    for name in ("a.py", "b.py"):
        (tmp_path / "pkg" / name).write_text(BIG_CLASS, encoding="utf-8")
    srp = [r for r in _pipeline_recommendations(run, tmp_path) if "SRP" in r]
    assert len(srp) == 2
    assert any("pkg/a.py:1]" in r for r in srp) and any("pkg/b.py:1]" in r for r in srp)
    assert not any("Line" in r for r in srp)


def test_pipeline_average_based_recommendations_appear_once(run, tmp_path):
    undocumented = "".join(f"def f{i}(x):\n    return x + {i}\n" for i in range(30))
    for name in ("a.py", "b.py"):
        (tmp_path / name).write_text(undocumented, encoding="utf-8")
    recommendations = _pipeline_recommendations(run, tmp_path)
    assert [r for r in recommendations if r.startswith("[DOCUMENTATION")] == [
        next(r for r in recommendations if r.startswith("[DOCUMENTATION]"))
    ]


def test_pipeline_does_not_praise_when_a_file_could_not_be_analysed(run, tmp_path):
    (tmp_path / "clean.py").write_text(CLEAN, encoding="utf-8")
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    assert not any(_is_praise(r) for r in _pipeline_recommendations(run, tmp_path))


def test_pipeline_praises_a_clean_project(run, tmp_path):
    (tmp_path / "clean.py").write_text(CLEAN, encoding="utf-8")
    recommendations = _pipeline_recommendations(run, tmp_path)
    assert len(recommendations) == 1 and _is_praise(recommendations[0])


# --- Generate and fix ---

WITHOUT_SOURCE = ["compose", "k8s", "dockerfile", "systemd", "nginx", "caddy", "github-actions", "gitlab-ci"]


def test_generators_covers_every_kind_tested():
    with_source = {k for k, spec in agentes_cli.GENERATORS.items() if spec[2]}
    assert with_source == {"openapi", "swagger", "docs", "diagram", "tests"}
    assert set(agentes_cli.GENERATORS) == set(WITHOUT_SOURCE) | {"helm", "linters"} | with_source


@pytest.mark.parametrize("kind", WITHOUT_SOURCE)
def test_generate_without_source(run, tmp_path, kind):
    out_file = tmp_path / "output" / f"{kind}.out"
    code, out, _ = run("generate", kind, "-o", str(out_file))
    assert code == 0 and "[OK]" in out
    assert out_file.stat().st_size > 0


def test_generate_helm_and_linters_write_into_a_directory(run, tmp_path):
    assert run("generate", "helm", "-o", str(tmp_path / "chart"), "--service", "api")[0] == 0
    assert (tmp_path / "chart" / "Chart.yaml").is_file()
    assert run("generate", "linters", "-o", str(tmp_path / "cfg"))[0] == 0
    assert (tmp_path / "cfg" / ".flake8").is_file()


@pytest.mark.parametrize("kind,name", [
    ("openapi", "openapi.json"), ("openapi", "openapi.yaml"), ("swagger", "ui.html"),
    ("docs", "DOCS.md"), ("diagram", "diagram.md"), ("tests", "test_app.py"),
])
def test_generate_with_source(run, project, kind, name):
    out_file = project / "gen" / name
    code, _, _ = run("generate", kind, "--source", str(project / "app.py"), "-o", str(out_file))
    assert code == 0
    assert out_file.stat().st_size > 0


def test_generate_pytest_tests_suggests_pytest(run, project):
    code, out, _ = run("generate", "tests", "--source", str(project / "app.py"),
                       "-o", str(project / "test_p.py"), "--framework", "pytest")
    assert code == 0
    assert "pytest" in out and "agentes test" not in out


def test_generate_does_not_overwrite_without_force(run, tmp_path):
    target = tmp_path / "docker-compose.yml"
    assert run("generate", "compose", "-o", str(target))[0] == 0
    target.write_text("mine\n", encoding="utf-8")
    code, _, err = run("generate", "compose", "-o", str(target))
    assert code == 2 and "--force" in err
    assert target.read_text(encoding="utf-8") == "mine\n"
    assert run("generate", "compose", "-o", str(target), "--force")[0] == 0
    assert target.read_text(encoding="utf-8") != "mine\n"


def test_generate_linters_keeps_an_existing_pyproject(run, tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'mine'\n", encoding="utf-8")
    code, out, _ = run("generate", "linters", "-o", str(tmp_path))
    assert code == 0
    assert "name = 'mine'" in (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
    assert "Keeping" in out
    assert (tmp_path / ".flake8").is_file()


def test_generate_without_kind_lists_them_and_missing_source_is_reported(run):
    code, out, _ = run("generate")
    assert code == 0 and all(kind in out for kind in agentes_cli.GENERATORS)
    code, _, err = run("generate", "openapi")
    assert code == 2 and "--source" in err


@pytest.fixture
def simulated_network(monkeypatch):
    """Fake PyPI and OSV: known versions and one vulnerability in flask 2.3.3."""
    from agentes.quality import dependency_auditor, vulnerabilities

    monkeypatch.delenv("AGENTES_OFFLINE", raising=False)
    index = {"requests": ["2.31.0", "2.32.3"], "flask": ["2.0.0", "2.3.3"]}
    monkeypatch.setattr(dependency_auditor, "pypi_versions", lambda name, timeout=10.0: index[name])

    def osv(deps, timeout=15.0):
        out = {d.key: [] for d in deps}
        for d in deps:
            if d.name == "flask" and d.version == "2.3.3":
                out[d.key] = [vulnerabilities.Vulnerability("GHSA-x", ["CVE-2099-1"], "Test flaw", "HIGH", "3.0.0")]
        return out

    monkeypatch.setattr(vulnerabilities, "query_osv", osv)


def test_fix_dry_run_changes_nothing_and_reports_vulnerabilities(run, project, simulated_network):
    req = project / "requirements.txt"
    before = req.read_text(encoding="utf-8")
    code, out, _ = run("fix", str(req), "--dry-run")
    assert code == 1, "the resulting flask version has a high-severity vulnerability"
    assert "requests==2.32.3" in out and "flask==2.3.3" in out
    assert "CVE-2099-1" in out and "3.0.0" in out
    assert req.read_text(encoding="utf-8") == before

    code, out, _ = run("fix", str(req), "--json")
    data = json.loads(out)
    assert data["corrections"] == 2 and data["vulnerabilities"][0]["level"] == "HIGH"
    assert "requests==2.32.3" in req.read_text(encoding="utf-8")


def test_fix_without_network_invents_no_versions(run, project):
    req = project / "requirements.txt"
    before = req.read_text(encoding="utf-8")
    code, _, err = run("fix", str(req))
    assert code == 2 and "offline mode" in err
    assert req.read_text(encoding="utf-8") == before


def test_vulns_offline_and_with_a_simulated_network(run, project, simulated_network, monkeypatch):
    (project / "requirements.txt").write_text("flask==2.3.3\nrequests>=2\n", encoding="utf-8")
    code, out, _ = run("vulns", str(project), "--json")
    data = json.loads(out)
    assert code == 1
    assert data["dependencies_checked"] == 1 and data["dependencies_unpinned"] == 1
    assert data["findings"][0]["rule_id"] == "VULN-GHSA-x"

    monkeypatch.setenv("AGENTES_OFFLINE", "1")
    code, _, err = run("vulns", str(project))
    assert code == 2 and "offline mode" in err


# --- Test ---

def test_test_runs_the_suite_and_fails_when_it_does_not_pass(run, tmp_path):
    (tmp_path / "modz.py").write_text("def double(x):\n    return x * 2\n", encoding="utf-8")
    suite = tmp_path / "test_modz.py"
    suite.write_text(
        "import unittest\nfrom modz import double\n\n"
        "class T(unittest.TestCase):\n"
        "    def test_double(self):\n        self.assertEqual(double(2), 4)\n",
        encoding="utf-8",
    )
    code, out, _ = run("test", str(suite))
    assert code == 0 and "All tests pass" in out

    # The failing suite goes into a separate file. Rewriting the same file with the same size
    # within the same second makes Python reuse the old .pyc and run the passing version.
    failing = tmp_path / "test_modz_fails.py"
    failing.write_text(suite.read_text(encoding="utf-8").replace("4)", "5)"), encoding="utf-8")
    code, out, _ = run("test", str(failing), "--json")
    assert code == 1
    assert json.loads(out)["failures"] == 1


def test_testability_with_matrix(run, project):
    code, out, _ = run("testability", str(project / "app.py"), "--matrix", "--json")
    assert code == 0
    assert json.loads(out)["scenarios"]


def test_contract_rejects_non_http_schemes(run):
    code, _, err = run("contract", "ftp://example")
    assert code == 2 and "http" in err


def test_contract_schema_from_json():
    schema = agentes_cli._schema_from_json({"id": "int", "tags": ["str"], "owner": {"ok": "bool"}})
    assert schema == {"id": int, "tags": [str], "owner": {"ok": bool}}
    with pytest.raises(agentes_cli.CliError):
        agentes_cli._schema_from_json({"id": "uuid"})


# --- Operate and utilities ---

def test_sla_exit_codes(run):
    assert run("sla", "--total", "1000", "--errors", "8")[0] == 0
    code, out, _ = run("sla", "--total", "1000", "--errors", "80", "--json")
    assert code == 1 and json.loads(out)["alert"] is True
    assert run("sla", "--total", "10", "--errors", "11")[0] == 2


def test_health_json_and_malformed_tcp(run):
    code, out, _ = run("health", "--min-free-mb", "0", "--json")
    assert code == 0 and json.loads(out)["status"] == "HEALTHY"
    assert run("health", "--tcp", "no_port")[0] == 2


def test_password_check_hash_and_verify(run, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO("abc\n"))
    code, out, _ = run("password", "check", "--stdin")
    assert code == 1 and "weak" in out

    strong = "Th1s-Is_A-L0ng!Passw0rd"
    monkeypatch.setattr(sys, "stdin", io.StringIO(strong + "\n"))
    code, out, _ = run("password", "hash", "--stdin")
    hashed = out.strip()
    assert code == 0 and ":" in hashed and strong not in hashed

    monkeypatch.setattr(sys, "stdin", io.StringIO(strong + "\n"))
    assert run("password", "verify", hashed, "--stdin")[0] == 0
    monkeypatch.setattr(sys, "stdin", io.StringIO("other\n"))
    assert run("password", "verify", hashed, "--stdin")[0] == 1
    assert run("password", "verify")[0] == 2


def test_doctor_json(run):
    code, out, _ = run("doctor", "--json")
    data = json.loads(out)
    assert code == 0
    assert {c["name"] for c in data["checks"]} >= {"Python", "PyYAML", "bandit"}


def test_no_color_and_force_color(run, monkeypatch):
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.delenv("NO_COLOR", raising=False)
    try:
        assert "\033[" in run("sla", "--total", "10", "--errors", "0")[1]
        assert "\033[" not in run("sla", "--total", "10", "--errors", "0", "--no-color")[1]
    finally:
        agentes_cli.ui.set_color(None)


def test_cli_output_contains_no_emoji(run, project):
    outputs = [run()[1], run("list")[1], run("doctor")[1], run("generate")[1],
               run("pipeline", str(project), "-o", str(project / "rep"), "--no-bandit")[1],
               run("sla", "--total", "10", "--errors", "9")[1]]
    for text in outputs:
        assert not any(ord(ch) >= 0x2600 for ch in text), "the CLI uses no emoji or pictographs"


def test_cli_offline_and_no_color_do_not_leak_into_the_process(tmp_path, monkeypatch):
    src = tmp_path / "ok.py"
    src.write_text("def one():\n    return 1\n", encoding="utf-8")
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


# --- Overview screen and unexpected errors (edge cases) ---

def test_help_for_a_command_that_does_not_exist(run):
    code, _, err = run("help", "deploy")
    assert code == 2 and "No help available for 'deploy'" in err


@pytest.mark.parametrize("error, exit_code, message", [
    (KeyboardInterrupt, 130, "Interrupted."),
    (BrokenPipeError, 0, ""),
    (RuntimeError("something broke"), 1, "Unexpected error: something broke"),
])
def test_errors_while_a_command_runs(run, monkeypatch, error, exit_code, message):
    from agentes.sre.alerting_engine import AlertingEngine

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(AlertingEngine, "evaluate_error_rate", fail)
    code, _, err = run("sla", "--total", "10", "--errors", "1")
    assert code == exit_code and message in err


def test_agentes_debug_shows_the_traceback(run, monkeypatch):
    from agentes.sre.alerting_engine import AlertingEngine

    monkeypatch.setattr(AlertingEngine, "evaluate_error_rate", lambda *a, **k: 1 / 0)
    monkeypatch.setenv("AGENTES_DEBUG", "1")
    with pytest.raises(ZeroDivisionError):
        run("sla", "--total", "10", "--errors", "1")


# --- Analyse (edge cases) ---

def test_pipeline_baseline_and_write_baseline_together(run, project, tmp_path):
    code, _, err = run("pipeline", str(project), "--baseline", "a.json", "--write-baseline", "b.json")
    assert code == 2 and "cannot be used together" in err


def test_pipeline_baseline_that_is_not_a_baseline(run, project, tmp_path):
    bad = tmp_path / "other.json"
    bad.write_text('{"schema": "something else"}', encoding="utf-8")
    code, _, err = run("pipeline", str(project), "--baseline", str(bad), "-o", str(tmp_path / "r"))
    assert code == 2 and "is not an agentes baseline" in err


def test_pipeline_reports_unused_entries_suppressions_and_truncation(run, project, tmp_path):
    baseline = tmp_path / "base.json"
    assert run("pipeline", str(project), "--write-baseline", str(baseline), "-o", str(tmp_path / "r"))[0] == 0
    # The secret in .env goes away, so its baseline entry is left unused.
    (project / ".env").write_text("DEBUG=true\n", encoding="utf-8")
    (project / "other.py").write_text("import os\n\nos.system('ls')  # agentes: ignore - fixed command\n", encoding="utf-8")
    code, out, _ = run("pipeline", str(project), "--baseline", str(baseline), "--max-files", "1",
                       "-o", str(tmp_path / "r"), "--offline", "--no-bandit", "--no-color")
    assert "entries no longer match anything: regenerate the baseline" in out
    assert ".py files were left out because of --max-files" in out


def test_pipeline_text_reports_suppressions_and_openapi(run, tmp_path):
    (tmp_path / "api.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n\n\n@app.route('/users')\ndef users():\n"
        "    \"\"\"List users.\"\"\"\n    return []\n\n\ndef run(cmd):\n    \"\"\"Doc.\"\"\"\n"
        "    import subprocess\n    return subprocess.run(cmd, shell=True)  # agentes: ignore - fixed\n",
        encoding="utf-8")
    code, out, _ = run("pipeline", str(tmp_path), "-o", str(tmp_path / "r"), "--offline", "--no-bandit", "--no-color")
    assert code == 0
    assert "suppressed inline" in out
    assert "OpenAPI" in out and (tmp_path / "r" / "openapi.json").is_file()


def test_secrets_text_reminds_to_rotate_published_secrets(run, project):
    code, out, _ = run("secrets", str(project), "--no-color")
    assert code == 1 and "rotate it as well as deleting it" in out


def test_audit_headers_of_a_url(run, http_server, closed_port):
    code, out, _ = run("audit", f"{http_server.url}/json", "--json")
    data = json.loads(out)
    assert data["kind"] == "HTTP headers" and data["findings"]
    assert all(f["rule_id"] == "HTTP-HEADERS" for f in data["findings"])
    # An error response still carries headers worth auditing.
    assert json.loads(run("audit", f"{http_server.url}/status/404", "--json")[1])["findings"]
    code, _, err = run("audit", f"http://127.0.0.1:{closed_port}/")
    assert code == 2 and "Could not connect" in err


def test_audit_usage_errors(run, project):
    code, _, err = run("audit", str(project / "Dockerfile"), "--type", "headers")
    assert code == 2 and "needs an http:// or https:// URL" in err
    code, _, err = run("audit", str(project), "--type", "docker")
    assert code == 2 and "--type only applies to a single file" in err


def test_vulns_without_manifests(run, tmp_path):
    code, _, err = run("vulns", str(tmp_path))
    assert code == 2 and "No dependency manifests" in err


def test_vulns_text_with_constraints_that_block_the_fix(run, tmp_path, simulated_network):
    (tmp_path / "requirements.txt").write_text("flask==2.3.3\nrequests>=2\n", encoding="utf-8")
    (tmp_path / "requirements-base.txt").write_text("flask>=2,<3\n", encoding="utf-8")
    code, out, _ = run("vulns", str(tmp_path), "--no-color")
    assert code == 1
    assert "dependencies without an exact version cannot be checked" in out
    assert "Constraints that block installing the fix" in out and "the fix needs 3.0.0" in out
    assert "Upgrade each package to at least the fixed version" in out


def test_vulns_when_osv_does_not_respond(run, tmp_path, simulated_network, monkeypatch):
    from agentes.quality import vulnerabilities

    def down(deps, timeout=15.0):
        raise vulnerabilities.VulnDBUnavailable("timed out")

    monkeypatch.setattr(vulnerabilities, "query_osv", down)
    (tmp_path / "requirements.txt").write_text("flask==2.3.3\n", encoding="utf-8")
    code, _, err = run("vulns", str(tmp_path))
    assert code == 2 and "Could not query OSV: timed out" in err


def test_metrics_without_files_and_with_performance_findings(run, tmp_path):
    code, _, err = run("metrics", str(tmp_path))
    assert code == 2 and "No .py files" in err
    (tmp_path / "m.py").write_text('"""Doc."""\n\n\ndef f(queue):\n    """Doc."""\n    while queue:\n'
                                   "        queue.pop(0)\n", encoding="utf-8")
    data = json.loads(run("metrics", str(tmp_path), "--json")[1])
    assert any(f["rule_id"] == "PERF" for f in data["findings"])


# --- Generate and fix (edge cases) ---

def test_generate_openapi_from_a_broken_source_or_one_without_routes(run, tmp_path):
    broken = tmp_path / "broken.py"
    broken.write_text("def (:\n", encoding="utf-8")
    code, _, err = run("generate", "openapi", "--source", str(broken), "-o", str(tmp_path / "oa.json"))
    assert code == 2 and "Could not read" in err
    plain = tmp_path / "plain.py"
    plain.write_text("def compute(x):\n    return x\n", encoding="utf-8")
    code, out, err = run("generate", "openapi", "--source", str(plain), "-o", str(tmp_path / "oa.json"), "--no-color")
    assert code == 0 and "No routes detected" in out + err


def test_generate_tests_default_output_and_invalid_source(run, tmp_path):
    source = tmp_path / "calc.py"
    source.write_text("def double(x):\n    return x * 2\n", encoding="utf-8")
    assert run("generate", "tests", "--source", str(source))[0] == 0
    assert (tmp_path / "test_calc.py").is_file()
    broken = tmp_path / "broken.py"
    broken.write_text("def (:\n", encoding="utf-8")
    code, _, err = run("generate", "tests", "--source", str(broken), "-o", str(tmp_path / "t.py"))
    assert code == 2 and "check that it is valid Python" in err


def test_generate_tests_record_warns_and_fails_when_the_module_does_not_load(run, tmp_path):
    source = tmp_path / "calc.py"
    source.write_text("def double(x):\n    return x * 2\n", encoding="utf-8")
    code, out, err = run("generate", "tests", "--source", str(source), "-o", str(tmp_path / "t1.py"), "--record",
                         "--no-color")
    assert code == 0
    assert "--record imports and runs" in out + err and "pin down the current behaviour" in out + err
    broken = tmp_path / "explodes.py"
    broken.write_text("raise RuntimeError('cannot load')\n\n\ndef f(x):\n    return x\n", encoding="utf-8")
    code, _, err = run("generate", "tests", "--source", str(broken), "-o", str(tmp_path / "t2.py"), "--record")
    assert code == 2 and "Generate the suite without --record" in err


def test_generate_linters_does_not_overwrite(run, tmp_path):
    out_dir = tmp_path / "cfg"
    assert run("generate", "linters", "-o", str(out_dir))[0] == 0
    code, out, err = run("generate", "linters", "-o", str(out_dir), "--no-color")
    assert code == 0 and "Keeping" in out + err and "No file was generated." in out + err


def test_fix_default_version_warns_that_it_has_no_effect(run, project):
    code, out, err = run("fix", str(project / "requirements.txt"), "--default-version", "1.0", "--no-color")
    assert "--default-version has no effect" in out + err
    assert code == 2, "nothing can be pinned offline"


def test_fix_text_unchanged_unresolved_and_applied(run, tmp_path, simulated_network, monkeypatch):
    from agentes.quality import dependency_auditor
    from agentes.quality.package_index import PackageNotFound

    index = {"requests": ["2.31.0", "2.32.3"]}

    def pypi(name, timeout=10.0):
        if name not in index:
            raise PackageNotFound(name)
        return index[name]

    monkeypatch.setattr(dependency_auditor, "pypi_versions", pypi)
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.32.3\n", encoding="utf-8")
    code, out, _ = run("fix", str(req), "--no-color")
    assert code == 0 and "has no versions to pin" in out

    req.write_text("requests>=2\nno-such-package>=1\n", encoding="utf-8")
    code, out, _ = run("fix", str(req), "--no-color")
    assert "Unchanged" in out and "no-such-package" in out
    assert "1 changes applied" in out
    assert req.read_text(encoding="utf-8").startswith("requests==2.32.3")


def test_fix_says_so_when_osv_does_not_respond(run, tmp_path, simulated_network, monkeypatch):
    from agentes.quality import vulnerabilities

    def down(deps, timeout=15.0):
        raise vulnerabilities.VulnDBUnavailable("timed out")

    monkeypatch.setattr(vulnerabilities, "query_osv", down)
    req = tmp_path / "requirements.txt"
    req.write_text("requests>=2\n", encoding="utf-8")
    code, out, err = run("fix", str(req), "--dry-run", "--no-color")
    assert code == 0 and "Could not query OSV: timed out" in out + err


# --- Test (edge cases) ---

def test_test_without_tests_or_with_a_broken_suite(run, tmp_path):
    empty = tmp_path / "test_empty.py"
    empty.write_text("x = 1\n", encoding="utf-8")
    code, out, _ = run("test", str(empty), "--no-color")
    assert code == 1 and "No unittest tests were found" in out
    broken = tmp_path / "test_broken.py"
    broken.write_text("def (:\n", encoding="utf-8")
    # unittest does not fail while discovering it: the broken suite counts as one test with an error.
    code, out, _ = run("test", str(broken), "--no-color")
    assert code == 1 and "SyntaxError" in out
    data = json.loads(run("test", str(broken), "--json")[1])
    assert (data["tests_run"], data["errors"]) == (1, 1)


def test_test_shows_failures_and_suite_quality(run, tmp_path):
    (tmp_path / "modq.py").write_text("def triple(x):\n    return x * 3\n", encoding="utf-8")
    suite = tmp_path / "test_modq.py"
    suite.write_text(
        "import unittest\nfrom modq import triple\n\n"
        "class T(unittest.TestCase):\n"
        "    def test_triple(self):\n        self.assertEqual(triple(2), 7)\n"
        "    def test_tautology(self):\n        self.assertTrue(True)\n",
        encoding="utf-8",
    )
    code, out, _ = run("test", str(suite), "--no-color")
    assert code == 1
    assert "Failing tests" in out and "AssertionError" in out and "--verbose" in out
    assert "Suite quality" in out and "WEAK-ASSERT" in out
    assert "1 tests do not pass." in out
    code, out, _ = run("test", str(suite), "--verbose", "--no-color")
    assert "Traceback" in out


def test_testability_as_text_with_and_without_matrix(run, project):
    code, out, _ = run("testability", str(project / "app.py"), "--no-color")
    assert code == 0 and "Add --matrix" in out and "agentes generate tests --source" in out
    code, out, _ = run("testability", str(project / "app.py"), "--matrix", "--limit", "1", "--no-color")
    assert "Suggested test scenarios" in out and "Use --limit 0 to show them all." in out


# --- Operate and utilities (edge cases) ---

def test_sla_without_traffic(run):
    code, out, err = run("sla", "--total", "0", "--errors", "0", "--no-color")
    assert code == 0 and "No traffic recorded" in out + err


def _stdin(monkeypatch, text):
    monkeypatch.setattr(sys, "stdin", io.StringIO(text))


def test_password_check_json(run, monkeypatch):
    _stdin(monkeypatch, "Tr0mb0ne-Blue-Rain\n")
    code, out, _ = run("password", "check", "--stdin", "--json")
    data = json.loads(out)
    assert code == 0 and data["strength"] in ("acceptable", "strong") and data["breaches"] is None


def test_password_hash_warns_on_stderr_and_prints_only_the_hash_on_stdout(run, monkeypatch):
    from agentes.defensive import auth_manager

    monkeypatch.setattr(auth_manager, "HAS_ARGON2", False)
    monkeypatch.setattr(auth_manager, "HAS_BCRYPT", False)
    _stdin(monkeypatch, "short\n")
    code, out, err = run("password", "hash", "--stdin")
    assert code == 0
    assert out.strip().startswith("pbkdf2:sha256:600000:") and len(out.strip().splitlines()) == 1
    assert "the password is weak" in err and "using PBKDF2" in err


def test_password_hash_json(run, monkeypatch):
    _stdin(monkeypatch, "Tr0mb0ne-Blue-Rain\n")
    data = json.loads(run("password", "hash", "--stdin", "--json")[1])
    assert data["hash"].startswith(f"{data['backend'].split(':')[0]}:")


def test_password_verify_asks_to_regenerate_an_old_hash(run, monkeypatch):
    from agentes.defensive import auth_manager
    from agentes.defensive.auth_manager import AuthManager

    monkeypatch.setattr(auth_manager, "HAS_ARGON2", False)
    monkeypatch.setattr(auth_manager, "HAS_BCRYPT", False)
    old = AuthManager.hash_password("Correct-123", iterations=1000)
    _stdin(monkeypatch, "Correct-123\n")
    code, out, err = run("password", "verify", old, "--stdin", "--no-color")
    assert code == 0 and "matches" in out and "Regenerate it" in out + err
    _stdin(monkeypatch, "Correct-123\n")
    assert json.loads(run("password", "verify", old, "--stdin", "--json")[1]) == {"valid": True, "needs_rehash": True}
    _stdin(monkeypatch, "Other-456\n")
    code, out, err = run("password", "verify", old, "--stdin", "--no-color")
    assert code == 1 and "does not match" in out + err


def test_empty_password_or_one_that_does_not_match_when_repeated(run, monkeypatch):
    _stdin(monkeypatch, "\n")
    code, _, err = run("password", "check", "--stdin")
    assert code == 2 and "The password is empty." in err
    answers = iter(["First-123", "Second-456"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    code, _, err = run("password", "hash")
    assert code == 2 and "do not match" in err


def test_unknown_demo_suggests_the_closest_one(run):
    code, _, err = run("demo", "defensiv")
    assert code == 2 and "Did you mean 'defensive'?" in err


def test_demo_all_runs_all_eight_and_writes_outside_the_package(run, tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTES_WORKDIR", str(tmp_path))
    code, out, _ = run("demo", "all")
    assert code == 0
    for agent, artefact in [
        ("devops", "docker-compose.yml"), ("docs", "openapi.json"), ("hardening", "Dockerfile.hardened"),
        ("qa", "qa_report.html"), ("quality", "results.sarif"), ("refactor", "sample_monolith.py"),
        ("sre", "sample_app.log"),
    ]:
        assert (tmp_path / agent / artefact).is_file(), (agent, artefact)
    assert "QA agent finished successfully." in out


def test_agent_name_shortcut_runs_its_demo(run, tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTES_WORKDIR", str(tmp_path))
    assert run("docs")[0] == 0
    assert (tmp_path / "docs" / "swagger_ui.html").is_file()


def test_doctor_as_text_depending_on_what_is_installed(run, monkeypatch):
    from agentes.cli import ops

    monkeypatch.setattr(ops, "_module_available", lambda name: name != "argon2")
    code, out, _ = run("doctor", "--no-color")
    assert code == 0 and "Ready to use" in out and 'pip install -e ".[all]"' in out
    monkeypatch.setattr(ops, "_module_available", lambda name: name != "yaml")
    code, out, _ = run("doctor", "--no-color")
    assert code == 1 and "Required components are missing." in out


def test_module_available_does_not_raise_on_odd_names():
    from agentes.cli import ops

    assert ops._module_available("json")
    assert not ops._module_available("no_such_module_here")
    assert not ops._module_available("no_such.submodule")
