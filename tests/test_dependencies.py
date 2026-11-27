"""Tests for fix (versions from PyPI) and the OSV vulnerability lookup, without network access."""
import json
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentes.common.orchestrator import dependency_vulnerability_stage, run_pipeline  # noqa: E402
from agentes.quality import vulnerabilities as vulns  # noqa: E402
from agentes.quality.dependency_auditor import DependencyAuditor  # noqa: E402
from agentes.quality.package_index import IndexUnavailable, PackageNotFound, best_version  # noqa: E402

# --- Choosing a version ----------------------------------------------------------

@pytest.mark.parametrize("spec,expected", [
    ("", "3.1.0"),
    (">=2.0", "3.1.0"),
    ("~=2.0", "2.3.3"),
    (">2.3.3,<3", None),
    (">=3.2", None),
])
def test_best_version(spec, expected):
    versions = ["2.0.0", "2.3.3", "3.1.0", "3.2.0rc1", "not-a-version"]
    assert best_version(versions, spec) == expected


def test_best_version_accepts_a_prerelease_when_it_is_the_only_match():
    assert best_version(["1.0.0", "2.0.0b1"], ">=2.0.0b1") == "2.0.0b1"


def test_plan_neither_pins_to_the_lower_bound_nor_invents_versions(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("flask>=2.0\nrequests\nghost\nslow\nnumpy==1.24.0\ndjango>=99\n", encoding="utf-8")

    def index(name):
        if name == "ghost":
            raise PackageNotFound(name)
        if name == "slow":
            raise IndexUnavailable("cannot reach pypi.org")
        return {"flask": ["2.0.0", "3.1.0"], "requests": ["2.32.3"], "django": ["5.0"]}[name]

    plan = DependencyAuditor.plan_requirements_fix(str(req), index=index)
    assert [c[2] for c in plan.changes] == ["flask==3.1.0", "requests==2.32.3"]
    reasons = {p: r for _, p, r in plan.unresolved}
    assert reasons["ghost"] == "not found on PyPI"
    assert "cannot reach" in reasons["slow"]
    assert "no published version" in reasons["django"]
    assert "1.0.0" not in "".join(plan.fixed)
    assert req.read_text(encoding="utf-8").startswith("flask>=2.0"), "planning writes nothing"


def test_without_network_nothing_changes(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests\n", encoding="utf-8")
    assert DependencyAuditor.resolve_package_version("requests") is None
    with pytest.warns(DeprecationWarning):
        assert DependencyAuditor.auto_fix_requirements_txt(str(req), "2.31.0")[1] == 0
    assert req.read_text(encoding="utf-8") == "requests\n"


# --- Manifests -------------------------------------------------------------------

def test_reading_manifests(tmp_path):
    (tmp_path / "requirements-dev.txt").write_text("flask==2.3.3\nrequests>=2\nuvicorn[standard]==0.30.1\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(json.dumps(
        {"dependencies": {"lodash": "4.17.20", "express": "^4.18.0"}, "devDependencies": {"jest": "=29.7.0"}}), encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {
        "": {"name": "app"}, "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/a/node_modules/@scope/b": {"version": "1.0.0"}}}), encoding="utf-8")
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "django"\nversion = "4.2.0"\n\n[[package]]\nname = "pyyaml"\nversion = "6.0.1"\n', encoding="utf-8")
    (tmp_path / "Pipfile.lock").write_text(json.dumps(
        {"default": {"requests": {"version": "==2.31.0"}}, "develop": {"pytest": {"version": "==8.0.0"}}}), encoding="utf-8")

    def read(name):
        deps, unpinned = vulns.read_manifest(str(tmp_path / name))
        return sorted((d.ecosystem, d.name, d.version) for d in deps), unpinned

    assert read("requirements-dev.txt") == ([("PyPI", "flask", "2.3.3"), ("PyPI", "uvicorn", "0.30.1")], 1)
    assert read("package.json") == ([("npm", "jest", "29.7.0"), ("npm", "lodash", "4.17.20")], 1)
    assert read("package-lock.json")[0] == [("npm", "@scope/b", "1.0.0"), ("npm", "lodash", "4.17.20")]
    assert read("poetry.lock")[0] == [("PyPI", "django", "4.2.0"), ("PyPI", "pyyaml", "6.0.1")]
    assert read("Pipfile.lock")[0] == [("PyPI", "pytest", "8.0.0"), ("PyPI", "requests", "2.31.0")]


# --- OSV responses ----------------------------------------------------------------

GHSA_ADVISORY = {
    "id": "GHSA-9wx4-h78v-vm56", "aliases": ["CVE-2024-35195"], "summary": "Session does not verify.",
    "database_specific": {"severity": "MODERATE"},
    "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                  "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}]}],
}
PYSEC_ADVISORY = {"id": "PYSEC-2024-1", "aliases": ["CVE-2024-35195"], "summary": "Duplicate"}
ADVISORY_WITHOUT_SEVERITY = {
    "id": "PYSEC-2099-9", "aliases": [], "summary": "Another one",
    "affected": [{"package": {"ecosystem": "PyPI", "name": "Requests"},
                  "ranges": [{"events": [{"fixed": "2.30.0"}, {"fixed": "2.33.1"}]}]}],
}


@pytest.fixture
def fake_osv(monkeypatch):
    """Replace the requests to OSV and record how many are made."""
    calls = []

    def post(url, payload, timeout):
        calls.append(url)
        if url == vulns.OSV_BATCH_URL:
            return {"results": [
                {"vulns": [{"id": "x"}]} if q["package"]["name"] == "requests" else {}
                for q in payload["queries"]
            ]}
        return {"vulns": [PYSEC_ADVISORY, GHSA_ADVISORY, ADVISORY_WITHOUT_SEVERITY]}

    monkeypatch.setattr(vulns, "_post_json", post)
    return calls


def test_query_osv_deduplicates_and_computes_the_fix(fake_osv):
    deps = [vulns.Dependency("PyPI", "requests", "2.31.0"), vulns.Dependency("PyPI", "flask", "3.1.0")]
    res = vulns.query_osv(deps)
    found = res[deps[0].key]
    assert [v.id for v in found] == ["GHSA-9wx4-h78v-vm56", "PYSEC-2099-9"], "one advisory per issue"
    assert found[0].display_id == "CVE-2024-35195"
    assert found[0].level == "MEDIUM" and found[1].level == "HIGH"
    assert found[0].fixed == "2.32.0" and found[1].fixed == "2.33.1"
    assert res[deps[1].key] == []
    assert len(fake_osv) == 2, "one batch for everything and one query for the affected package only"


def test_pipeline_stage(tmp_path, fake_osv, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nflask>=2\n", encoding="utf-8")

    stage, items = dependency_vulnerability_stage(str(tmp_path), check=True)
    assert stage["status"] == "fail" and stage["dependencies_unpinned"] == 1
    assert {i["rule_id"] for i in items} == {"VULN-GHSA-9wx4-h78v-vm56", "VULN-PYSEC-2099-9"}
    assert all(i["line"] == 1 for i in items)

    stage, items = dependency_vulnerability_stage(str(tmp_path))  # AGENTES_OFFLINE=1, set by conftest
    assert stage["status"] == "skipped" and items == []


def test_without_a_connection_the_stage_is_skipped_and_does_not_fail(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

    def down(url, payload, timeout):
        raise vulns.VulnDBUnavailable("cannot reach api.osv.dev")

    monkeypatch.setattr(vulns, "_post_json", down)
    report, code = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "rep"), prefer_bandit=False,
                                check_vulnerabilities=True)
    stage = next(s for s in report["stages"] if s["name"] == "dependency_vulns")
    assert stage["status"] == "skipped" and "api.osv.dev" in stage["summary"]
    assert code == 0


def test_pypi_drops_yanked_releases_and_those_incompatible_with_python(monkeypatch):
    from agentes.quality import package_index

    releases = {
        "1.0.0": [{"yanked": False, "requires_python": ">=3.8"}],
        "2.0.0": [{"yanked": False, "requires_python": ">=3.13"}],
        "2.1.0": [{"yanked": True, "requires_python": None}],
        "1.5.0": [{"yanked": False, "requires_python": None}],
        "0.9.0": [],
    }
    monkeypatch.setattr(package_index, "http_get_json", lambda url, timeout=10.0: {"releases": releases})
    assert sorted(package_index.pypi_versions("x", python_version="3.9.18")) == ["1.0.0", "1.5.0"]
    assert sorted(package_index.pypi_versions("x", python_version="3.13.1")) == ["1.0.0", "1.5.0", "2.0.0"]


# --- pyproject.toml, installed environments and constraints that block the fix ------

PYPROJECT = """
[project]
name = "my-app"
dependencies = ["Pillow>=10,<13", "requests==2.31.0", "rich"]

[project.optional-dependencies]
dev = ["pytest>=8", "my-app[extra]"]

[dependency-groups]
lint = ["ruff==0.6.0"]

[tool.poetry.dependencies]
python = "^3.9"
django = "4.2.0"
flask = "^2.0"
"""


def _venv(root, packages):
    env = root / ".venv"
    site = env / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (env / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    for name, version in packages:
        info = site / f"{name}-{version}.dist-info"
        info.mkdir()
        (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", encoding="utf-8")
    return env


def test_reading_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    data = vulns.read_manifest_data(str(tmp_path / "pyproject.toml"))
    assert sorted((d.name, d.version) for d in data.deps) == [("django", "4.2.0"), ("requests", "2.31.0"), ("ruff", "0.6.0")]
    assert data.unpinned == 4, "Pillow, rich, pytest and flask; my-app[extra] is the project itself"
    assert ("pillow", "<13,>=10", str(tmp_path / "pyproject.toml")) in data.constraints


def test_requirements_with_compound_ranges(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("flask>=2,<3  # web\n-e .[dev]\nrequests==2.31.0\n", encoding="utf-8")
    data = vulns.read_manifest_data(str(req))
    assert [(d.name, d.line) for d in data.deps] == [("requests", 3)]
    assert data.unpinned == 1 and data.constraints[0][:2] == ("flask", "<3,>=2")


def test_installed_environments(tmp_path):
    _venv(tmp_path, [("pillow", "12.3.0"), ("Requests", "2.32.3")])
    envs = vulns.find_environments(str(tmp_path))
    assert envs == [str(tmp_path / ".venv")]
    assert sorted((d.name, d.version) for d in vulns.installed_packages(envs[0])) == [("Requests", "2.32.3"), ("pillow", "12.3.0")]


def _osv_pillow(deps, timeout=15.0):
    out = {d.key: [] for d in deps}
    for d in deps:
        if d.name.lower() == "pillow" and d.version == "12.3.0":
            out[d.key] = [vulns.Vulnerability("GHSA-p", ["CVE-2026-1"], "Overflow", "CRITICAL", "13.0.0")]
    return out


def test_constraint_that_blocks_the_fix_and_installed_version(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = ["Pillow>=10,<13"]\n', encoding="utf-8")
    env = _venv(tmp_path, [("pillow", "12.3.0")])
    monkeypatch.setattr(vulns, "query_osv", _osv_pillow)

    res = vulns.scan([str(tmp_path / "pyproject.toml")], environments=[str(env)], root=str(tmp_path))
    assert not res.unchecked and res.installed == 1 and res.checked == 1
    msg = res.findings[0].message
    assert "installed in .venv" in msg and "Fixed in 13.0.0" in msg
    assert "'pillow<13,>=10' in pyproject.toml prevents installing" in msg
    assert res.blocked_fixes == [("pillow", "<13,>=10", str(tmp_path / "pyproject.toml"), "13.0.0")]


def test_with_nothing_checkable_it_does_not_report_ok(tmp_path, monkeypatch):
    """A project with ranges in pyproject and no .venv has nothing to check; reporting 'OK, 0 vulnerabilities' would mislead."""
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = ["rich>=13"]\n', encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("-e .[dev]\n", encoding="utf-8")
    monkeypatch.setattr(vulns, "query_osv", _osv_pillow)

    stage, items = dependency_vulnerability_stage(str(tmp_path), check=True)
    assert stage["status"] == "skipped" and "not checked" in stage["summary"] and items == []

    _venv(tmp_path, [("pillow", "12.3.0")])
    stage, items = dependency_vulnerability_stage(str(tmp_path), check=True)
    assert stage["status"] == "fail" and stage["environments"] == [".venv"] and len(items) == 1


def test_cli_vulns_warns_when_nothing_was_checked(tmp_path, monkeypatch, capsys):
    from agentes import cli

    monkeypatch.delenv("AGENTES_OFFLINE", raising=False)
    monkeypatch.setattr(vulns, "query_osv", _osv_pillow)
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = ["rich>=13"]\n', encoding="utf-8")
    assert cli.main(["vulns", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "unchecked"
    assert cli.main(["vulns", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "No dependency was checked" in out and "No known vulnerabilities" not in out


def test_an_exact_pin_is_not_a_blocking_constraint(tmp_path, monkeypatch):
    req = tmp_path / "requirements.txt"
    req.write_text("pillow==12.3.0\n", encoding="utf-8")
    monkeypatch.setattr(vulns, "query_osv", _osv_pillow)
    res = vulns.scan([str(req)], root=str(tmp_path))
    assert len(res.findings) == 1 and res.blocked_fixes == []
    assert "prevents" not in res.findings[0].message


# --- Manifest readers and query edge cases ---------------------------------------------

def test_package_lock_v1_with_nested_dependencies(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {
        "express": {"version": "4.18.2", "dependencies": {"qs": {"version": "6.11.0"}}},
        "bundled-dep": {"bundled": True},
    }}), encoding="utf-8")
    deps, unpinned = vulns.read_manifest(str(lock))
    assert sorted((d.name, d.version) for d in deps) == [("express", "4.18.2"), ("qs", "6.11.0")]
    assert unpinned == 0


def test_requirements_ignores_anything_that_is_not_a_requirement(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("# comment\n-r base.txt\nthis is not a requirement!!\nflask==2.3.3  # pinned\n\n", encoding="utf-8")
    deps, unpinned = vulns.read_manifest(str(req))
    assert [(d.name, d.version) for d in deps] == [("flask", "2.3.3")] and unpinned == 0


def test_unknown_manifest_and_missing_root(tmp_path):
    with pytest.raises(ValueError, match="Not a known dependency manifest"):
        vulns.read_manifest(str(tmp_path / "setup.cfg"))
    assert vulns.find_environments(str(tmp_path / "missing")) == []


def test_fixed_version_with_versions_that_are_not_pep440():
    dep = vulns.Dependency("PyPI", "package", "odd-1", "requirements.txt")
    vuln = {"affected": [
        {"package": {"ecosystem": "npm", "name": "package"}, "ranges": [{"events": [{"fixed": "9.0.0"}]}]},
        {"package": {"ecosystem": "PyPI", "name": "Package"}, "ranges": [{"events": [{"fixed": "2.0"}, {"fixed": "1.5"}]}]},
    ]}
    # When versions cannot be compared, the lowest fixed version is proposed, and never one from another ecosystem.
    assert vulns._fixed_version(vuln, dep) == "1.5"


def test_querying_osv_with_no_dependencies_or_no_connection(monkeypatch, closed_port):
    assert vulns.query_osv([]) == {}
    monkeypatch.setattr(vulns, "OSV_BATCH_URL", f"http://127.0.0.1:{closed_port}/querybatch")
    with pytest.raises(vulns.VulnDBUnavailable, match="cannot reach"):
        vulns.query_osv([vulns.Dependency("PyPI", "flask", "2.3.3", "r.txt")], timeout=2)


def test_blocking_constraint_only_with_a_pypi_fixed_version():
    dep = vulns.Dependency("PyPI", "flask", "2.3.3", "r.txt")
    constraints = [("flask", "this is not a specifier", "a.txt"), ("flask", "<3", "b.txt")]
    assert vulns._blocking_constraint(dep, "3.0.0", constraints) == ("flask", "<3", "b.txt")
    assert vulns._blocking_constraint(dep, None, constraints) is None
    npm = vulns.Dependency("npm", "flask", "2.3.3", "package.json")
    assert vulns._blocking_constraint(npm, "3.0.0", constraints) is None


def test_scan_reports_what_it_could_not_read(tmp_path, monkeypatch):
    bad = tmp_path / "package.json"
    bad.write_text("{not json", encoding="utf-8")
    env = tmp_path / ".venv"
    env.mkdir()
    (env / "pyvenv.cfg").write_text("home = /usr\n", encoding="utf-8")

    def permission_denied(path):
        raise OSError("permission denied")

    monkeypatch.setattr(vulns, "installed_packages", permission_denied)
    monkeypatch.setattr(vulns, "query_osv", lambda deps, timeout=15.0: {})
    result = vulns.scan([str(bad)], environments=[str(env)], root=str(tmp_path))
    errors = [f for f in result.findings if f.rule_id == "VULN-READ-ERROR"]
    assert {f.file for f in errors} == {str(bad), str(env)}
    assert all(f.level == "ERROR" for f in errors)


# --- DependencyAuditor: edge cases ------------------------------------------------------------

def test_requirement_lines_that_are_not_parsed():
    for line in ("", "# just a comment", "-e .", "--index-url https://x", "@@@ invalid"):
        assert DependencyAuditor._parse_requirement_line(line) is None


def test_resolving_a_version_with_and_without_an_index(monkeypatch):
    def index(name):
        if name == "missing":
            raise PackageNotFound(name)
        return ["1.0", "1.2", "2.0b1"]

    assert DependencyAuditor.resolve_package_version("x", index=index) == "1.2"
    assert DependencyAuditor.resolve_package_version("missing", index=index) is None
    assert DependencyAuditor.resolve_package_version("x", use_pypi=False) is None
    # With no index and network access, it queries PyPI with the given timeout.
    from agentes.quality import dependency_auditor
    monkeypatch.delenv("AGENTES_OFFLINE", raising=False)
    calls = []
    monkeypatch.setattr(dependency_auditor, "pypi_versions", lambda name, timeout: calls.append(timeout) or ["3.0"])
    assert DependencyAuditor.resolve_package_version("x", timeout=4.0) == "3.0" and calls == [4.0]


def test_auditing_a_missing_requirements_file_or_one_with_odd_lines(tmp_path):
    assert DependencyAuditor.audit_requirements_txt(str(tmp_path / "no.txt"))[0][1] == "INFO"
    req = tmp_path / "requirements.txt"
    req.write_text("-r base.txt\n@@@\nflask\n", encoding="utf-8")
    assert [pkg for pkg, _, _ in DependencyAuditor.audit_requirements_txt(str(req))] == ["flask"]
    plan = DependencyAuditor.plan_requirements_fix(str(req), index=lambda name: ["2.0"])
    assert [after for _, _, after in plan.changes] == ["flask==2.0"]


def test_auto_fix_without_a_file_without_network_or_with_default_version(tmp_path):
    assert DependencyAuditor.auto_fix_requirements_txt(str(tmp_path / "no.txt")) == (str(tmp_path / "no.txt"), 0)
    req = tmp_path / "requirements.txt"
    req.write_text("flask\n", encoding="utf-8")
    assert DependencyAuditor.auto_fix_requirements_txt(str(req), use_pypi=False) == (str(req), 0)
    with pytest.warns(DeprecationWarning, match="default_version has no effect"):
        DependencyAuditor.auto_fix_requirements_txt(str(req), "1.0", use_pypi=False)
    assert req.read_text(encoding="utf-8") == "flask\n"


@pytest.mark.parametrize("content, expected", [
    ({"dependencies": {"a": "^1.0.0", "b": "1.2.3"}, "devDependencies": {"c": "~2.0", "d": "*"}},
     {"a": "MEDIUM", "c": "MEDIUM", "d": "MEDIUM"}),
    ({"dependencies": {"a": "1.2.3"}}, {"ALL": "OK"}),
    ("{not json", {"PACKAGE.JSON": "ERROR"}),
])
def test_auditing_package_json(tmp_path, content, expected):
    path = tmp_path / "package.json"
    path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
    assert {pkg: level for pkg, level, _ in DependencyAuditor.audit_package_json(str(path))} == expected


def test_auditing_a_missing_package_json(tmp_path):
    assert DependencyAuditor.audit_package_json(str(tmp_path / "package.json"))[0][1] == "INFO"


def test_pyproject_dependencies_with_invalid_requirements(tmp_path):
    from agentes.quality.dependency_auditor import package_dependencies

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = ["flask>=2", "invalid!!"]\n',
                                             encoding="utf-8")
    assert package_dependencies(str(tmp_path)) == {"flask"}
