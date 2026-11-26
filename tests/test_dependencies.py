"""Tests de fix (versiones desde PyPI) y de la búsqueda de vulnerabilidades en OSV, sin red."""
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

# --- Elección de versión ---------------------------------------------------------

@pytest.mark.parametrize("spec,expected", [
    ("", "3.1.0"),
    (">=2.0", "3.1.0"),
    ("~=2.0", "2.3.3"),
    (">2.3.3,<3", None),
    (">=3.2", None),
])
def test_best_version(spec, expected):
    versiones = ["2.0.0", "2.3.3", "3.1.0", "3.2.0rc1", "no-es-version"]
    assert best_version(versiones, spec) == expected


def test_best_version_admite_prerelease_si_es_lo_unico_que_cumple():
    assert best_version(["1.0.0", "2.0.0b1"], ">=2.0.0b1") == "2.0.0b1"


def test_plan_no_fija_al_limite_inferior_ni_inventa(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("flask>=2.0\nrequests\nfantasma\nlento\nnumpy==1.24.0\ndjango>=99\n", encoding="utf-8")

    def indice(name):
        if name == "fantasma":
            raise PackageNotFound(name)
        if name == "lento":
            raise IndexUnavailable("sin conexión con pypi.org")
        return {"flask": ["2.0.0", "3.1.0"], "requests": ["2.32.3"], "django": ["5.0"]}[name]

    plan = DependencyAuditor.plan_requirements_fix(str(req), index=indice)
    assert [c[2] for c in plan.changes] == ["flask==3.1.0", "requests==2.32.3"]
    motivos = {p: r for _, p, r in plan.unresolved}
    assert motivos["fantasma"] == "no existe en PyPI"
    assert "sin conexión" in motivos["lento"]
    assert "ninguna versión" in motivos["django"]
    assert "1.0.0" not in "".join(plan.fixed)
    assert req.read_text(encoding="utf-8").startswith("flask>=2.0"), "plan no escribe nada"


def test_sin_red_no_cambia_nada(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests\n", encoding="utf-8")
    assert DependencyAuditor.resolve_package_version("requests") is None
    with pytest.warns(DeprecationWarning):
        assert DependencyAuditor.auto_fix_requirements_txt(str(req), "2.31.0")[1] == 0
    assert req.read_text(encoding="utf-8") == "requests\n"


# --- Manifiestos -----------------------------------------------------------------

def test_lectura_de_manifiestos(tmp_path):
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

    def leer(nombre):
        deps, sueltas = vulns.read_manifest(str(tmp_path / nombre))
        return sorted((d.ecosystem, d.name, d.version) for d in deps), sueltas

    assert leer("requirements-dev.txt") == ([("PyPI", "flask", "2.3.3"), ("PyPI", "uvicorn", "0.30.1")], 1)
    assert leer("package.json") == ([("npm", "jest", "29.7.0"), ("npm", "lodash", "4.17.20")], 1)
    assert leer("package-lock.json")[0] == [("npm", "@scope/b", "1.0.0"), ("npm", "lodash", "4.17.20")]
    assert leer("poetry.lock")[0] == [("PyPI", "django", "4.2.0"), ("PyPI", "pyyaml", "6.0.1")]
    assert leer("Pipfile.lock")[0] == [("PyPI", "pytest", "8.0.0"), ("PyPI", "requests", "2.31.0")]


# --- Respuestas de OSV ------------------------------------------------------------

AVISO_GHSA = {
    "id": "GHSA-9wx4-h78v-vm56", "aliases": ["CVE-2024-35195"], "summary": "Session no verifica.",
    "database_specific": {"severity": "MODERATE"},
    "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                  "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}]}],
}
AVISO_PYSEC = {"id": "PYSEC-2024-1", "aliases": ["CVE-2024-35195"], "summary": "Duplicado"}
AVISO_SIN_SEVERIDAD = {
    "id": "PYSEC-2099-9", "aliases": [], "summary": "Otro",
    "affected": [{"package": {"ecosystem": "PyPI", "name": "Requests"},
                  "ranges": [{"events": [{"fixed": "2.30.0"}, {"fixed": "2.33.1"}]}]}],
}


@pytest.fixture
def osv_falso(monkeypatch):
    """Sustituye las peticiones a OSV y registra cuántas se hacen."""
    llamadas = []

    def post(url, payload, timeout):
        llamadas.append(url)
        if url == vulns.OSV_BATCH_URL:
            return {"results": [
                {"vulns": [{"id": "x"}]} if q["package"]["name"] == "requests" else {}
                for q in payload["queries"]
            ]}
        return {"vulns": [AVISO_PYSEC, AVISO_GHSA, AVISO_SIN_SEVERIDAD]}

    monkeypatch.setattr(vulns, "_post_json", post)
    return llamadas


def test_query_osv_deduplica_y_calcula_la_correccion(osv_falso):
    deps = [vulns.Dependency("PyPI", "requests", "2.31.0"), vulns.Dependency("PyPI", "flask", "3.1.0")]
    res = vulns.query_osv(deps)
    encontrados = res[deps[0].key]
    assert [v.id for v in encontrados] == ["GHSA-9wx4-h78v-vm56", "PYSEC-2099-9"], "un aviso por fallo"
    assert encontrados[0].display_id == "CVE-2024-35195"
    assert encontrados[0].level == "MEDIO" and encontrados[1].level == "ALTO"
    assert encontrados[0].fixed == "2.32.0" and encontrados[1].fixed == "2.33.1"
    assert res[deps[1].key] == []
    assert len(osv_falso) == 2, "un lote para todas y una consulta solo para la afectada"


def test_etapa_del_pipeline(tmp_path, osv_falso, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nflask>=2\n", encoding="utf-8")

    stage, items = dependency_vulnerability_stage(str(tmp_path), check=True)
    assert stage["status"] == "fail" and stage["dependencies_unpinned"] == 1
    assert {i["rule_id"] for i in items} == {"VULN-GHSA-9wx4-h78v-vm56", "VULN-PYSEC-2099-9"}
    assert all(i["line"] == 1 for i in items)

    stage, items = dependency_vulnerability_stage(str(tmp_path))  # AGENTES_OFFLINE=1 por conftest
    assert stage["status"] == "skipped" and items == []


def test_sin_conexion_la_etapa_se_omite_y_no_falla(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

    def caido(url, payload, timeout):
        raise vulns.VulnDBUnavailable("sin conexión con api.osv.dev")

    monkeypatch.setattr(vulns, "_post_json", caido)
    report, code = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "rep"), prefer_bandit=False,
                                check_vulnerabilities=True)
    etapa = next(s for s in report["stages"] if s["name"] == "dependency_vulns")
    assert etapa["status"] == "skipped" and "api.osv.dev" in etapa["summary"]
    assert code == 0


def test_pypi_descarta_versiones_retiradas_o_incompatibles_con_python(monkeypatch):
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


# --- pyproject.toml, entornos instalados y restricciones que bloquean la corrección ----

PYPROJECT = """
[project]
name = "mi-app"
dependencies = ["Pillow>=10,<13", "requests==2.31.0", "rich"]

[project.optional-dependencies]
dev = ["pytest>=8", "mi-app[extra]"]

[dependency-groups]
lint = ["ruff==0.6.0"]

[tool.poetry.dependencies]
python = "^3.9"
django = "4.2.0"
flask = "^2.0"
"""


def _venv(root, paquetes):
    env = root / ".venv"
    site = env / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (env / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    for nombre, version in paquetes:
        info = site / f"{nombre}-{version}.dist-info"
        info.mkdir()
        (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {nombre}\nVersion: {version}\n", encoding="utf-8")
    return env


def test_lectura_de_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    data = vulns.read_manifest_data(str(tmp_path / "pyproject.toml"))
    assert sorted((d.name, d.version) for d in data.deps) == [("django", "4.2.0"), ("requests", "2.31.0"), ("ruff", "0.6.0")]
    assert data.unpinned == 4, "Pillow, rich, pytest y flask; mi-app[extra] es el propio proyecto"
    assert ("pillow", "<13,>=10", str(tmp_path / "pyproject.toml")) in data.constraints


def test_requirements_con_rangos_compuestos(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("flask>=2,<3  # web\n-e .[dev]\nrequests==2.31.0\n", encoding="utf-8")
    data = vulns.read_manifest_data(str(req))
    assert [(d.name, d.line) for d in data.deps] == [("requests", 3)]
    assert data.unpinned == 1 and data.constraints[0][:2] == ("flask", "<3,>=2")


def test_entornos_instalados(tmp_path):
    _venv(tmp_path, [("pillow", "12.3.0"), ("Requests", "2.32.3")])
    envs = vulns.find_environments(str(tmp_path))
    assert envs == [str(tmp_path / ".venv")]
    assert sorted((d.name, d.version) for d in vulns.installed_packages(envs[0])) == [("Requests", "2.32.3"), ("pillow", "12.3.0")]


def _osv_pillow(deps, timeout=15.0):
    out = {d.key: [] for d in deps}
    for d in deps:
        if d.name.lower() == "pillow" and d.version == "12.3.0":
            out[d.key] = [vulns.Vulnerability("GHSA-p", ["CVE-2026-1"], "Desbordamiento", "CRITICO", "13.0.0")]
    return out


def test_restriccion_que_impide_corregir_y_version_instalada(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = ["Pillow>=10,<13"]\n', encoding="utf-8")
    env = _venv(tmp_path, [("pillow", "12.3.0")])
    monkeypatch.setattr(vulns, "query_osv", _osv_pillow)

    res = vulns.scan([str(tmp_path / "pyproject.toml")], environments=[str(env)], root=str(tmp_path))
    assert not res.unchecked and res.installed == 1 and res.checked == 1
    msg = res.findings[0].message
    assert "instalado en .venv" in msg and "Corregido en 13.0.0" in msg
    assert "'pillow<13,>=10' de pyproject.toml impide instalar" in msg
    assert res.blocked_fixes == [("pillow", "<13,>=10", str(tmp_path / "pyproject.toml"), "13.0.0")]


def test_sin_nada_comprobable_no_dice_ok(tmp_path, monkeypatch):
    """Proyecto con rangos en pyproject y sin .venv: no hay nada que comprobar, y decir 'OK, 0 vulnerabilidades' sería engañoso."""
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = ["rich>=13"]\n', encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("-e .[dev]\n", encoding="utf-8")
    monkeypatch.setattr(vulns, "query_osv", _osv_pillow)

    stage, items = dependency_vulnerability_stage(str(tmp_path), check=True)
    assert stage["status"] == "skipped" and "sin comprobar" in stage["summary"] and items == []

    _venv(tmp_path, [("pillow", "12.3.0")])
    stage, items = dependency_vulnerability_stage(str(tmp_path), check=True)
    assert stage["status"] == "fail" and stage["environments"] == [".venv"] and len(items) == 1


def test_cli_vulns_sin_comprobar_avisa(tmp_path, monkeypatch, capsys):
    from agentes import cli

    monkeypatch.delenv("AGENTES_OFFLINE", raising=False)
    monkeypatch.setattr(vulns, "query_osv", _osv_pillow)
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = ["rich>=13"]\n', encoding="utf-8")
    assert cli.main(["vulns", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "unchecked"
    assert cli.main(["vulns", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "No se ha comprobado ninguna dependencia" in out and "Ninguna vulnerabilidad conocida" not in out


def test_un_pin_exacto_no_es_una_restriccion_que_bloquea(tmp_path, monkeypatch):
    req = tmp_path / "requirements.txt"
    req.write_text("pillow==12.3.0\n", encoding="utf-8")
    monkeypatch.setattr(vulns, "query_osv", _osv_pillow)
    res = vulns.scan([str(req)], root=str(tmp_path))
    assert len(res.findings) == 1 and res.blocked_fixes == []
    assert "impide" not in res.findings[0].message


# --- Lectores de manifiestos y casos límite de la consulta --------------------------------

def test_package_lock_v1_con_dependencias_anidadas(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {
        "express": {"version": "4.18.2", "dependencies": {"qs": {"version": "6.11.0"}}},
        "enlazado": {"bundled": True},
    }}), encoding="utf-8")
    deps, unpinned = vulns.read_manifest(str(lock))
    assert sorted((d.name, d.version) for d in deps) == [("express", "4.18.2"), ("qs", "6.11.0")]
    assert unpinned == 0


def test_requirements_ignora_lo_que_no_es_un_requisito(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("# comentario\n-r base.txt\nesto no es un requisito!!\nflask==2.3.3  # fijado\n\n", encoding="utf-8")
    deps, unpinned = vulns.read_manifest(str(req))
    assert [(d.name, d.version) for d in deps] == [("flask", "2.3.3")] and unpinned == 0


def test_manifiesto_desconocido_y_raiz_inexistente(tmp_path):
    with pytest.raises(ValueError, match="No es un manifiesto de dependencias conocido"):
        vulns.read_manifest(str(tmp_path / "setup.cfg"))
    assert vulns.find_environments(str(tmp_path / "no-existe")) == []


def test_version_corregida_con_versiones_que_no_son_pep440():
    dep = vulns.Dependency("PyPI", "paquete", "raro-1", "requirements.txt")
    vuln = {"affected": [
        {"package": {"ecosystem": "npm", "name": "paquete"}, "ranges": [{"events": [{"fixed": "9.0.0"}]}]},
        {"package": {"ecosystem": "PyPI", "name": "Paquete"}, "ranges": [{"events": [{"fixed": "2.0"}, {"fixed": "1.5"}]}]},
    ]}
    # Sin poder comparar versiones se propone la menor corregida, y nunca la de otro ecosistema.
    assert vulns._fixed_version(vuln, dep) == "1.5"


def test_consultar_osv_sin_dependencias_o_sin_conexion(monkeypatch, closed_port):
    assert vulns.query_osv([]) == {}
    monkeypatch.setattr(vulns, "OSV_BATCH_URL", f"http://127.0.0.1:{closed_port}/querybatch")
    with pytest.raises(vulns.VulnDBUnavailable, match="sin conexión"):
        vulns.query_osv([vulns.Dependency("PyPI", "flask", "2.3.3", "r.txt")], timeout=2)


def test_restriccion_que_bloquea_solo_con_version_corregida_de_pypi():
    dep = vulns.Dependency("PyPI", "flask", "2.3.3", "r.txt")
    constraints = [("flask", "esto no es un especificador", "a.txt"), ("flask", "<3", "b.txt")]
    assert vulns._blocking_constraint(dep, "3.0.0", constraints) == ("flask", "<3", "b.txt")
    assert vulns._blocking_constraint(dep, None, constraints) is None
    npm = vulns.Dependency("npm", "flask", "2.3.3", "package.json")
    assert vulns._blocking_constraint(npm, "3.0.0", constraints) is None


def test_scan_informa_de_lo_que_no_pudo_leer(tmp_path, monkeypatch):
    bad = tmp_path / "package.json"
    bad.write_text("{no es json", encoding="utf-8")
    env = tmp_path / ".venv"
    env.mkdir()
    (env / "pyvenv.cfg").write_text("home = /usr\n", encoding="utf-8")

    def sin_permiso(path):
        raise OSError("permiso denegado")

    monkeypatch.setattr(vulns, "installed_packages", sin_permiso)
    monkeypatch.setattr(vulns, "query_osv", lambda deps, timeout=15.0: {})
    result = vulns.scan([str(bad)], environments=[str(env)], root=str(tmp_path))
    errors = [f for f in result.findings if f.rule_id == "VULN-READ-ERROR"]
    assert {f.file for f in errors} == {str(bad), str(env)}
    assert all(f.level == "ERROR" for f in errors)


# --- DependencyAuditor: casos límite ----------------------------------------------------------

def test_requisitos_que_no_se_analizan():
    for line in ("", "# solo comentario", "-e .", "--index-url https://x", "@@@ no válido"):
        assert DependencyAuditor._parse_requirement_line(line) is None


def test_resolver_version_con_y_sin_indice(monkeypatch):
    def index(name):
        if name == "falta":
            raise PackageNotFound(name)
        return ["1.0", "1.2", "2.0b1"]

    assert DependencyAuditor.resolve_package_version("x", index=index) == "1.2"
    assert DependencyAuditor.resolve_package_version("falta", index=index) is None
    assert DependencyAuditor.resolve_package_version("x", use_pypi=False) is None
    # Sin índice y con red, consulta PyPI con el timeout indicado.
    from agentes.quality import dependency_auditor
    monkeypatch.delenv("AGENTES_OFFLINE", raising=False)
    calls = []
    monkeypatch.setattr(dependency_auditor, "pypi_versions", lambda name, timeout: calls.append(timeout) or ["3.0"])
    assert DependencyAuditor.resolve_package_version("x", timeout=4.0) == "3.0" and calls == [4.0]


def test_auditar_requirements_inexistente_o_con_lineas_raras(tmp_path):
    assert DependencyAuditor.audit_requirements_txt(str(tmp_path / "no.txt"))[0][1] == "INFORMACION"
    req = tmp_path / "requirements.txt"
    req.write_text("-r base.txt\n@@@\nflask\n", encoding="utf-8")
    assert [pkg for pkg, _, _ in DependencyAuditor.audit_requirements_txt(str(req))] == ["flask"]
    plan = DependencyAuditor.plan_requirements_fix(str(req), index=lambda name: ["2.0"])
    assert [after for _, _, after in plan.changes] == ["flask==2.0"]


def test_auto_fix_sin_archivo_sin_red_o_con_default_version(tmp_path):
    assert DependencyAuditor.auto_fix_requirements_txt(str(tmp_path / "no.txt")) == (str(tmp_path / "no.txt"), 0)
    req = tmp_path / "requirements.txt"
    req.write_text("flask\n", encoding="utf-8")
    assert DependencyAuditor.auto_fix_requirements_txt(str(req), use_pypi=False) == (str(req), 0)
    with pytest.warns(DeprecationWarning, match="default_version ya no tiene efecto"):
        DependencyAuditor.auto_fix_requirements_txt(str(req), "1.0", use_pypi=False)
    assert req.read_text(encoding="utf-8") == "flask\n"


@pytest.mark.parametrize("contenido, esperado", [
    ({"dependencies": {"a": "^1.0.0", "b": "1.2.3"}, "devDependencies": {"c": "~2.0", "d": "*"}},
     {"a": "MEDIO", "c": "MEDIO", "d": "MEDIO"}),
    ({"dependencies": {"a": "1.2.3"}}, {"TODAS": "OK"}),
    ("{no es json", {"PACKAGE.JSON": "ERROR"}),
])
def test_auditar_package_json(tmp_path, contenido, esperado):
    path = tmp_path / "package.json"
    path.write_text(contenido if isinstance(contenido, str) else json.dumps(contenido), encoding="utf-8")
    assert {pkg: level for pkg, level, _ in DependencyAuditor.audit_package_json(str(path))} == esperado


def test_auditar_package_json_inexistente(tmp_path):
    assert DependencyAuditor.audit_package_json(str(tmp_path / "package.json"))[0][1] == "INFORMACION"


def test_dependencias_del_pyproject_con_requisitos_invalidos(tmp_path):
    from agentes.quality.dependency_auditor import package_dependencies

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = ["flask>=2", "no válido!!"]\n',
                                             encoding="utf-8")
    assert package_dependencies(str(tmp_path)) == {"flask"}
