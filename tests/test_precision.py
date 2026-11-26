"""Precisión con proyectos reales: sin duplicados entre motores, severidad calibrada y sin APIs inventadas."""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentes.common import audits  # noqa: E402
from agentes.common.findings import Finding  # noqa: E402
from agentes.common.orchestrator import run_pipeline  # noqa: E402
from agentes.docs.openapi_generator import OpenAPIGenerator  # noqa: E402

CODIGO = '''import hashlib


def fingerprint(data: bytes) -> str:
    """Clave de caché, no un uso de seguridad."""
    return hashlib.md5(data).hexdigest()


def get_provider():
    """Helper de configuración: no es un endpoint."""
    return "x"


def carga():
    """Mejor esfuerzo."""
    try:
        return int("x")
    except Exception:
        pass
'''


def test_except_pass_sale_una_vez_y_como_medio(tmp_path):
    (tmp_path / "app.py").write_text(CODIGO, encoding="utf-8")
    report, code = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "rep"), prefer_bandit=False)
    linea = CODIGO.splitlines().index("    except Exception:") + 1
    en_linea = [f for f in report["findings"] if f["line"] == linea]
    temas = [audits.topic(Finding.from_dict(f)) for f in en_linea]
    assert temas.count("exception-swallow") == 1, en_linea
    assert all(f["level"] != "ALTO" for f in en_linea)
    hashes = [f for f in report["findings"] if "md5" in f["message"].lower()]
    assert hashes and all(f["level"] == "MEDIO" for f in hashes)
    assert "usedforsecurity=False" in hashes[0]["message"]
    assert code == 0, "ninguno de los dos es bloqueante"


def test_fusion_de_motores_en_la_misma_linea():
    grupo = [
        Finding("a.py", 7, "BAJO", "[bandit] Try, Except, Pass detected.", "SAST-BAJO"),
        Finding("a.py", 7, "ALTO", "Uso de 'except Exception: pass' que silencia errores.", "SAST-ALTO"),
        Finding("a.py", 9, "CRITICO", "[bandit] Use of weak MD5 hash for security. Consider usedforsecurity=False", "SAST-CRITICO"),
        Finding("a.py", 9, "MEDIO", "Uso de hash criptográfico débil 'hashlib.md5()' (usa SHA-256 o superior).", "SAST-MEDIO"),
        Finding("a.py", 11, "CRITICO", "Uso de función de riesgo dinámico 'eval()'.", "SAST-CRITICO"),
    ]
    res = audits.merge_duplicates(grupo)
    assert len(res) == 3
    por_linea = {f.line: f for f in res}
    assert por_linea[7].level == "MEDIO" and "Detectado también por: bandit" in por_linea[7].message
    assert por_linea[9].level == "MEDIO" and por_linea[9].rule_id == "SAST-MEDIO"
    assert por_linea[11].level == "CRITICO", "eval no se rebaja"


def test_solid_no_repite_lo_del_analisis_estatico():
    sast = [Finding("a.py", 7, "MEDIO", "Uso de 'except Exception: pass' que silencia errores.", "SAST-MEDIO").to_dict()]
    solid = [
        Finding("a.py", 7, "ALTO", "[EXCEPTION-HYGIENE] Bloque 'except' silencia la excepción con 'pass'.", "SOLID-EXCEPTION-HYGIENE").to_dict(),
        Finding("a.py", 30, "ALTO", "[EXCEPTION-HYGIENE] Bloque 'except' silencia la excepción con 'pass'.", "SOLID-EXCEPTION-HYGIENE").to_dict(),
    ]
    res = audits.drop_covered(solid, sast)
    assert [f["line"] for f in res] == [30]
    assert res[0]["level"] == "MEDIO", "también se calibra el que queda"


def test_openapi_solo_con_framework_web(tmp_path):
    (tmp_path / "app.py").write_text(CODIGO, encoding="utf-8")
    report, _ = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "rep"), prefer_bandit=False)
    docs = next(s for s in report["stages"] if s["name"] == "documentation")
    assert docs["status"] == "skipped" and "framework web" in docs["summary"]
    assert not (tmp_path / "rep" / "openapi.json").exists(), "no se inventa una API"

    (tmp_path / "web.py").write_text(
        'from flask import Flask\napp = Flask(__name__)\n\n@app.route("/items", methods=["POST"])\ndef crear():\n    return {}\n',
        encoding="utf-8",
    )
    report, _ = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "rep"), prefer_bandit=False)
    docs = next(s for s in report["stages"] if s["name"] == "documentation")
    assert docs["status"] == "ok" and docs["frameworks"] == ["flask"]
    spec = json.loads((tmp_path / "rep" / "openapi.json").read_text(encoding="utf-8"))
    assert list(spec["paths"]) == ["/items"], "get_provider no es una ruta"


def test_sin_rutas_no_se_inventa_health(tmp_path):
    src = tmp_path / "nada.py"
    src.write_text("def suma(a, b):\n    return a + b\n", encoding="utf-8")
    assert OpenAPIGenerator.generate_openapi_spec(str(src))["paths"] == {}


def test_cli_openapi_por_convencion_solo_si_se_pide(tmp_path, capsys):
    from agentes import cli

    src = tmp_path / "api.py"
    src.write_text("def get_users():\n    return []\n", encoding="utf-8")
    assert cli.main(["generate", "openapi", "--source", str(src), "-o", str(tmp_path / "a.json")]) == 0
    assert "--naming-convention" in capsys.readouterr().out
    assert json.loads((tmp_path / "a.json").read_text(encoding="utf-8"))["paths"] == {}
    assert cli.main(["generate", "openapi", "--source", str(src), "-o", str(tmp_path / "b.json"), "--naming-convention"]) == 0
    assert "/users" in json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))["paths"]


# --- Bandit, plantillas .env y rutas mostradas -------------------------------------

def test_bandit_se_busca_junto_al_interprete(monkeypatch):
    from agentes.quality import static_checker as sc

    monkeypatch.setattr(sc.importlib.util, "find_spec", lambda name: object() if name == "bandit" else None)
    monkeypatch.setattr(sc.shutil, "which", lambda name: None)
    assert sc.StaticCodeAnalyzer.bandit_command() == [sys.executable, "-m", "bandit"], "sin depender del PATH"

    monkeypatch.setattr(sc.importlib.util, "find_spec", lambda name: None)
    monkeypatch.setattr(sc.shutil, "which", lambda name: "/opt/bin/bandit")
    assert sc.StaticCodeAnalyzer.bandit_command() == ["/opt/bin/bandit"]

    monkeypatch.setattr(sc.shutil, "which", lambda name: None)
    assert sc.StaticCodeAnalyzer.bandit_command() is None


def test_sin_bandit_el_resumen_lo_dice(tmp_path, monkeypatch):
    from agentes.quality import static_checker as sc

    monkeypatch.setattr(sc.StaticCodeAnalyzer, "bandit_command", staticmethod(lambda: None))
    (tmp_path / "a.py").write_text("X = 1\n", encoding="utf-8")
    report, _ = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "rep"), prefer_bandit=True)
    sast = next(s for s in report["stages"] if s["name"] == "quality_sast")
    assert sast["engine"] == "ast" and "sin Bandit" in sast["summary"]
    report, _ = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "rep"), prefer_bandit=False)
    assert "sin Bandit" not in next(s for s in report["stages"] if s["name"] == "quality_sast")["summary"]


def test_plantillas_env_y_valores_vacios(tmp_path):
    plantilla = tmp_path / ".env.example"
    plantilla.write_text("API_KEY=\nSECRET_KEY=changeme\nDEBUG=true\n", encoding="utf-8")
    hallazgos = audits.audit_env(str(plantilla))
    assert [f.level for f in hallazgos] == ["BAJO"] and "[DEBUG]" in hallazgos[0].message

    real = tmp_path / ".env"
    real.write_text("API_KEY=\nSECRET_KEY=changeme\nTOKEN=abc\n", encoding="utf-8")
    mensajes = " ".join(f.message for f in audits.audit_env(str(real)))
    assert "API_KEY" not in mensajes, "un valor vacío está sin definir, no es una clave corta"
    assert "SECRET_KEY" in mensajes and "TOKEN" in mensajes


def test_rutas_relativas_al_proyecto_analizado(tmp_path, capsys, monkeypatch):
    from agentes import cli

    lejos = tmp_path / "a" / "b" / "c" / "d"
    lejos.mkdir(parents=True)
    proyecto = tmp_path / "proyecto"
    (proyecto / "src").mkdir(parents=True)
    (proyecto / "src" / "mod.py").write_text("def f():\n    try:\n        return 1\n    except Exception:\n        pass\n", encoding="utf-8")
    monkeypatch.chdir(lejos)
    cli.main(["analyze", str(proyecto), "-o", str(tmp_path / "rep"), "--no-bandit"])
    out = capsys.readouterr().out
    assert "src/mod.py:4" in out.replace(os.sep, "/")
    assert str(proyecto / "src" / "mod.py") not in out


# --- Umbral de ramas, open() cerrado en finally y urlopen de urllib -----------------

def _sast(tmp_path, code):
    from agentes.quality.static_checker import StaticCodeAnalyzer
    src = tmp_path / "mod.py"
    src.write_text(code, encoding="utf-8")
    return [msg for _, _, msg in StaticCodeAnalyzer.analyze_python_file(str(src), prefer_bandit=False)]


def _ramas(n):
    cuerpo = "".join(f"    {'if' if i == 0 else 'elif'} x == {i}:\n        return {i}\n" for i in range(n))
    return f"def f(x):\n    \"\"\"Doc.\"\"\"\n{cuerpo}    return -1\n"


def test_ocp_como_ruff_y_pylint_permite_hasta_12_ramas(tmp_path):
    from agentes.refactor.solid_checker import SOLIDChecker
    src = tmp_path / "ramas.py"
    src.write_text(_ramas(12), encoding="utf-8")
    assert not any(p == "OCP" for _, p, _, _ in SOLIDChecker.audit_file(str(src)))
    src.write_text(_ramas(13), encoding="utf-8")
    ocp = [msg for _, p, _, msg in SOLIDChecker.audit_file(str(src)) if p == "OCP"]
    assert len(ocp) == 1 and "13 bifurcaciones" in ocp[0] and "máximo recomendado: 12" in ocp[0]


ABIERTO = "Llamada a 'open()' fuera de un context manager"


def test_open_cerrado_en_finally_no_es_una_fuga(tmp_path):
    codigo = '''
def informe(ruta):
    """Doc."""
    report = None
    if ruta:
        report = open(ruta, "w", encoding="utf-8")
    try:
        if report:
            report.write("x")
    finally:
        if report:
            report.close()
'''
    assert not any(ABIERTO in m for m in _sast(tmp_path, codigo))


def test_open_cerrado_en_todos_los_except_y_en_else(tmp_path):
    codigo = '''
def escribir(tmp, destino):
    """Doc."""
    handle = open(tmp, "wb")
    try:
        handle.write(b"x")
    except BaseException:
        handle.close()
        raise
    else:
        handle.close()
'''
    assert not any(ABIERTO in m for m in _sast(tmp_path, codigo))


def test_open_dentro_de_exitstack(tmp_path):
    codigo = '''
import contextlib


def varios(rutas):
    """Doc."""
    with contextlib.ExitStack() as stack:
        return [stack.enter_context(open(r)) for r in rutas]
'''
    assert not any(ABIERTO in m for m in _sast(tmp_path, codigo))


def test_open_sin_cierre_garantizado_sigue_avisando(tmp_path):
    sin_cierre = 'def f(r):\n    """Doc."""\n    h = open(r)\n    return h.read()\n'
    solo_en_except = '''
def g(r):
    """Doc."""
    h = open(r)
    try:
        return h.read()
    except OSError:
        h.close()
        raise
'''
    assert any(ABIERTO in m for m in _sast(tmp_path, sin_cierre))
    assert any(ABIERTO in m for m in _sast(tmp_path, solo_en_except)), "sin else ni finally, el camino normal no cierra"


URLOPEN = "Llamada a 'urlopen()' sin 'timeout'"


def test_urlopen_de_otros_objetos_no_es_el_de_urllib(tmp_path):
    codigo = '''
import yt_dlp


def bajar(url):
    """Doc."""
    with yt_dlp.YoutubeDL({}) as ydl:
        with ydl.urlopen(url) as response:
            return response.read()


def urlopen(x):
    """Una función propia con el mismo nombre."""
    return x


def usar():
    """Doc."""
    return urlopen(1)
'''
    assert not any(URLOPEN in m for m in _sast(tmp_path, codigo))


def test_urlopen_de_urllib_se_detecta_importe_como_importe(tmp_path):
    formas = {
        "import urllib.request\nurllib.request.urlopen(u)": True,
        "import urllib.request as ur\nur.urlopen(u)": True,
        "from urllib import request\nrequest.urlopen(u)": True,
        "from urllib.request import urlopen\nurlopen(u)": True,
        "from urllib.request import urlopen as abrir\nabrir(u)": True,
        "from urllib.request import *\nurlopen(u)": True,
        "from urllib.request import urlopen\nurlopen(u, timeout=5)": False,
        "import urllib.request\nurllib.request.urlopen(u, None, 5)": False,
    }
    for codigo, avisa in formas.items():
        hallazgos = _sast(tmp_path, f"u = 'https://x'\n{codigo}\n")
        assert any(URLOPEN in m for m in hallazgos) is avisa, codigo


# --- Rendimiento: pop(0)/insert(0) solo en bucles y re.compile que no cambia ----------

def _perf(tmp_path, code):
    from agentes.refactor.code_metrics import CodeMetricsCalculator
    src = tmp_path / "perf.py"
    src.write_text(code, encoding="utf-8")
    return [msg for _, _, _, msg in CodeMetricsCalculator.audit_performance(str(src))]


def test_pop_e_insert_sueltos_no_son_un_cuello_de_botella(tmp_path):
    codigo = '''
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
for extra in ("a", "b"):
    sys.path.insert(0, extra)


def guion(respuestas):
    """Un doble de getpass: cada llamada entrega la siguiente respuesta."""
    pendientes = list(respuestas)

    def _prompt(label=""):
        return pendientes.pop(0)

    return _prompt


class Lento:
    def __init__(self, respuestas):
        self.respuestas = list(respuestas)

    def preguntar(self):
        if self.respuestas:
            return self.respuestas.pop(0)
        return None


def avisos(lista, aviso):
    lista.insert(0, aviso)
    return lista
'''
    assert _perf(tmp_path, codigo) == []


def test_pop_e_insert_en_bucle_siguen_avisando(tmp_path):
    codigo = '''
def anchura(raiz):
    cola = [raiz]
    while cola:
        nodo = cola.pop(0)
        cola.extend(nodo.hijos)


def invertir(xs):
    out = []
    for x in xs:
        out.insert(0, x)
    return out
'''
    msgs = _perf(tmp_path, codigo)
    assert sum(".pop(0)" in m and "bucle" in m for m in msgs) == 1
    assert sum(".insert(0" in m and "bucle" in m for m in msgs) == 1


def test_re_compile_de_un_patron_que_cambia_en_cada_vuelta(tmp_path):
    codigo = '''
import re


def compilar(palabras, use_regex, flags):
    patrones = [palabras] if use_regex else [p.strip() for p in palabras.split(",")]
    compilados = []
    for pat in patrones:
        try:
            compilados.append(re.compile(pat if use_regex else re.escape(pat), flags))
        except re.error:
            return None
    return compilados


def por_indice(patrones):
    for i, _ in enumerate(patrones):
        actual = patrones[i]
        yield re.compile(actual)


def de_una_funcion(fuente):
    while True:
        yield re.compile(fuente())
'''
    assert not any("re.compile" in m for m in _perf(tmp_path, codigo))


def test_re_compile_invariante_sigue_avisando(tmp_path):
    codigo = '''
import re

PATRON = r"\\d+"


def literal(lineas):
    for linea in lineas:
        if re.compile(r"\\s+").match(linea):
            yield linea


def constante(lineas):
    for linea in lineas:
        yield re.compile(PATRON, re.I).search(linea)


def solo_cambia_fuera(patrones, lineas):
    for pat in patrones:
        for linea in lineas:
            yield re.compile(re.escape(pat)).search(linea)
'''
    assert sum("re.compile" in m for m in _perf(tmp_path, codigo)) == 3


def test_in_sobre_tupla_o_lista_corta_de_constantes_no_avisa(tmp_path):
    codigo = '''
def filtrar(items, pares, x):
    for item in items:
        if item in ("env", "logs"):
            pass
        if item in ("get", "post", "put", "delete", "patch", "options", "head"):
            pass
        if item in ["a", "b", "c"]:
            pass
    for a, b in pares:
        if x in [a, b]:
            return True
    return False
'''
    assert _perf(tmp_path, codigo) == []


def test_in_sobre_coleccion_grande_o_construida_en_cada_vuelta_avisa_sin_duplicar(tmp_path):
    codigo = '''
def buscar(items, a, b, c, d, y):
    for x in items:
        if x in ("1", "2", "3", "4", "5", "6", "7", "8", "9"):
            pass
        if x in [a, b]:
            pass
        if x in [a, b] and y in [c, d]:
            pass
'''
    msgs = _perf(tmp_path, codigo)
    assert len(msgs) == 3
    assert all("Búsqueda secuencial O(n)" in m for m in msgs)


# --- YAML multidocumento y workloads de Kubernetes -----------------------------------

def test_yaml_multidocumento_y_k8s_workloads(tmp_path):
    from agentes.devops.yaml_validator import YAMLValidator
    from agentes.hardening.k8s_hardening import K8sHardening

    multi = tmp_path / "manifests.yaml"
    multi.write_text(
        "apiVersion: v1\n"
        "kind: Service\n"
        "metadata:\n"
        "  name: web-svc\n"
        "spec:\n"
        "  ports:\n"
        "    - port: 80\n"
        "---\n"
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: web\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      initContainers:\n"
        "        - name: init-db\n"
        "          image: busybox\n"
        "      containers:\n"
        "        - name: app\n"
        "          image: nginx:1.25\n",
        encoding="utf-8",
    )

    ok, errs = YAMLValidator.validate_yaml_syntax(str(multi))
    assert ok and errs == []

    findings = audits.audit_yaml(str(multi))
    assert findings
    assert all(f.rule_id == "K8S-WORKLOAD" for f in findings)
    msgs = " ".join(f.message for f in findings)
    assert "Deployment.spec.securityContext.runAsNonRoot" in msgs
    assert "Container(app).allowPrivilegeEscalation" in msgs
    assert "InitContainer(init-db).allowPrivilegeEscalation" in msgs

    statefulset = {
        "kind": "StatefulSet",
        "spec": {"template": {"spec": {"containers": [{"name": "db", "securityContext": None}]}}},
    }
    st_findings = K8sHardening.audit_pod_security_context(statefulset)
    assert any("StatefulSet.spec.securityContext.runAsNonRoot" in e for e, _, _ in st_findings)

    cronjob = {
        "kind": "CronJob",
        "spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "job"}]}}}}},
    }
    cj_findings = K8sHardening.audit_pod_security_context(cronjob)
    assert any("CronJob.spec.securityContext.runAsNonRoot" in e for e, _, _ in cj_findings)
    assert any("Container(job).allowPrivilegeEscalation" in e for e, _, _ in cj_findings)

    hardened_dep = tmp_path / "hardened_deploy.yaml"
    hardened_dep.write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      securityContext:\n"
        "        runAsNonRoot: true\n"
        "      containers:\n"
        "        - name: app\n"
        "          securityContext:\n"
        "            allowPrivilegeEscalation: false\n"
        "            readOnlyRootFilesystem: true\n"
        "            capabilities:\n"
        "              drop: [ALL]\n",
        encoding="utf-8",
    )
    assert audits.audit_yaml(str(hardened_dep)) == []

    svc = tmp_path / "service.yaml"
    svc.write_text("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cfg\n", encoding="utf-8")
    assert audits.audit_yaml(str(svc)) == []

    ok_missing, errs_missing = YAMLValidator.validate_yaml_syntax(str(tmp_path / "missing.yaml"))
    assert not ok_missing and errs_missing


# --- comment_ratio con docstrings y casos que SOLIDAuditor no debe marcar ----------

def test_comment_ratio_cuenta_docstrings_en_recomendaciones(tmp_path):
    from agentes.refactor.code_metrics import CodeMetricsCalculator
    from agentes.refactor.refactor_suggester import RefactorSuggester

    con_docs = tmp_path / "con_docs.py"
    cuerpo_doc = "".join(
        f'def fn_{i}(x: int) -> int:\n    """Suma {i}."""\n    return x + {i}\n\n'
        for i in range(28)
    )
    con_docs.write_text('"""Módulo documentado sin comentarios #."""\n\n' + cuerpo_doc, encoding="utf-8")
    m_doc = CodeMetricsCalculator.calculate_file_metrics(str(con_docs))
    assert m_doc["code_loc"] > 50
    assert m_doc["comment_ratio"] >= 5.0
    recs_doc = RefactorSuggester.generate_recommendations(m_doc, [], praise_if_clean=False)
    assert not any(r.startswith("[DOCUMENTACION") for r in recs_doc)

    sin_docs = tmp_path / "sin_docs.py"
    cuerpo_sin = "".join(
        f"def fn_{i}(x: int) -> int:\n    y = x + {i}\n    return y\n\n"
        for i in range(18)
    )
    sin_docs.write_text(cuerpo_sin, encoding="utf-8")
    m_sin = CodeMetricsCalculator.calculate_file_metrics(str(sin_docs))
    assert m_sin["code_loc"] > 50
    assert m_sin["comment_ratio"] == 0.0
    recs_sin = RefactorSuggester.generate_recommendations(m_sin, [], praise_if_clean=False)
    assert any(r.startswith("[DOCUMENTACION") for r in recs_sin)


def test_solid_dip_y_data_contract_sin_falsos_positivos(tmp_path):
    from agentes.refactor.solid_checker import SOLIDChecker

    src = tmp_path / "clean_di_and_dc.py"
    src.write_text(
        "from collections import Counter\n"
        "from dataclasses import dataclass\n"
        "from datetime import datetime\n"
        "from pathlib import Path\n"
        "from threading import Lock\n"
        "\n"
        "class MiError(Exception):\n"
        "    pass\n"
        "\n"
        "class Seguro:\n"
        "    def __init__(self, counts, path: str, created=None) -> None:\n"
        "        if not path:\n"
        "            raise KeyError('path')\n"
        "        if path == 'bad':\n"
        "            raise MiError('bad')\n"
        "        self.counts = Counter(counts)\n"
        "        self.path = Path(path)\n"
        "        self.lock = Lock()\n"
        "        self.ts = created or datetime.now()\n"
        "\n"
        "class Acoplado:\n"
        "    def __init__(self) -> None:\n"
        "        self.repo = PostgresRepo()\n"
        "\n"
        "@dataclass\n"
        "class ConSlots:\n"
        "    __slots__ = ('x',)\n"
        "    x: int\n"
        "\n"
        "@dataclass\n"
        "class MutablePostInit:\n"
        "    raw: str\n"
        "    def __post_init__(self) -> None:\n"
        "        self.raw = self.raw.strip()\n",
        encoding="utf-8",
    )
    findings = SOLIDChecker.audit_file(str(src))
    dip = [(ln, msg) for ln, p, _, msg in findings if p == "DIP"]
    assert len(dip) == 1 and "PostgresRepo" in dip[0][1]

    dc = [msg for _, p, _, msg in findings if p == "DATA-CONTRACT"]
    assert not any("ConSlots" in m for m in dc)
    mutable_msgs = [m for m in dc if "MutablePostInit" in m]
    assert len(mutable_msgs) == 1
    assert "frozen=True" not in mutable_msgs[0]
    assert "slots=True" in mutable_msgs[0]


# --- Deduplicación entre etapas y secretos inequívocos en comentarios ---------------

def test_deduplicacion_entre_sast_solid_y_perf(tmp_path):
    src = tmp_path / "dup.py"
    src.write_text(
        "import time\n"
        "\n"
        "def f(items=[]):\n"
        '    """Doc."""\n'
        "    try:\n"
        "        return len(items)\n"
        "    except:\n"
        "        return 0\n"
        "\n"
        "async def g():\n"
        '    """Doc."""\n'
        "    time.sleep(0.1)\n",
        encoding="utf-8",
    )
    report, _ = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "rep"), prefer_bandit=False)
    findings = report["findings"]

    bare = [f for f in findings if f["line"] == 7 and audits.topic(Finding.from_dict(f)) == "bare-except"]
    assert len(bare) == 1, bare

    mutable = [f for f in findings if f["line"] == 3 and audits.topic(Finding.from_dict(f)) == "mutable-default"]
    assert len(mutable) == 1, mutable

    blocking = [f for f in findings if f["line"] == 12 and audits.topic(Finding.from_dict(f)) == "blocking-async"]
    assert len(blocking) == 1, blocking


def test_secretos_inequivocos_se_detectan_en_comentarios(tmp_path):
    from agentes.defensive.config_manager import ConfigManager

    cfg = tmp_path / "leak.py"
    cfg.write_text(
        '# old: ghp_' + '16C7e42F292c6912E7710c838347Ae178B4a\n'
        '# AKIA' + 'IOSFODNN7EXAMPLE\n'
        '# -----BEGIN RSA ' + 'PRIVATE KEY-----\n'
        '# password = "esto es un ejemplo"\n',
        encoding="utf-8",
    )
    hits = ConfigManager.scan_file_for_secrets(str(cfg))
    assert [ln for ln, _, _ in hits] == [1, 2, 3]
    descs = " | ".join(desc for _, desc, _ in hits)
    assert "GitHub" in descs and "AWS" in descs and "PEM" in descs


# --- except Exception según lo que hace con el error ---------------------------------

BROAD = '''import logging

logger = logging.getLogger(__name__)


def relanza(x):
    """Doc."""
    try:
        return int(x)
    except Exception as exc:
        raise ValueError(x) from exc


def registra(x):
    """Doc."""
    try:
        return int(x)
    except Exception:
        logger.exception("fallo")


def con_traza(x):
    """Doc."""
    try:
        return int(x)
    except Exception:
        logger.error("fallo", exc_info=True)


def informa(x):
    """Doc."""
    try:
        return int(x)
    except Exception as e:
        print(f"No se pudo convertir: {e}")
        return None


def descarta(x):
    """Doc."""
    try:
        return int(x)
    except Exception:
        return 0


def anidada(x):
    """La función definida dentro no cuenta como relanzar."""
    try:
        return int(x)
    except Exception:
        def _f():
            raise RuntimeError
        return _f
'''


def test_except_exception_segun_lo_que_hace(tmp_path):
    from agentes.quality.static_checker import StaticCodeAnalyzer

    path = tmp_path / "broad.py"
    path.write_text(BROAD, encoding="utf-8")
    lines = BROAD.splitlines()
    handlers = [i for i, text in enumerate(lines, 1) if text.strip().startswith("except Exception")]
    issues = {line: (level, msg) for line, level, msg in
              StaticCodeAnalyzer.analyze_python_file(str(path), prefer_bandit=False) if "except Exception" in msg}
    relanza, registra, con_traza, informa, descarta, anidada = handlers
    assert relanza not in issues and registra not in issues and con_traza not in issues
    assert issues[informa][0] == "BAJO" and "frontera" in issues[informa][1]
    assert issues[descarta][0] == "MEDIO"
    assert issues[anidada][0] == "MEDIO"
    # Siguen siendo el mismo tema: se funden con Bandit y se silencian con broad-except.
    assert audits.topic(Finding("a.py", informa, "BAJO", issues[informa][1])) == "broad-except"


# --- Rangos que copian el pyproject.toml ------------------------------------------

def test_requirements_que_copia_el_pyproject_no_pide_versiones_exactas(tmp_path):
    from agentes.quality.dependency_auditor import DependencyAuditor

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "lib"\nversion = "1"\ndependencies = ["PyYAML>=6.0", "packaging~=24.0"]\n'
        '[project.optional-dependencies]\ndev = ["pytest>=7"]\n',
        encoding="utf-8",
    )
    req = tmp_path / "requirements.txt"
    req.write_text("pyyaml>=6.0\npackaging~=24.0\npytest>=7\nrequests>=2.31\nflask\n", encoding="utf-8")
    flagged = {pkg: level for pkg, level, _ in DependencyAuditor.audit_requirements_txt(str(req))}
    assert flagged == {"requests>=2.31": "BAJO", "flask": "MEDIO"}

    # Sin pyproject, o si no se puede leer, se avisa como siempre.
    (tmp_path / "pyproject.toml").write_text("[project\n", encoding="utf-8")
    assert len(DependencyAuditor.audit_requirements_txt(str(req))) == 5


# --- Docstrings: solo la API pública que no se documenta en otro sitio ------------------

DOCS = '''import ast
from typing import override


class Visitor(ast.NodeVisitor):
    """Doc."""

    def visit_Call(self, node):
        self.generic_visit(node)


class NoVisitor:
    """Doc."""

    def visit_Call(self, node):
        return node

    @property
    def size(self):
        return 1

    @size.setter
    def size(self, value):
        self._size = value

    @override
    def run(self):
        return 2


def externa():
    """Doc."""
    def interna():
        return 1
    return interna


def publica():
    return 3
'''


def test_docstrings_solo_en_la_api_publica(tmp_path):
    from agentes.quality.static_checker import StaticCodeAnalyzer

    path = tmp_path / "docs_mod.py"
    path.write_text(DOCS, encoding="utf-8")
    missing = sorted(msg.split("'")[1] for _, _, msg in StaticCodeAnalyzer.analyze_python_file(str(path), prefer_bandit=False)
                     if "carece de docstring" in msg)
    # El visit_Call de una clase que no es un NodeVisitor y el getter de la propiedad sí cuentan.
    assert missing == ["publica", "size", "visit_Call"]


# --- Tabla de reglas del análisis estático -----------------------------------------------

def test_una_regla_nueva_solo_necesita_estar_en_la_tabla(tmp_path, monkeypatch):
    """El recorrido aplica lo que registre RULES: añadir una regla no toca CodeQualityChecker."""
    import ast

    from agentes.quality import static_checker

    def global_statement(state, node):
        state.issue(node.lineno, "BAJO", f"global {', '.join(node.names)}")

    monkeypatch.setitem(static_checker.RULES, ast.Global, (global_statement,))
    path = tmp_path / "mod.py"
    path.write_text('"""Doc."""\nX = 0\n\n\ndef f():\n    """Doc."""\n    global X\n    X = 1\n', encoding="utf-8")
    checker = static_checker.CodeQualityChecker(str(path))
    checker.visit(ast.parse(path.read_text(encoding="utf-8")))
    assert checker.issues == [(7, "BAJO", "global X")]


def test_las_cadenas_de_llamadas_paran_en_la_primera_regla_que_decide(tmp_path, monkeypatch):
    """La primera regla que devuelve True decide: las siguientes de la cadena no se evalúan."""
    import ast

    from agentes.quality import static_checker

    evaluated = []

    def decides(state, node, attr, owner):
        evaluated.append("decide")
        return attr == "load"

    def spy(state, node, attr, owner):
        evaluated.append(f"spy:{attr}")
        return False

    monkeypatch.setattr(static_checker, "ATTRIBUTE_CALL_RULES", (decides, spy))
    checker = static_checker.CodeQualityChecker("mod.py")
    checker.visit(ast.parse("yaml.load(s)\nyaml.dump(s)\n"))
    assert evaluated == ["decide", "decide", "spy:dump"]


# --- Bandit por grupos: fallos, filtro en tests y rutas -----------------------------------

def _fake_bandit(monkeypatch, respond):
    """Sustituye el subproceso de Bandit: respond(archivos) devuelve la salida o lanza la excepción."""
    import types

    from agentes.quality import static_checker

    def run(cmd, **kwargs):
        return types.SimpleNamespace(stdout=respond(cmd[cmd.index("-q") + 1:]))

    monkeypatch.setattr(static_checker.StaticCodeAnalyzer, "bandit_command", staticmethod(lambda: ["bandit"]))
    monkeypatch.setattr(static_checker.subprocess, "run", run)
    return static_checker.StaticCodeAnalyzer


def _bandit_result(path, test_id, line=3, severity="HIGH", confidence="HIGH"):
    return {"filename": path, "test_id": test_id, "line_number": line, "issue_severity": severity,
            "issue_confidence": confidence, "issue_text": f"texto {test_id}"}


def test_bandit_un_grupo_que_falla_no_tumba_a_los_demas(tmp_path, monkeypatch):
    for name in ("a.py", "b.py", "c.py", "d.py"):
        (tmp_path / name).touch()
    files = [str(tmp_path / name) for name in ("a.py", "b.py", "c.py", "d.py")]

    def respond(chunk):
        if chunk[0].endswith("c.py"):
            raise subprocess.TimeoutExpired("bandit", 60)
        return json.dumps({"results": [
            _bandit_result(files[0], "B602"),
            {"test_id": "B101"},                      # sin archivo
            _bandit_result("/otro/sitio.py", "B602"),  # de un archivo que no se pidió
        ]})

    analyzer = _fake_bandit(monkeypatch, respond)
    batch = analyzer._analyze_batch_with_bandit(files, chunk_size=2)
    # El segundo grupo no aparece: sus archivos quedan solo con el motor AST.
    assert batch == {files[0]: [(3, "CRITICO", "[bandit] texto B602")], files[1]: []}


def test_bandit_en_tests_no_cuenta_assert_ni_contrasenas_de_ejemplo(tmp_path, monkeypatch):
    (tmp_path / "test_mod.py").touch()
    path = str(tmp_path / "test_mod.py")
    results = [_bandit_result(path, code, line=n) for n, code in enumerate(("B101", "B105", "B106", "B107", "B602"), 1)]
    analyzer = _fake_bandit(monkeypatch, lambda chunk: json.dumps({"results": results}))
    assert analyzer._analyze_batch_with_bandit([path]) == {path: [(5, "CRITICO", "[bandit] texto B602")]}


def test_bandit_devuelve_la_ruta_tal_como_se_pidio(tmp_path, monkeypatch):
    real = tmp_path / "real.py"
    real.write_text("x = 1\n", encoding="utf-8")
    link = tmp_path / "enlace.py"
    link.symlink_to(real)
    analyzer = _fake_bandit(monkeypatch, lambda chunk: json.dumps({"results": [_bandit_result(str(real), "B602")]}))
    assert analyzer._analyze_batch_with_bandit([str(link)]) == {str(link): [(3, "CRITICO", "[bandit] texto B602")]}


@pytest.mark.parametrize("salida", ["", "   ", "no es json", "null", "[]", OSError("sin permiso"), ValueError("x")])
def test_bandit_sin_ningun_informe_valido_devuelve_none(tmp_path, monkeypatch, salida):
    (tmp_path / "a.py").touch()
    path = str(tmp_path / "a.py")

    def respond(chunk):
        if isinstance(salida, Exception):
            raise salida
        return salida

    analyzer = _fake_bandit(monkeypatch, respond)
    assert analyzer._analyze_batch_with_bandit([path]) is None


# --- OpenAPI: tipos de los parámetros y rutas sin barra inicial ---------------------------

def test_openapi_traduce_las_anotaciones_y_normaliza_la_ruta(tmp_path):
    src = tmp_path / "api.py"
    src.write_text(
        "from typing import Dict, List, Optional\nfrom fastapi import FastAPI\napp = FastAPI()\n\n\n"
        '@app.post("items")\ndef crear(ids: List[int], nota: Optional[str], extra: Dict[str, int], '
        'nombre: "str", libre, cuenta: int = 1):\n    """Crea."""\n    return {}\n',
        encoding="utf-8",
    )
    spec = OpenAPIGenerator.generate_openapi_spec(str(src))
    assert list(spec["paths"]) == ["/items"]
    schema = spec["components"]["schemas"]["crear_Request"]
    assert schema["properties"] == {
        "ids": {"type": "array", "items": {"type": "integer"}}, "nota": {"type": "string"},
        "extra": {"type": "object"}, "nombre": {"type": "string"}, "libre": {"type": "string"},
        "cuenta": {"type": "integer"},
    }
    assert "cuenta" not in schema["required"], "con valor por defecto no es obligatorio"
