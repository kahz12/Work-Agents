"""
Catálogo de reglas del análisis estático y del auditor de rendimiento: para cada regla, un
código que la activa y otro parecido que no. Si una regla cambia de criterio, el test dice cuál.
"""
import ast
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentes.quality.static_checker import CodeQualityChecker, StaticCodeAnalyzer  # noqa: E402
from agentes.refactor.code_metrics import CodeMetricsCalculator  # noqa: E402


def _messages(code: str, filename: str = "mod.py"):
    checker = CodeQualityChecker(filename)
    checker.visit(ast.parse(code))
    return [msg for _, _, msg in checker.issues]


# (código que activa la regla, código parecido que no, fragmento del mensaje)
CATALOGO = {
    "demasiados argumentos": (
        "def f(a, b, c, d, e, g):\n    '''D.'''\n", "def f(self, a, b, c, d, e):\n    '''D.'''\n",
        "recibe 6 argumentos"),
    "argumento por defecto mutable": (
        "def f(x={}):\n    '''D.'''\n", "def f(x=None):\n    '''D.'''\n", "por defecto mutable"),
    "except desnudo": ("try:\n    x()\nexcept:\n    raise\n", "try:\n    x()\nexcept ValueError:\n    raise\n",
                       "Uso de 'except:' genérico"),
    "eval": ("eval(x)\n", "literal_eval(x)\n", "riesgo dinámico 'eval()'"),
    "pickle.loads": ("import pickle\npickle.loads(b)\n", "import json\njson.loads(b)\n", "pickle.loads()"),
    "os.popen": ("import os\nos.popen(cmd)\n", "import os\nos.getcwd()\n", "os.popen()"),
    "yaml.load sin SafeLoader": (
        "import yaml\nyaml.load(s)\n", "import yaml\nyaml.load(s, Loader=yaml.SafeLoader)\nyaml.load(s, SafeLoader)\n",
        "yaml.load()' sin SafeLoader"),
    "hash débil": ("import hashlib\nhashlib.sha1(b)\n", "import hashlib\nhashlib.sha1(b, usedforsecurity=False)\n",
                   "hashlib.sha1()"),
    "TLS sin verificar": ("import requests\nrequests.get(u, verify=False, timeout=1)\n",
                          "import requests\nrequests.get(u, timeout=1)\n", "verify=False"),
    "HTTP sin timeout": ("import httpx\nhttpx.post(u)\n", "import httpx\nhttpx.post(u, timeout=3)\n",
                         "Petición HTTP sin 'timeout'"),
    "urlopen sin timeout": ("import urllib.request\nurllib.request.urlopen(u)\n",
                            "import urllib.request\nurllib.request.urlopen(u, timeout=2)\n", "urlopen()' sin 'timeout'"),
    "shell=True": ("import subprocess\nsubprocess.call(c, shell=True)\n", "import subprocess\nsubprocess.call(c)\n",
                   "shell=True"),
    "SQL concatenado": ("cur.execute('SELECT ' + x)\n", "cur.execute('SELECT ?', (x,))\n", "concatenate en execute()"),
    "SQL con %": ("cur.execute('SELECT %s' % x)\n", "cur.execute('SELECT %s', (x,))\n", "formato dinámico (%)"),
    "SQL con f-string": ("cur.executemany(f'SELECT {x}', rows)\n", "cur.executemany('SELECT ?', rows)\n", "f-string en"),
    "SQL con .format": ("cur.execute('SELECT {}'.format(x))\n", "cur.execute(QUERY)\n", "formato dinámico (.format)"),
    "Jinja": ("import jinja2 as jinja\njinja.from_string(t)\n", "import json\njson.dumps(t)\n", "Jinja render/from_string"),
    "time.sleep en async": ("import time\nasync def f():\n    '''D.'''\n    time.sleep(1)\n",
                            "import time\ndef f():\n    '''D.'''\n    time.sleep(1)\n", "bloquea el event loop"),
    "open con ruta construida": ("open(f'/tmp/{x}')\n", "open(RUTA)\n", "Path Traversal"),
    "assert fuera de tests": ("assert x\n", "if not x:\n    raise ValueError\n", "Uso de assert"),
    "secreto en una asignación": ("API_KEY = 'q8Zr4mN2pW7vX1kL'\n", "API_KEY = os.environ['API_KEY']\n",
                                  "secreto hardcodeado en 'API_KEY'"),
    "secreto en un atributo": ("self.password = 'q8Zr4mN2pW7vX1kL'\n", "self.password_field = 'q8Zr4mN2pW7vX1kL'\n",
                               "secreto hardcodeado en 'password'"),
    "random para un token": ("import random\ntoken = random.random()\n", "import secrets\ntoken = secrets.token_hex()\n",
                             "módulo 'random'"),
}


@pytest.mark.parametrize("activa, no_activa, mensaje", CATALOGO.values(), ids=CATALOGO.keys())
def test_regla(activa, no_activa, mensaje):
    assert any(mensaje in m for m in _messages(activa)), _messages(activa)
    assert not any(mensaje in m for m in _messages(no_activa)), _messages(no_activa)


@pytest.mark.parametrize("valor", [
    "corta", "<tu-clave-aqui>", "$API_KEY", "${API_KEY}", "{api_key}", "xxxxxxxxxxxx", "changeme-now",
])
def test_rellenos_que_no_cuentan_como_secreto(valor):
    assert not any("secreto hardcodeado" in m for m in _messages(f"api_key = {valor!r}\n"))


def test_asignaciones_que_no_se_pueden_revisar_no_lanzan():
    assert _messages("token: str\nx[0] = 'q8Zr4mN2pW7vX1kL'\na, b = 1, 2\n") == []


def test_en_tests_no_se_marcan_secretos_de_ejemplo_ni_assert():
    code = "API_KEY = 'q8Zr4mN2pW7vX1kL'\nconfig = {'token': 'q8Zr4mN2pW7vX1kL'}\nassert x\n"
    assert _messages(code, "test_mod.py") == []


def test_analizador_con_un_archivo_que_no_existe_o_que_no_se_puede_analizar(tmp_path, monkeypatch):
    missing = str(tmp_path / "no.py")
    assert StaticCodeAnalyzer.analyze_python_files([missing], prefer_bandit=False) == {
        missing: [(0, "ERROR", f"El archivo {missing} no existe.")]}
    mod = tmp_path / "mod.py"
    mod.write_text("x = 1\n", encoding="utf-8")

    def falla(self, node):
        raise RuntimeError("visita rota")

    monkeypatch.setattr(CodeQualityChecker, "visit", falla)
    assert StaticCodeAnalyzer._analyze_with_ast(str(mod)) == [(0, "ERROR", "Error durante el análisis: visita rota")]


def test_analizar_un_archivo_con_bandit_devuelve_none_si_no_esta(tmp_path, monkeypatch):
    mod = tmp_path / "mod.py"
    mod.write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(StaticCodeAnalyzer, "bandit_command", staticmethod(lambda: None))
    assert StaticCodeAnalyzer._analyze_with_bandit(str(mod)) is None


# --- Auditor de rendimiento y complejidad -----------------------------------------------------

def _perf(tmp_path, code):
    path = tmp_path / "perf.py"
    path.write_text(code, encoding="utf-8")
    return [msg for _, _, _, msg in CodeMetricsCalculator.audit_performance(str(path))]


@pytest.mark.parametrize("llamada, nombre", [
    ("requests.get(u)", "requests.get()"),
    ("urllib.request.urlopen(u)", "urllib.request.urlopen()"),
    ("open(u)", "open()"),
])
def test_e_s_bloqueante_dentro_de_una_corrutina(tmp_path, llamada, nombre):
    msgs = _perf(tmp_path, f"import requests, urllib.request\n\n\nasync def f(u):\n    return {llamada}\n")
    assert any(nombre in m for m in msgs), msgs


def test_concatenar_texto_en_un_bucle_detecta_variables_anotadas_y_f_strings(tmp_path):
    msgs = _perf(tmp_path, "def f(items):\n    out: str = ''\n    for i in items:\n        out += f'{i}'\n"
                           "    return out\n")
    assert any("Concatenación incremental" in m for m in msgs), msgs


def test_re_compile_en_un_bucle_async_y_nombres_ligados_por_except_e_import(tmp_path):
    code = ("import re\n\n\nasync def f(rows):\n    async for row in rows:\n        try:\n            import json as pat\n"
            "        except ValueError as pat:\n            pass\n        re.compile(pat)\n        re.compile('fijo')\n")
    msgs = _perf(tmp_path, code)
    compiles = [m for m in msgs if "re.compile" in m]
    # El patrón ligado en cada vuelta (por el import o el except) no se puede sacar; el literal sí.
    assert len(compiles) == 1, msgs


def test_complejidad_de_un_bucle_async_for(tmp_path):
    path = tmp_path / "m.py"
    path.write_text("async def f(rows):\n    async for r in rows:\n        if r:\n            return r\n", encoding="utf-8")
    [(name, _, cyclomatic, cognitive)] = CodeMetricsCalculator.calculate_file_metrics(str(path))["function_details"]
    assert (name, cyclomatic, cognitive) == ("f", 3, 3)


def test_metricas_y_rendimiento_de_archivos_que_no_se_pueden_leer(tmp_path):
    missing = str(tmp_path / "no.py")
    assert CodeMetricsCalculator.audit_performance(missing) == [(0, "N/A", "ERROR", f"El archivo '{missing}' no existe.")]
    assert CodeMetricsCalculator.calculate_file_metrics(missing) == {"error": f"El archivo '{missing}' no existe."}
    assert "No se pudo leer" in CodeMetricsCalculator.calculate_file_metrics(str(tmp_path))["error"]
    broken = tmp_path / "roto.py"
    broken.write_text("def (:\n", encoding="utf-8")
    assert CodeMetricsCalculator.audit_performance(str(broken))[0][:3] == (0, "AST", "ERROR")
