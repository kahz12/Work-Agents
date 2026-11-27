"""
Rule catalogue for static analysis and the performance auditor: for each rule, code that
triggers it and similar code that does not. When a rule changes its criteria, the failing test
names the rule.
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


# (code that triggers the rule, similar code that does not, message fragment)
CATALOGUE = {
    "too many arguments": (
        "def f(a, b, c, d, e, g):\n    '''D.'''\n", "def f(self, a, b, c, d, e):\n    '''D.'''\n",
        "takes 6 arguments"),
    "mutable default argument": (
        "def f(x={}):\n    '''D.'''\n", "def f(x=None):\n    '''D.'''\n", "mutable default argument"),
    "bare except": ("try:\n    x()\nexcept:\n    raise\n", "try:\n    x()\nexcept ValueError:\n    raise\n",
                    "bare 'except:'"),
    "eval": ("eval(x)\n", "literal_eval(x)\n", "dynamic code execution function 'eval()'"),
    "pickle.loads": ("import pickle\npickle.loads(b)\n", "import json\njson.loads(b)\n", "pickle.loads()"),
    "os.popen": ("import os\nos.popen(cmd)\n", "import os\nos.getcwd()\n", "os.popen()"),
    "yaml.load without SafeLoader": (
        "import yaml\nyaml.load(s)\n", "import yaml\nyaml.load(s, Loader=yaml.SafeLoader)\nyaml.load(s, SafeLoader)\n",
        "yaml.load()' without SafeLoader"),
    "weak hash": ("import hashlib\nhashlib.sha1(b)\n", "import hashlib\nhashlib.sha1(b, usedforsecurity=False)\n",
                  "hashlib.sha1()"),
    "unverified TLS": ("import requests\nrequests.get(u, verify=False, timeout=1)\n",
                       "import requests\nrequests.get(u, timeout=1)\n", "verify=False"),
    "HTTP without timeout": ("import httpx\nhttpx.post(u)\n", "import httpx\nhttpx.post(u, timeout=3)\n",
                             "HTTP request without an explicit 'timeout'"),
    "urlopen without timeout": ("import urllib.request\nurllib.request.urlopen(u)\n",
                                "import urllib.request\nurllib.request.urlopen(u, timeout=2)\n",
                                "urlopen()' without an explicit 'timeout'"),
    "shell=True": ("import subprocess\nsubprocess.call(c, shell=True)\n", "import subprocess\nsubprocess.call(c)\n",
                   "shell=True"),
    "concatenated SQL": ("cur.execute('SELECT ' + x)\n", "cur.execute('SELECT ?', (x,))\n",
                         "string concatenation in execute()"),
    "SQL with %": ("cur.execute('SELECT %s' % x)\n", "cur.execute('SELECT %s', (x,))\n", "dynamic formatting (%)"),
    "SQL with an f-string": ("cur.executemany(f'SELECT {x}', rows)\n", "cur.executemany('SELECT ?', rows)\n",
                             "f-string in"),
    "SQL with .format": ("cur.execute('SELECT {}'.format(x))\n", "cur.execute(QUERY)\n", "dynamic formatting (.format)"),
    "Jinja": ("import jinja2 as jinja\njinja.from_string(t)\n", "import json\njson.dumps(t)\n", "Jinja render/from_string"),
    "time.sleep in async": ("import time\nasync def f():\n    '''D.'''\n    time.sleep(1)\n",
                            "import time\ndef f():\n    '''D.'''\n    time.sleep(1)\n", "blocks the event loop"),
    "open with a built path": ("open(f'/tmp/{x}')\n", "open(PATH)\n", "path traversal"),
    "assert outside tests": ("assert x\n", "if not x:\n    raise ValueError\n", "Use of assert"),
    "secret in an assignment": ("API_KEY = 'q8Zr4mN2pW7vX1kL'\n", "API_KEY = os.environ['API_KEY']\n",
                                "hardcoded secret in 'API_KEY'"),
    "secret in an attribute": ("self.password = 'q8Zr4mN2pW7vX1kL'\n", "self.password_field = 'q8Zr4mN2pW7vX1kL'\n",
                               "hardcoded secret in 'password'"),
    "random for a token": ("import random\ntoken = random.random()\n", "import secrets\ntoken = secrets.token_hex()\n",
                           "'random' module"),
}


@pytest.mark.parametrize("triggers, does_not_trigger, message", CATALOGUE.values(), ids=CATALOGUE.keys())
def test_rule(triggers, does_not_trigger, message):
    assert any(message in m for m in _messages(triggers)), _messages(triggers)
    assert not any(message in m for m in _messages(does_not_trigger)), _messages(does_not_trigger)


# Spanish placeholders ("tu-clave-aqui") are recognised as well, since the tool is used on Spanish codebases.
@pytest.mark.parametrize("value", [
    "short", "<your-key-here>", "tu-clave-aqui", "$API_KEY", "${API_KEY}", "{api_key}", "xxxxxxxxxxxx", "changeme-now",
])
def test_placeholders_do_not_count_as_secrets(value):
    assert not any("hardcoded secret" in m for m in _messages(f"api_key = {value!r}\n"))


def test_assignments_that_cannot_be_checked_do_not_raise():
    assert _messages("token: str\nx[0] = 'q8Zr4mN2pW7vX1kL'\na, b = 1, 2\n") == []


def test_sample_secrets_and_assert_are_not_flagged_in_tests():
    code = "API_KEY = 'q8Zr4mN2pW7vX1kL'\nconfig = {'token': 'q8Zr4mN2pW7vX1kL'}\nassert x\n"
    assert _messages(code, "test_mod.py") == []


def test_analyser_with_a_missing_or_unanalysable_file(tmp_path, monkeypatch):
    missing = str(tmp_path / "no.py")
    assert StaticCodeAnalyzer.analyze_python_files([missing], prefer_bandit=False) == {
        missing: [(0, "ERROR", f"File {missing} does not exist.")]}
    mod = tmp_path / "mod.py"
    mod.write_text("x = 1\n", encoding="utf-8")

    def fail(self, node):
        raise RuntimeError("broken visit")

    monkeypatch.setattr(CodeQualityChecker, "visit", fail)
    assert StaticCodeAnalyzer._analyze_with_ast(str(mod)) == [(0, "ERROR", "Error during analysis: broken visit")]


def test_analysing_a_file_with_bandit_returns_none_when_it_is_missing(tmp_path, monkeypatch):
    mod = tmp_path / "mod.py"
    mod.write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(StaticCodeAnalyzer, "bandit_command", staticmethod(lambda: None))
    assert StaticCodeAnalyzer._analyze_with_bandit(str(mod)) is None


# --- Performance and complexity auditor ------------------------------------------------------

def _perf(tmp_path, code):
    path = tmp_path / "perf.py"
    path.write_text(code, encoding="utf-8")
    return [msg for _, _, _, msg in CodeMetricsCalculator.audit_performance(str(path))]


@pytest.mark.parametrize("call, name", [
    ("requests.get(u)", "requests.get()"),
    ("urllib.request.urlopen(u)", "urllib.request.urlopen()"),
    ("open(u)", "open()"),
])
def test_blocking_io_inside_a_coroutine(tmp_path, call, name):
    msgs = _perf(tmp_path, f"import requests, urllib.request\n\n\nasync def f(u):\n    return {call}\n")
    assert any(name in m for m in msgs), msgs


def test_string_concatenation_in_a_loop_detects_annotated_variables_and_f_strings(tmp_path):
    msgs = _perf(tmp_path, "def f(items):\n    out: str = ''\n    for i in items:\n        out += f'{i}'\n"
                           "    return out\n")
    assert any("Incremental string concatenation" in m for m in msgs), msgs


def test_re_compile_in_an_async_loop_and_names_bound_by_except_and_import(tmp_path):
    code = ("import re\n\n\nasync def f(rows):\n    async for row in rows:\n        try:\n            import json as pat\n"
            "        except ValueError as pat:\n            pass\n        re.compile(pat)\n        re.compile('fixed')\n")
    msgs = _perf(tmp_path, code)
    compiles = [m for m in msgs if "re.compile" in m]
    # The pattern rebound on every iteration (by the import or the except) cannot be hoisted; the literal can.
    assert len(compiles) == 1, msgs


def test_complexity_of_an_async_for_loop(tmp_path):
    path = tmp_path / "m.py"
    path.write_text("async def f(rows):\n    async for r in rows:\n        if r:\n            return r\n", encoding="utf-8")
    [(name, _, cyclomatic, cognitive)] = CodeMetricsCalculator.calculate_file_metrics(str(path))["function_details"]
    assert (name, cyclomatic, cognitive) == ("f", 3, 3)


def test_metrics_and_performance_of_unreadable_files(tmp_path):
    missing = str(tmp_path / "no.py")
    assert CodeMetricsCalculator.audit_performance(missing) == [(0, "N/A", "ERROR", f"File '{missing}' does not exist.")]
    assert CodeMetricsCalculator.calculate_file_metrics(missing) == {"error": f"File '{missing}' does not exist."}
    assert "Could not read" in CodeMetricsCalculator.calculate_file_metrics(str(tmp_path))["error"]
    broken = tmp_path / "broken.py"
    broken.write_text("def (:\n", encoding="utf-8")
    assert CodeMetricsCalculator.audit_performance(str(broken))[0][:3] == (0, "AST", "ERROR")
