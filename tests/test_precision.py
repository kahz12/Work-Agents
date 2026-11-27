"""Precision on real projects: no duplicates across engines, calibrated severity and no invented APIs."""
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

CODE = '''import hashlib


def fingerprint(data: bytes) -> str:
    """Cache key, not a security use."""
    return hashlib.md5(data).hexdigest()


def get_provider():
    """Configuration helper: not an endpoint."""
    return "x"


def load():
    """Best effort."""
    try:
        return int("x")
    except Exception:
        pass
'''


def test_except_pass_is_reported_once_and_as_medium(tmp_path):
    (tmp_path / "app.py").write_text(CODE, encoding="utf-8")
    report, code = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "rep"), prefer_bandit=False)
    line = CODE.splitlines().index("    except Exception:") + 1
    on_line = [f for f in report["findings"] if f["line"] == line]
    topics = [audits.topic(Finding.from_dict(f)) for f in on_line]
    assert topics.count("exception-swallow") == 1, on_line
    assert all(f["level"] != "HIGH" for f in on_line)
    hashes = [f for f in report["findings"] if "md5" in f["message"].lower()]
    assert hashes and all(f["level"] == "MEDIUM" for f in hashes)
    assert "usedforsecurity=False" in hashes[0]["message"]
    assert code == 0, "neither of them is blocking"


def test_merging_engines_on_the_same_line():
    group = [
        Finding("a.py", 7, "LOW", "[bandit] Try, Except, Pass detected.", "SAST-LOW"),
        Finding("a.py", 7, "HIGH", "Use of 'except Exception: pass', which silences errors.", "SAST-HIGH"),
        Finding("a.py", 9, "CRITICAL", "[bandit] Use of weak MD5 hash for security. Consider usedforsecurity=False", "SAST-CRITICAL"),
        Finding("a.py", 9, "MEDIUM", "Weak cryptographic hash 'hashlib.md5()' (use SHA-256 or stronger).", "SAST-MEDIUM"),
        Finding("a.py", 11, "CRITICAL", "Use of the dynamic code execution function 'eval()'.", "SAST-CRITICAL"),
    ]
    res = audits.merge_duplicates(group)
    assert len(res) == 3
    by_line = {f.line: f for f in res}
    assert by_line[7].level == "MEDIUM" and "Also detected by: bandit" in by_line[7].message
    assert by_line[9].level == "MEDIUM" and by_line[9].rule_id == "SAST-MEDIUM"
    assert by_line[11].level == "CRITICAL", "eval is never downgraded"


def test_solid_does_not_repeat_what_static_analysis_reported():
    sast = [Finding("a.py", 7, "MEDIUM", "Use of 'except Exception: pass', which silences errors.", "SAST-MEDIUM").to_dict()]
    solid = [
        Finding("a.py", 7, "HIGH", "[EXCEPTION-HYGIENE] The 'except' block silences the exception with 'pass'.",
                "SOLID-EXCEPTION-HYGIENE").to_dict(),
        Finding("a.py", 30, "HIGH", "[EXCEPTION-HYGIENE] The 'except' block silences the exception with 'pass'.",
                "SOLID-EXCEPTION-HYGIENE").to_dict(),
    ]
    res = audits.drop_covered(solid, sast)
    assert [f["line"] for f in res] == [30]
    assert res[0]["level"] == "MEDIUM", "the remaining one is calibrated too"


def test_openapi_only_with_a_web_framework(tmp_path):
    (tmp_path / "app.py").write_text(CODE, encoding="utf-8")
    report, _ = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "rep"), prefer_bandit=False)
    docs = next(s for s in report["stages"] if s["name"] == "documentation")
    assert docs["status"] == "skipped" and "web framework" in docs["summary"]
    assert not (tmp_path / "rep" / "openapi.json").exists(), "no API is invented"

    (tmp_path / "web.py").write_text(
        'from flask import Flask\napp = Flask(__name__)\n\n@app.route("/items", methods=["POST"])\ndef create():\n    return {}\n',
        encoding="utf-8",
    )
    report, _ = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "rep"), prefer_bandit=False)
    docs = next(s for s in report["stages"] if s["name"] == "documentation")
    assert docs["status"] == "ok" and docs["frameworks"] == ["flask"]
    spec = json.loads((tmp_path / "rep" / "openapi.json").read_text(encoding="utf-8"))
    assert list(spec["paths"]) == ["/items"], "get_provider is not a route"


def test_without_routes_no_health_endpoint_is_invented(tmp_path):
    src = tmp_path / "nothing.py"
    src.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    assert OpenAPIGenerator.generate_openapi_spec(str(src))["paths"] == {}


def test_cli_openapi_uses_the_naming_convention_only_on_request(tmp_path, capsys):
    from agentes import cli

    src = tmp_path / "api.py"
    src.write_text("def get_users():\n    return []\n", encoding="utf-8")
    assert cli.main(["generate", "openapi", "--source", str(src), "-o", str(tmp_path / "a.json")]) == 0
    assert "--naming-convention" in capsys.readouterr().out
    assert json.loads((tmp_path / "a.json").read_text(encoding="utf-8"))["paths"] == {}
    assert cli.main(["generate", "openapi", "--source", str(src), "-o", str(tmp_path / "b.json"), "--naming-convention"]) == 0
    assert "/users" in json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))["paths"]


# --- Bandit, .env templates and displayed paths ----------------------------------------

def test_bandit_is_looked_up_next_to_the_interpreter(monkeypatch):
    from agentes.quality import static_checker as sc

    monkeypatch.setattr(sc.importlib.util, "find_spec", lambda name: object() if name == "bandit" else None)
    monkeypatch.setattr(sc.shutil, "which", lambda name: None)
    assert sc.StaticCodeAnalyzer.bandit_command() == [sys.executable, "-m", "bandit"], "without depending on PATH"

    monkeypatch.setattr(sc.importlib.util, "find_spec", lambda name: None)
    monkeypatch.setattr(sc.shutil, "which", lambda name: "/opt/bin/bandit")
    assert sc.StaticCodeAnalyzer.bandit_command() == ["/opt/bin/bandit"]

    monkeypatch.setattr(sc.shutil, "which", lambda name: None)
    assert sc.StaticCodeAnalyzer.bandit_command() is None


def test_without_bandit_the_summary_says_so(tmp_path, monkeypatch):
    from agentes.quality import static_checker as sc

    monkeypatch.setattr(sc.StaticCodeAnalyzer, "bandit_command", staticmethod(lambda: None))
    (tmp_path / "a.py").write_text("X = 1\n", encoding="utf-8")
    report, _ = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "rep"), prefer_bandit=True)
    sast = next(s for s in report["stages"] if s["name"] == "quality_sast")
    assert sast["engine"] == "ast" and "without Bandit" in sast["summary"]
    report, _ = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "rep"), prefer_bandit=False)
    assert "without Bandit" not in next(s for s in report["stages"] if s["name"] == "quality_sast")["summary"]


def test_env_templates_and_empty_values(tmp_path):
    template = tmp_path / ".env.example"
    template.write_text("API_KEY=\nSECRET_KEY=changeme\nDEBUG=true\n", encoding="utf-8")
    findings = audits.audit_env(str(template))
    assert [f.level for f in findings] == ["LOW"] and "[DEBUG]" in findings[0].message

    real = tmp_path / ".env"
    real.write_text("API_KEY=\nSECRET_KEY=changeme\nTOKEN=abc\n", encoding="utf-8")
    messages = " ".join(f.message for f in audits.audit_env(str(real)))
    assert "API_KEY" not in messages, "an empty value means unset, not a short key"
    assert "SECRET_KEY" in messages and "TOKEN" in messages


def test_paths_relative_to_the_analysed_project(tmp_path, capsys, monkeypatch):
    from agentes import cli

    far_away = tmp_path / "a" / "b" / "c" / "d"
    far_away.mkdir(parents=True)
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "mod.py").write_text("def f():\n    try:\n        return 1\n    except Exception:\n        pass\n", encoding="utf-8")
    monkeypatch.chdir(far_away)
    cli.main(["analyze", str(project), "-o", str(tmp_path / "rep"), "--no-bandit"])
    out = capsys.readouterr().out
    assert "src/mod.py:4" in out.replace(os.sep, "/")
    assert str(project / "src" / "mod.py") not in out


# --- Branch threshold, open() closed in finally and urllib's urlopen -------------------

def _sast(tmp_path, code):
    from agentes.quality.static_checker import StaticCodeAnalyzer
    src = tmp_path / "mod.py"
    src.write_text(code, encoding="utf-8")
    return [msg for _, _, msg in StaticCodeAnalyzer.analyze_python_file(str(src), prefer_bandit=False)]


def _branches(n):
    body = "".join(f"    {'if' if i == 0 else 'elif'} x == {i}:\n        return {i}\n" for i in range(n))
    return f"def f(x):\n    \"\"\"Doc.\"\"\"\n{body}    return -1\n"


def test_ocp_allows_up_to_12_branches_like_ruff_and_pylint(tmp_path):
    from agentes.refactor.solid_checker import SOLIDChecker
    src = tmp_path / "branches.py"
    src.write_text(_branches(12), encoding="utf-8")
    assert not any(p == "OCP" for _, p, _, _ in SOLIDChecker.audit_file(str(src)))
    src.write_text(_branches(13), encoding="utf-8")
    ocp = [msg for _, p, _, msg in SOLIDChecker.audit_file(str(src)) if p == "OCP"]
    assert len(ocp) == 1 and "13 'if/elif' branches" in ocp[0] and "recommended maximum: 12" in ocp[0]


OPEN_OUTSIDE_WITH = "Call to 'open()' outside a 'with' context manager"


def test_open_closed_in_finally_is_not_a_leak(tmp_path):
    code = '''
def write_report(path):
    """Doc."""
    report = None
    if path:
        report = open(path, "w", encoding="utf-8")
    try:
        if report:
            report.write("x")
    finally:
        if report:
            report.close()
'''
    assert not any(OPEN_OUTSIDE_WITH in m for m in _sast(tmp_path, code))


def test_open_closed_in_every_except_and_in_else(tmp_path):
    code = '''
def write(tmp, destination):
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
    assert not any(OPEN_OUTSIDE_WITH in m for m in _sast(tmp_path, code))


def test_open_inside_an_exitstack(tmp_path):
    code = '''
import contextlib


def open_all(paths):
    """Doc."""
    with contextlib.ExitStack() as stack:
        return [stack.enter_context(open(p)) for p in paths]
'''
    assert not any(OPEN_OUTSIDE_WITH in m for m in _sast(tmp_path, code))


def test_open_without_a_guaranteed_close_is_still_reported(tmp_path):
    never_closed = 'def f(r):\n    """Doc."""\n    h = open(r)\n    return h.read()\n'
    closed_only_in_except = '''
def g(r):
    """Doc."""
    h = open(r)
    try:
        return h.read()
    except OSError:
        h.close()
        raise
'''
    assert any(OPEN_OUTSIDE_WITH in m for m in _sast(tmp_path, never_closed))
    assert any(OPEN_OUTSIDE_WITH in m for m in _sast(tmp_path, closed_only_in_except)), \
        "with neither else nor finally, the normal path never closes the file"


URLOPEN = "Call to 'urlopen()' without an explicit 'timeout'"


def test_urlopen_on_other_objects_is_not_urllibs(tmp_path):
    code = '''
import yt_dlp


def download(url):
    """Doc."""
    with yt_dlp.YoutubeDL({}) as ydl:
        with ydl.urlopen(url) as response:
            return response.read()


def urlopen(x):
    """A function of our own with the same name."""
    return x


def use():
    """Doc."""
    return urlopen(1)
'''
    assert not any(URLOPEN in m for m in _sast(tmp_path, code))


def test_urllib_urlopen_is_detected_however_it_is_imported(tmp_path):
    forms = {
        "import urllib.request\nurllib.request.urlopen(u)": True,
        "import urllib.request as ur\nur.urlopen(u)": True,
        "from urllib import request\nrequest.urlopen(u)": True,
        "from urllib.request import urlopen\nurlopen(u)": True,
        "from urllib.request import urlopen as fetch\nfetch(u)": True,
        "from urllib.request import *\nurlopen(u)": True,
        "from urllib.request import urlopen\nurlopen(u, timeout=5)": False,
        "import urllib.request\nurllib.request.urlopen(u, None, 5)": False,
    }
    for code, reported in forms.items():
        findings = _sast(tmp_path, f"u = 'https://x'\n{code}\n")
        assert any(URLOPEN in m for m in findings) is reported, code


# --- Performance: pop(0)/insert(0) only in loops, and re.compile that does not change ---

def _perf(tmp_path, code):
    from agentes.refactor.code_metrics import CodeMetricsCalculator
    src = tmp_path / "perf.py"
    src.write_text(code, encoding="utf-8")
    return [msg for _, _, _, msg in CodeMetricsCalculator.audit_performance(str(src))]


def test_one_off_pop_and_insert_are_not_a_bottleneck(tmp_path):
    code = '''
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
for extra in ("a", "b"):
    sys.path.insert(0, extra)


def script(answers):
    """A getpass double: each call hands out the next answer."""
    pending = list(answers)

    def _prompt(label=""):
        return pending.pop(0)

    return _prompt


class Slow:
    def __init__(self, answers):
        self.answers = list(answers)

    def ask(self):
        if self.answers:
            return self.answers.pop(0)
        return None


def prepend(items, item):
    items.insert(0, item)
    return items
'''
    assert _perf(tmp_path, code) == []


def test_pop_and_insert_in_a_loop_are_still_reported(tmp_path):
    code = '''
def breadth_first(root):
    queue = [root]
    while queue:
        node = queue.pop(0)
        queue.extend(node.children)


def reverse(xs):
    out = []
    for x in xs:
        out.insert(0, x)
    return out
'''
    msgs = _perf(tmp_path, code)
    assert sum(".pop(0)" in m and "loop" in m for m in msgs) == 1
    assert sum(".insert(0" in m and "loop" in m for m in msgs) == 1


def test_re_compile_of_a_pattern_that_changes_on_every_iteration(tmp_path):
    code = '''
import re


def compile_all(words, use_regex, flags):
    patterns = [words] if use_regex else [p.strip() for p in words.split(",")]
    compiled = []
    for pat in patterns:
        try:
            compiled.append(re.compile(pat if use_regex else re.escape(pat), flags))
        except re.error:
            return None
    return compiled


def by_index(patterns):
    for i, _ in enumerate(patterns):
        current = patterns[i]
        yield re.compile(current)


def from_a_function(source):
    while True:
        yield re.compile(source())
'''
    assert not any("re.compile" in m for m in _perf(tmp_path, code))


def test_loop_invariant_re_compile_is_still_reported(tmp_path):
    code = '''
import re

PATTERN = r"\\d+"


def literal(lines):
    for line in lines:
        if re.compile(r"\\s+").match(line):
            yield line


def constant(lines):
    for line in lines:
        yield re.compile(PATTERN, re.I).search(line)


def only_changes_outside(patterns, lines):
    for pat in patterns:
        for line in lines:
            yield re.compile(re.escape(pat)).search(line)
'''
    assert sum("re.compile" in m for m in _perf(tmp_path, code)) == 3


def test_in_against_a_short_tuple_or_list_of_constants_is_not_reported(tmp_path):
    code = '''
def filter_items(items, pairs, x):
    for item in items:
        if item in ("env", "logs"):
            pass
        if item in ("get", "post", "put", "delete", "patch", "options", "head"):
            pass
        if item in ["a", "b", "c"]:
            pass
    for a, b in pairs:
        if x in [a, b]:
            return True
    return False
'''
    assert _perf(tmp_path, code) == []


def test_in_against_a_large_or_rebuilt_collection_is_reported_once(tmp_path):
    code = '''
def search(items, a, b, c, d, y):
    for x in items:
        if x in ("1", "2", "3", "4", "5", "6", "7", "8", "9"):
            pass
        if x in [a, b]:
            pass
        if x in [a, b] and y in [c, d]:
            pass
'''
    msgs = _perf(tmp_path, code)
    assert len(msgs) == 3
    assert all("O(n) membership test" in m for m in msgs)


# --- Multi-document YAML and Kubernetes workloads ------------------------------------------

def test_multi_document_yaml_and_k8s_workloads(tmp_path):
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


# --- comment_ratio with docstrings, and cases SOLIDAuditor must not flag ------------------

def test_comment_ratio_counts_docstrings_for_recommendations(tmp_path):
    from agentes.refactor.code_metrics import CodeMetricsCalculator
    from agentes.refactor.refactor_suggester import RefactorSuggester

    documented = tmp_path / "documented.py"
    documented_body = "".join(
        f'def fn_{i}(x: int) -> int:\n    """Add {i}."""\n    return x + {i}\n\n'
        for i in range(28)
    )
    documented.write_text('"""Documented module without # comments."""\n\n' + documented_body, encoding="utf-8")
    m_doc = CodeMetricsCalculator.calculate_file_metrics(str(documented))
    assert m_doc["code_loc"] > 50
    assert m_doc["comment_ratio"] >= 5.0
    recs_doc = RefactorSuggester.generate_recommendations(m_doc, [], praise_if_clean=False)
    assert not any(r.startswith("[DOCUMENTATION") for r in recs_doc)

    undocumented = tmp_path / "undocumented.py"
    undocumented_body = "".join(
        f"def fn_{i}(x: int) -> int:\n    y = x + {i}\n    return y\n\n"
        for i in range(18)
    )
    undocumented.write_text(undocumented_body, encoding="utf-8")
    m_none = CodeMetricsCalculator.calculate_file_metrics(str(undocumented))
    assert m_none["code_loc"] > 50
    assert m_none["comment_ratio"] == 0.0
    recs_none = RefactorSuggester.generate_recommendations(m_none, [], praise_if_clean=False)
    assert any(r.startswith("[DOCUMENTATION") for r in recs_none)


def test_solid_dip_and_data_contract_without_false_positives(tmp_path):
    from agentes.refactor.solid_checker import SOLIDChecker

    src = tmp_path / "clean_di_and_dc.py"
    src.write_text(
        "from collections import Counter\n"
        "from dataclasses import dataclass\n"
        "from datetime import datetime\n"
        "from pathlib import Path\n"
        "from threading import Lock\n"
        "\n"
        "class MyError(Exception):\n"
        "    pass\n"
        "\n"
        "class Safe:\n"
        "    def __init__(self, counts, path: str, created=None) -> None:\n"
        "        if not path:\n"
        "            raise KeyError('path')\n"
        "        if path == 'bad':\n"
        "            raise MyError('bad')\n"
        "        self.counts = Counter(counts)\n"
        "        self.path = Path(path)\n"
        "        self.lock = Lock()\n"
        "        self.ts = created or datetime.now()\n"
        "\n"
        "class Coupled:\n"
        "    def __init__(self) -> None:\n"
        "        self.repo = PostgresRepo()\n"
        "\n"
        "@dataclass\n"
        "class WithSlots:\n"
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
    assert not any("WithSlots" in m for m in dc)
    mutable_msgs = [m for m in dc if "MutablePostInit" in m]
    assert len(mutable_msgs) == 1
    assert "frozen=True" not in mutable_msgs[0]
    assert "slots=True" in mutable_msgs[0]


# --- Deduplication across stages, and unambiguous secrets in comments --------------------

def test_deduplication_across_sast_solid_and_perf(tmp_path):
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


def test_unambiguous_secrets_are_detected_in_comments(tmp_path):
    from agentes.defensive.config_manager import ConfigManager

    cfg = tmp_path / "leak.py"
    cfg.write_text(
        '# old: ghp_' + '16C7e42F292c6912E7710c838347Ae178B4a\n'
        '# AKIA' + 'IOSFODNN7EXAMPLE\n'
        '# -----BEGIN RSA ' + 'PRIVATE KEY-----\n'
        '# password = "this is an example"\n',
        encoding="utf-8",
    )
    hits = ConfigManager.scan_file_for_secrets(str(cfg))
    assert [ln for ln, _, _ in hits] == [1, 2, 3]
    descs = " | ".join(desc for _, desc, _ in hits)
    assert "GitHub" in descs and "AWS" in descs and "PEM" in descs


# --- except Exception, graded by what it does with the error ---------------------------------

BROAD = '''import logging

logger = logging.getLogger(__name__)


def reraises(x):
    """Doc."""
    try:
        return int(x)
    except Exception as exc:
        raise ValueError(x) from exc


def logs(x):
    """Doc."""
    try:
        return int(x)
    except Exception:
        logger.exception("failure")


def with_traceback(x):
    """Doc."""
    try:
        return int(x)
    except Exception:
        logger.error("failure", exc_info=True)


def reports(x):
    """Doc."""
    try:
        return int(x)
    except Exception as e:
        print(f"Could not convert: {e}")
        return None


def discards(x):
    """Doc."""
    try:
        return int(x)
    except Exception:
        return 0


def nested(x):
    """A function defined inside the handler does not count as re-raising."""
    try:
        return int(x)
    except Exception:
        def _f():
            raise RuntimeError
        return _f
'''


def test_except_exception_by_what_the_handler_does(tmp_path):
    from agentes.quality.static_checker import StaticCodeAnalyzer

    path = tmp_path / "broad.py"
    path.write_text(BROAD, encoding="utf-8")
    lines = BROAD.splitlines()
    handlers = [i for i, text in enumerate(lines, 1) if text.strip().startswith("except Exception")]
    issues = {line: (level, msg) for line, level, msg in
              StaticCodeAnalyzer.analyze_python_file(str(path), prefer_bandit=False) if "except Exception" in msg}
    reraises, logs, with_traceback, reports, discards, nested = handlers
    assert reraises not in issues and logs not in issues and with_traceback not in issues
    assert issues[reports][0] == "LOW" and "boundary" in issues[reports][1]
    assert issues[discards][0] == "MEDIUM"
    assert issues[nested][0] == "MEDIUM"
    # They are still the same topic: merged with Bandit and suppressed with broad-except.
    assert audits.topic(Finding("a.py", reports, "LOW", issues[reports][1])) == "broad-except"


# --- Ranges that mirror pyproject.toml ------------------------------------------------------

def test_requirements_mirroring_pyproject_do_not_ask_for_exact_versions(tmp_path):
    from agentes.quality.dependency_auditor import DependencyAuditor

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "lib"\nversion = "1"\ndependencies = ["PyYAML>=6.0", "packaging~=24.0"]\n'
        '[project.optional-dependencies]\ndev = ["pytest>=7"]\n',
        encoding="utf-8",
    )
    req = tmp_path / "requirements.txt"
    req.write_text("pyyaml>=6.0\npackaging~=24.0\npytest>=7\nrequests>=2.31\nflask\n", encoding="utf-8")
    flagged = {pkg: level for pkg, level, _ in DependencyAuditor.audit_requirements_txt(str(req))}
    assert flagged == {"requests>=2.31": "LOW", "flask": "MEDIUM"}

    # Without a pyproject, or when it cannot be read, everything is reported as usual.
    (tmp_path / "pyproject.toml").write_text("[project\n", encoding="utf-8")
    assert len(DependencyAuditor.audit_requirements_txt(str(req))) == 5


# --- Docstrings: only public API that is not documented elsewhere --------------------------

DOCS = '''import ast
from typing import override


class Visitor(ast.NodeVisitor):
    """Doc."""

    def visit_Call(self, node):
        self.generic_visit(node)


class NotAVisitor:
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


def outer():
    """Doc."""
    def inner():
        return 1
    return inner


def public_api():
    return 3
'''


def test_docstrings_only_required_on_public_api(tmp_path):
    from agentes.quality.static_checker import StaticCodeAnalyzer

    path = tmp_path / "docs_mod.py"
    path.write_text(DOCS, encoding="utf-8")
    missing = sorted(msg.split("'")[1] for _, _, msg in StaticCodeAnalyzer.analyze_python_file(str(path), prefer_bandit=False)
                     if "has no docstring" in msg)
    # visit_Call on a class that is not a NodeVisitor, and the property getter, do count.
    assert missing == ["public_api", "size", "visit_Call"]


# --- Static analysis rule table ------------------------------------------------------------

def test_a_new_rule_only_needs_an_entry_in_the_table(tmp_path, monkeypatch):
    """The traversal runs whatever RULES registers: adding a rule never touches CodeQualityChecker."""
    import ast

    from agentes.quality import static_checker

    def global_statement(state, node):
        state.issue(node.lineno, "LOW", f"global {', '.join(node.names)}")

    monkeypatch.setitem(static_checker.RULES, ast.Global, (global_statement,))
    path = tmp_path / "mod.py"
    path.write_text('"""Doc."""\nX = 0\n\n\ndef f():\n    """Doc."""\n    global X\n    X = 1\n', encoding="utf-8")
    checker = static_checker.CodeQualityChecker(str(path))
    checker.visit(ast.parse(path.read_text(encoding="utf-8")))
    assert checker.issues == [(7, "LOW", "global X")]


def test_call_rule_chains_stop_at_the_first_rule_that_decides(tmp_path, monkeypatch):
    """The first rule returning True owns the call: the rest of the chain is not evaluated."""
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


# --- Bandit in chunks: failures, test-file filtering and paths ---------------------------------

def _fake_bandit(monkeypatch, respond):
    """Replace the Bandit subprocess: respond(files) returns its output or raises."""
    import types

    from agentes.quality import static_checker

    def run(cmd, **kwargs):
        return types.SimpleNamespace(stdout=respond(cmd[cmd.index("-q") + 1:]))

    monkeypatch.setattr(static_checker.StaticCodeAnalyzer, "bandit_command", staticmethod(lambda: ["bandit"]))
    monkeypatch.setattr(static_checker.subprocess, "run", run)
    return static_checker.StaticCodeAnalyzer


def _bandit_result(path, test_id, line=3, severity="HIGH", confidence="HIGH"):
    return {"filename": path, "test_id": test_id, "line_number": line, "issue_severity": severity,
            "issue_confidence": confidence, "issue_text": f"text {test_id}"}


def test_bandit_a_failing_chunk_does_not_take_down_the_others(tmp_path, monkeypatch):
    for name in ("a.py", "b.py", "c.py", "d.py"):
        (tmp_path / name).touch()
    files = [str(tmp_path / name) for name in ("a.py", "b.py", "c.py", "d.py")]

    def respond(chunk):
        if chunk[0].endswith("c.py"):
            raise subprocess.TimeoutExpired("bandit", 60)
        return json.dumps({"results": [
            _bandit_result(files[0], "B602"),
            {"test_id": "B101"},                          # no file
            _bandit_result("/somewhere/else.py", "B602"),  # a file nobody asked for
        ]})

    analyzer = _fake_bandit(monkeypatch, respond)
    batch = analyzer._analyze_batch_with_bandit(files, chunk_size=2)
    # The second chunk is missing: its files fall back to the AST engine.
    assert batch == {files[0]: [(3, "CRITICAL", "[bandit] text B602")], files[1]: []}


def test_bandit_ignores_asserts_and_sample_passwords_in_tests(tmp_path, monkeypatch):
    (tmp_path / "test_mod.py").touch()
    path = str(tmp_path / "test_mod.py")
    results = [_bandit_result(path, code, line=n) for n, code in enumerate(("B101", "B105", "B106", "B107", "B602"), 1)]
    analyzer = _fake_bandit(monkeypatch, lambda chunk: json.dumps({"results": results}))
    assert analyzer._analyze_batch_with_bandit([path]) == {path: [(5, "CRITICAL", "[bandit] text B602")]}


def test_bandit_returns_paths_exactly_as_requested(tmp_path, monkeypatch):
    real = tmp_path / "real.py"
    real.write_text("x = 1\n", encoding="utf-8")
    link = tmp_path / "link.py"
    link.symlink_to(real)
    analyzer = _fake_bandit(monkeypatch, lambda chunk: json.dumps({"results": [_bandit_result(str(real), "B602")]}))
    assert analyzer._analyze_batch_with_bandit([str(link)]) == {str(link): [(3, "CRITICAL", "[bandit] text B602")]}


@pytest.mark.parametrize("output", ["", "   ", "not json", "null", "[]", OSError("permission denied"), ValueError("x")])
def test_bandit_without_any_valid_report_returns_none(tmp_path, monkeypatch, output):
    (tmp_path / "a.py").touch()
    path = str(tmp_path / "a.py")

    def respond(chunk):
        if isinstance(output, Exception):
            raise output
        return output

    analyzer = _fake_bandit(monkeypatch, respond)
    assert analyzer._analyze_batch_with_bandit([path]) is None


# --- OpenAPI: parameter types and routes without a leading slash ---------------------------

def test_openapi_translates_annotations_and_normalises_the_route(tmp_path):
    src = tmp_path / "api.py"
    src.write_text(
        "from typing import Dict, List, Optional\nfrom fastapi import FastAPI\napp = FastAPI()\n\n\n"
        '@app.post("items")\ndef create(ids: List[int], note: Optional[str], extra: Dict[str, int], '
        'name: "str", untyped, count: int = 1):\n    """Create items."""\n    return {}\n',
        encoding="utf-8",
    )
    spec = OpenAPIGenerator.generate_openapi_spec(str(src))
    assert list(spec["paths"]) == ["/items"]
    schema = spec["components"]["schemas"]["create_Request"]
    assert schema["properties"] == {
        "ids": {"type": "array", "items": {"type": "integer"}}, "note": {"type": "string"},
        "extra": {"type": "object"}, "name": {"type": "string"}, "untyped": {"type": "string"},
        "count": {"type": "integer"},
    }
    assert "count" not in schema["required"], "a parameter with a default value is not required"
