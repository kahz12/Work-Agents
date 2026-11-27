"""YAML validation with PyYAML, and findings suppressed on their own line."""
import json

import pytest

from agentes.common import audits
from agentes.common.findings import Finding
from agentes.common.orchestrator import run_pipeline
from agentes.common.suppressions import InlineSuppressions, markers, rule_names
from agentes.devops.yaml_validator import YAMLValidator

# --- YAML: PyYAML decides what is valid ---------------------------------------------

VALID_WITH_TABS = {
    "comment": "name: ci\n# comment\twith tab\non: push\n",
    "quotes": 'env:\n  MSG: "hello\tworld"\n',
    "literal block": "script: |\n  \tmake test\n  echo done\n",
}


@pytest.mark.parametrize("content", VALID_WITH_TABS.values(), ids=VALID_WITH_TABS.keys())
def test_valid_yaml_with_legitimate_tabs(tmp_path, content):
    path = tmp_path / "ci.yml"
    path.write_text(content, encoding="utf-8")
    assert YAMLValidator.validate_yaml_syntax(str(path)) == (True, [])
    assert audits.audit_yaml(str(path)) == []


def test_yaml_tab_in_indentation_reports_its_line(tmp_path):
    path = tmp_path / "bad.yml"
    path.write_text("steps:\n\t- run: make\n", encoding="utf-8")
    ok, errors = YAMLValidator.validate_yaml_syntax(str(path))
    assert not ok and len(errors) == 1
    assert errors[0].startswith("Line 2: Tab character")
    [finding] = audits.audit_yaml(str(path))
    assert (finding.line, finding.level, finding.rule_id) == (2, "HIGH", "YAML")


def test_yaml_parse_error_reports_its_line(tmp_path):
    path = tmp_path / "bad.yml"
    path.write_text("a: [1, 2\nb: 3\n", encoding="utf-8")
    [finding] = audits.audit_yaml(str(path))
    assert finding.line == 2
    assert "YAML parse error" in finding.message


def test_yaml_with_a_tab_in_a_comment_is_still_audited_for_kubernetes(tmp_path):
    # A legitimate tab in a comment must not prevent the file's Kubernetes audit.
    path = tmp_path / "pod.yaml"
    path.write_text(
        "apiVersion: v1\nkind: Pod\n# comment\twith tab\nspec:\n  containers:\n    - name: app\n      image: nginx\n",
        encoding="utf-8",
    )
    findings = audits.audit_yaml(str(path))
    assert findings and all(f.rule_id == "K8S-POD" for f in findings)


def test_pipeline_does_not_fail_on_valid_yaml_with_tabs(tmp_path):
    (tmp_path / "ci.yml").write_text(VALID_WITH_TABS["comment"], encoding="utf-8")
    (tmp_path / "app.py").write_text('def ok():\n    """Doc."""\n    return 1\n', encoding="utf-8")
    report, code = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "out"), prefer_bandit=False,
                                check_vulnerabilities=False)
    assert code == 0
    assert not [f for f in report["findings"] if f["rule_id"] == "YAML"]


# --- Markers -------------------------------------------------------------------------

@pytest.mark.parametrize("line, expected", [
    ("x = 1", set()),
    ("x = 1  # ordinary comment", set()),
    ("x = 1  # agentes: ignore", {"*"}),
    ("x = 1  # AGENTES: IGNORE - reason", {"*"}),
    ("x = 1  # agentes: ignore[SOLID-GUARD, shell]", {"solid-guard", "shell"}),
    ("x = 1  # agentes: ignored", set()),
    ("x = 1  # noqa", set()),
    ("x = 1  # noqa: E501", set()),
    ("x = 1  # noqa: BLE001 - SDK boundary", {"broad-except", "exception-swallow"}),
    ("x = 1  # noqa: E501, S602", {"shell"}),
    ("x = 1  # nosec", {"sast:*"}),
    ("x = 1  # nosec - fixed command", {"sast:*"}),
    ("x = 1  # nosec B602, B324", {"shell", "weak-hash"}),
    ("x = 1  # nosec: B101", {"assert"}),
])
def test_markers(line, expected):
    assert markers(line) == expected


def test_rule_names_include_rule_id_prefixes_and_rule():
    f = Finding("a.py", 3, "MEDIUM", "[GUARD] Function 'f' reaches 4 levels of nesting (> 3).", "SOLID-GUARD")
    assert {"solid", "solid-guard"} <= rule_names(f)
    sast = Finding("a.py", 3, "MEDIUM", "Use of 'except Exception:'. Catch more specific exceptions instead.",
                   "SAST-MEDIUM")
    assert {"sast", "sast-medium", "broad-except"} <= rule_names(sast)
    doc = Finding("a.py", 1, "LOW", "Public function 'f' has no docstring.", "SAST-LOW")
    assert "docstring" in rule_names(doc)


SOURCE = '''"""Module."""
import subprocess


def f(x):
    """Doc."""
    try:
        return int(x)
    except Exception:  # noqa: BLE001 - SDK boundary
        return None


def g(cmd):
    """Doc."""
    return subprocess.run(cmd, shell=True)  # nosec B602 - fixed command


def h(cmd):
    """Doc."""
    return subprocess.run(cmd, shell=True)  # noqa


def k(cmd):
    """Doc."""
    return subprocess.run(cmd, shell=True)  # agentes: ignore[docstring]


password = "Sup3rS3cretValue!"  # nosec
token = "Sup3rS3cretValue!"  # agentes: ignore[SECRET, hardcoded-secret]
'''


def _lines(findings):
    return sorted(Finding.from_dict(f).line if isinstance(f, dict) else f.line for f in findings)


def test_inline_suppressions_filter_and_count(tmp_path):
    path = tmp_path / "m.py"
    path.write_text(SOURCE, encoding="utf-8")
    raw = audits.sast([str(path)], prefer_bandit=False) + audits.scan_secrets(str(path))
    inline = InlineSuppressions()
    kept = inline.filter(raw)
    lines = _lines(kept)
    assert 9 not in lines            # noqa: BLE001 maps onto broad-except
    assert 15 not in lines           # nosec B602 maps onto shell=True
    assert 20 in lines               # a noqa without codes suppresses nothing
    assert 25 in lines               # the marker only suppresses the rule it names
    assert 28 in lines               # nosec does not suppress secrets
    assert 29 not in lines           # agentes: ignore[SECRET, ...] does
    assert inline.suppressed == len(raw) - len(kept) > 0


def test_inline_keeps_the_item_type_and_unreadable_files_suppress_nothing(tmp_path):
    as_dict = {"file": str(tmp_path / "missing.py"), "line": 1, "level": "HIGH", "message": "m", "rule_id": "X"}
    url = Finding("https://example.com", 0, "MEDIUM", "[HSTS] missing", "HTTP-HEADERS")
    assert InlineSuppressions().filter([as_dict, url]) == [as_dict, url]


def test_pipeline_counts_suppressed_findings_and_does_not_block_on_them(tmp_path):
    (tmp_path / "app.py").write_text(
        '"""Module."""\nimport subprocess\n\n\ndef g(cmd):\n    """Doc."""\n'
        '    return subprocess.run(cmd, shell=True)  # agentes: ignore - fixed command, reviewed\n',
        encoding="utf-8",
    )
    report, code = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "out"), prefer_bandit=False,
                                check_vulnerabilities=False)
    assert code == 0
    assert report["inline_suppressed"] >= 1
    assert not [f for f in report["findings"] if f["line"] == 7]


def test_pipeline_suppresses_solid_finding_and_its_recommendation(tmp_path):
    body = "".join(f"    if x == {i}:\n        return {i}\n" for i in range(14))
    (tmp_path / "app.py").write_text(
        f'"""Module."""\n\n\ndef f(x):  # agentes: ignore[SOLID-OCP]\n    """Doc."""\n{body}    return -1\n',
        encoding="utf-8",
    )
    report, _ = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "out"), prefer_bandit=False,
                             check_vulnerabilities=False)
    assert not [f for f in report["findings"] if f["rule_id"] == "SOLID-OCP"]
    metrics = next(s for s in report["stages"] if s["name"] == "refactor_metrics")
    assert not [r for r in metrics["recommendations"] if "OCP" in r]
    assert report["inline_suppressed"] == 1


def test_cli_analyze_secrets_and_metrics_report_suppressed_findings(tmp_path, capsys):
    from agentes.cli import main

    path = tmp_path / "m.py"
    path.write_text(SOURCE, encoding="utf-8")
    assert main(["analyze", str(path), "--json", "--no-bandit", "--offline", "-o", str(tmp_path / "r")]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["inline_suppressed"] >= 2
    assert 15 not in _lines(data["findings"])

    main(["secrets", str(path), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["inline_suppressed"] == 1 and _lines(data["findings"]) == [28]

    main(["metrics", str(path), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert "inline_suppressed" in data
    assert all(f["rule_id"].startswith(("SOLID-", "PERF", "METRICS")) for f in data["findings"])

    main(["analyze", str(path), "--no-bandit", "--offline", "--no-color", "-o", str(tmp_path / "r")])
    assert "suppressed inline" in capsys.readouterr().out
