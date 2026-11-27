"""Category of each finding (security or quality) in the JSON report, the SARIF log and the console."""
import json

import pytest

from agentes.common.findings import Finding
from agentes.common.orchestrator import run_pipeline
from agentes.common.reporting import findings_to_sarif
from agentes.common.rules import QUALITY, SECURITY, category, count_by_category, rule_names

SHELL_TRUE = "Subprocess started with 'shell=True' (command injection risk)."


@pytest.mark.parametrize("finding, expected", [
    (Finding("a.py", 1, "HIGH", SHELL_TRUE, "SAST-HIGH"), SECURITY),
    (Finding("a.py", 1, "MEDIUM", "Possible TOCTOU race condition: 'os.path.exists' followed by 'open()' for writing.",
             "SAST-MEDIUM"), SECURITY),
    (Finding("a.py", 1, "LOW", "[bandit] Consider possible security implications associated with pickle.", "SAST-LOW"),
     SECURITY),
    (Finding("a.py", 1, "HIGH", "Credential inside a connection URL", "SECRET"), SECURITY),
    (Finding("Dockerfile", 0, "HIGH", "No USER", "DOCKERFILE"), SECURITY),
    (Finding("r.txt", 2, "HIGH", "CVE", "VULN-GHSA-xxxx"), SECURITY),
    (Finding("a.py", 1, "LOW", "Public function 'f' has no docstring.", "SAST-LOW"), QUALITY),
    (Finding("a.py", 1, "MEDIUM", "Use of 'except Exception:'. Catch more specific exceptions instead.",
             "SAST-MEDIUM"), QUALITY),
    (Finding("a.py", 1, "MEDIUM", "Use of 'except Exception: pass', which silences errors.", "SAST-MEDIUM"), QUALITY),
    (Finding("a.py", 1, "MEDIUM", "[GUARD] Function 'f' reaches 4 levels", "SOLID-GUARD"), QUALITY),
    (Finding("a.py", 1, "MEDIUM", "[MEDIUM IMPACT] concatenation", "PERF"), QUALITY),
    (Finding("ci.yml", 2, "HIGH", "Line 2: YAML parse error", "YAML"), QUALITY),
    (Finding("a.py", 1, "ERROR", "Syntax error: invalid syntax", "SAST-ERROR"), QUALITY),
])
def test_category(finding, expected):
    assert category(finding) == expected


def test_rule_names_include_the_sarif_rule_id():
    f = Finding("a.py", 1, "HIGH", SHELL_TRUE, "SAST-HIGH")
    assert {"sast-shell", "shell", "sast", "sast-high"} <= rule_names(f)


def test_sarif_tags_security_and_severity(tmp_path):
    findings = [
        {"file": "a.py", "line": 3, "level": "HIGH", "rule_id": "SAST-HIGH", "message": SHELL_TRUE},
        {"file": "a.py", "line": 1, "level": "LOW", "rule_id": "SAST-LOW",
         "message": "Public function 'f' has no docstring."},
    ]
    path = findings_to_sarif("T", findings, str(tmp_path / "r.sarif"))
    rules = {r["id"]: r for r in json.loads(open(path, encoding="utf-8").read())["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["SAST-SHELL"]["properties"] == {"tags": ["security"], "security-severity": "8.0"}
    assert rules["SAST-DOCSTRING"]["properties"] == {"tags": ["maintainability"]}


def test_pipeline_annotates_and_counts_categories(tmp_path):
    (tmp_path / "app.py").write_text(
        "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n", encoding="utf-8")
    report, _ = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "out"), prefer_bandit=False,
                             check_vulnerabilities=False)
    assert all(f["category"] in (SECURITY, QUALITY) for f in report["findings"])
    assert report["findings_by_category"] == count_by_category(report["findings"])
    assert report["findings_by_category"][SECURITY] >= 1 and report["findings_by_category"][QUALITY] >= 1
    html = open(report["artifacts"]["html"], encoding="utf-8").read()
    assert "<th>Category</th>" in html and "Code quality" in html


def test_console_separates_security_from_quality(tmp_path, capsys):
    from agentes.cli import main

    (tmp_path / "app.py").write_text(
        "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n", encoding="utf-8")
    main(["analyze", str(tmp_path), "--no-bandit", "--offline", "--no-color", "-o", str(tmp_path / "r")])
    out = capsys.readouterr().out
    assert out.index("Security (") < out.index("Code quality (")
    assert "shell=True" in out[out.index("Security ("):out.index("Code quality (")]

    (tmp_path / "app.py").write_text("def run(cmd):\n    return cmd\n", encoding="utf-8")
    main(["analyze", str(tmp_path), "--no-bandit", "--offline", "--no-color", "-o", str(tmp_path / "r")])
    out = capsys.readouterr().out
    assert "No security findings." in out and "Security (" not in out

    main(["analyze", str(tmp_path), "--no-bandit", "--offline", "--json", "-o", str(tmp_path / "r")])
    data = json.loads(capsys.readouterr().out)
    assert {f["category"] for f in data["findings"]} == {QUALITY}
