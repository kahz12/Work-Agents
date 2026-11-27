"""
Tests for audits.py: which auditor handles each file, how findings from several engines are
merged, and what happens when a file cannot be read.
"""
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentes.common import audits  # noqa: E402
from agentes.common.findings import Finding  # noqa: E402


@pytest.mark.parametrize("name, kind", [
    ("Dockerfile", "docker"), ("Dockerfile.prod", "docker"), ("app.dockerfile", "docker"),
    ("api.service", "systemd"), ("requirements-dev.txt", "deps"), ("package.json", "deps"),
    ("ci.yml", "yaml"), ("values.yaml", "yaml"), (".env", "env"), (".env.local", "env"), ("prod.env", "env"),
    ("app.log", "logs"), ("test_api.py", "tests"), ("api_test.py", "tests"), ("api.py", None), ("README.md", None),
])
def test_audit_kind_from_file_name(name, kind):
    assert audits.detect_kind(os.path.join("sub", name)) == kind


def test_auditing_an_unknown_kind(tmp_path):
    with pytest.raises(ValueError, match="Unrecognised audit kind"):
        audits.audit_file(str(tmp_path / "README.md"))


def test_auditing_systemd_package_json_and_test_suites(tmp_path):
    service = tmp_path / "api.service"
    service.write_text("[Service]\nExecStart=/usr/bin/api\n", encoding="utf-8")
    assert {f.rule_id for f in audits.audit_file(str(service))} == {"SYSTEMD"}
    pkg = tmp_path / "package.json"
    pkg.write_text('{"dependencies": {"left-pad": "^1.3.0"}}', encoding="utf-8")
    [npm] = audits.audit_file(str(pkg))
    assert (npm.rule_id, npm.level) == ("DEPS-NPM", "MEDIUM") and "left-pad" in npm.message
    suite = tmp_path / "test_x.py"
    suite.write_text("def test_a():\n    assert True\n", encoding="utf-8")
    assert any("WEAK-ASSERT" in f.message for f in audits.audit_file(str(suite)))
    broken = tmp_path / "test_broken.py"
    broken.write_text("def (:\n", encoding="utf-8")
    [error] = audits.audit_file(str(broken))
    assert (error.level, error.rule_id) == ("ERROR", "TEST-QUALITY")


def test_secret_scan_of_a_file_that_could_not_be_scanned(tmp_path, monkeypatch):
    from agentes.defensive.config_manager import ConfigManager

    path = str(tmp_path / "x.py")

    def explode(p):
        raise RuntimeError("disk failure")

    monkeypatch.setattr(ConfigManager, "scan_file_for_secrets", staticmethod(explode))
    [finding] = audits.scan_secrets(path)
    assert (finding.level, finding.rule_id) == ("ERROR", "SECRET-SCAN-ERROR") and "disk failure" in finding.message
    monkeypatch.setattr(ConfigManager, "scan_file_for_secrets", staticmethod(lambda p: [(0, "", "permission denied")]))
    [finding] = audits.scan_secrets(path)
    assert finding.rule_id == "SECRET-SCAN-ERROR" and "permission denied" in finding.message


def test_merge_lists_the_other_engines_that_reported_it():
    ast_finding = Finding("a.py", 4, "HIGH", "Use of 'except Exception: pass', which silences errors.", "SAST-HIGH")
    solid = Finding("a.py", 4, "HIGH", "[EXCEPTION-HYGIENE] The 'except' block silences the exception with 'pass'.",
                    "SOLID-EXCEPTION-HYGIENE")
    bandit = Finding("a.py", 4, "LOW", "[bandit] Try, Except, Pass detected.", "SAST-LOW")
    [merged] = audits.merge_duplicates([ast_finding, solid, bandit])
    assert merged.message.startswith("Use of 'except Exception: pass'")
    assert merged.message.endswith("Also detected by: SOLID, bandit.")
    assert merged.level == "MEDIUM", "swallowing exceptions is calibrated as reliability, not security"
