"""Tests for the baseline of accepted findings."""
import json
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentes.common.baseline import Baseline, fingerprint, write_baseline  # noqa: E402
from agentes.common.orchestrator import run_pipeline  # noqa: E402

# Fake tokens are split into two literals ("ghp_" "16C7..."): Python joins them and the detector
# sees the whole token, but the file never contains a complete one, so GitHub's secret
# protection does not block the push.
SECRET = 'TOKEN = "ghp_' '16C7e42F292c6912E7710c838347Ae178B4a"\n'


def test_fingerprint_ignores_line_numbers_and_absolute_paths(tmp_path):
    a = {"file": str(tmp_path / "x.py"), "line": 3, "level": "HIGH", "message": "Line 3: m", "rule_id": "R"}
    b = dict(a, line=40, message="Line 40: m")
    assert fingerprint(a, str(tmp_path)) == fingerprint(b, str(tmp_path))
    other_root = tmp_path / "copy"
    c = dict(a, file=str(other_root / "x.py"))
    assert fingerprint(a, str(tmp_path)) == fingerprint(c, str(other_root))


def test_extra_occurrences_count_as_new(tmp_path):
    item = {"file": "x.py", "line": 1, "level": "HIGH", "message": "m", "rule_id": "R"}
    path = tmp_path / "b.json"
    write_baseline(str(path), [item], str(tmp_path))
    base = Baseline.load(str(path), str(tmp_path))
    assert base.filter([item, item]) == [item]
    assert base.suppressed == 1


def test_only_stores_what_would_fail(tmp_path):
    items = [
        {"file": "a.py", "line": 1, "level": "HIGH", "message": "high", "rule_id": "SAST-HIGH"},
        {"file": "a.py", "line": 2, "level": "LOW", "message": "low", "rule_id": "SOLID-X"},
        {"file": "a.py", "line": 3, "level": "HIGH", "message": "secret", "rule_id": "SECRET"},
    ]
    saved, skipped = write_baseline(str(tmp_path / "b.json"), items, str(tmp_path))
    assert (saved, skipped) == (2, 1)
    data = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))
    assert data["schema"] == "agentes.baseline.v1" and all(e["file"] == "a.py" for e in data["entries"])


def test_pipeline_with_baseline_fails_only_on_new_findings(tmp_path):
    project = tmp_path / "p"
    project.mkdir()
    (project / "config.py").write_text(SECRET, encoding="utf-8")
    options = dict(output_dir=str(tmp_path / "rep"), prefer_bandit=False)

    report, code = run_pipeline(str(project), **options)
    assert code == 1
    base = tmp_path / "base.json"
    write_baseline(str(base), report["findings"], str(project))

    report, code = run_pipeline(str(project), baseline=str(base), **options)
    assert code == 0, [s for s in report["stages"] if s["status"] == "fail"]
    assert report["baseline"]["suppressed"] >= 1

    (project / "new.py").write_text(SECRET.replace("TOKEN", "OTHER"), encoding="utf-8")
    _, code = run_pipeline(str(project), baseline=str(base), **options)
    assert code == 1, "a new secret must fail the pipeline again"


def test_invalid_baseline(tmp_path):
    bad = tmp_path / "b.json"
    bad.write_text('{"schema": "other"}', encoding="utf-8")
    with pytest.raises(ValueError, match="is not an agentes baseline"):
        Baseline.load(str(bad), str(tmp_path))


def test_cli_write_baseline_and_baseline(tmp_path, capsys):
    from agentes import cli

    (tmp_path / "config.py").write_text(SECRET, encoding="utf-8")
    base = tmp_path / ".agentes-baseline.json"
    rep = str(tmp_path / "rep")
    assert cli.main(["pipeline", str(tmp_path), "-o", rep, "--no-bandit", "--write-baseline", str(base)]) == 0
    assert base.is_file()
    assert cli.main(["pipeline", str(tmp_path), "-o", rep, "--no-bandit", "--baseline", str(base)]) == 0
    assert "accepted findings are not counted" in capsys.readouterr().out
    assert cli.main(["pipeline", str(tmp_path), "--baseline", str(tmp_path / "no.json")]) == 2
