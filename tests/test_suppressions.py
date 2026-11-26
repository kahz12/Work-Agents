"""Validación YAML con PyYAML y hallazgos silenciados en su propia línea."""
import json

import pytest

from agentes.common import audits
from agentes.common.findings import Finding
from agentes.common.orchestrator import run_pipeline
from agentes.common.suppressions import InlineSuppressions, markers, rule_names
from agentes.devops.yaml_validator import YAMLValidator

# --- YAML: decide PyYAML -------------------------------------------------------------

VALID_WITH_TABS = {
    "comentario": "name: ci\n# comentario\tcon tab\non: push\n",
    "comillas": 'env:\n  MSG: "hola\tmundo"\n',
    "bloque literal": "script: |\n  \tmake test\n  echo fin\n",
}


@pytest.mark.parametrize("content", VALID_WITH_TABS.values(), ids=VALID_WITH_TABS.keys())
def test_yaml_valido_con_tabulaciones_legitimas(tmp_path, content):
    path = tmp_path / "ci.yml"
    path.write_text(content, encoding="utf-8")
    assert YAMLValidator.validate_yaml_syntax(str(path)) == (True, [])
    assert audits.audit_yaml(str(path)) == []


def test_yaml_tab_en_indentacion_indica_su_linea(tmp_path):
    path = tmp_path / "bad.yml"
    path.write_text("steps:\n\t- run: make\n", encoding="utf-8")
    ok, errors = YAMLValidator.validate_yaml_syntax(str(path))
    assert not ok and len(errors) == 1
    assert errors[0].startswith("Línea 2: Tabulación")
    [finding] = audits.audit_yaml(str(path))
    assert (finding.line, finding.level, finding.rule_id) == (2, "ALTO", "YAML")


def test_yaml_error_de_parseo_indica_su_linea(tmp_path):
    path = tmp_path / "bad.yml"
    path.write_text("a: [1, 2\nb: 3\n", encoding="utf-8")
    [finding] = audits.audit_yaml(str(path))
    assert finding.line == 2
    assert "Error de parseo YAML" in finding.message


def test_yaml_con_tab_en_comentario_sigue_auditando_kubernetes(tmp_path):
    # Un tabulador válido en un comentario no debe impedir la auditoría de Kubernetes del archivo.
    path = tmp_path / "pod.yaml"
    path.write_text(
        "apiVersion: v1\nkind: Pod\n# comentario\tcon tab\nspec:\n  containers:\n    - name: app\n      image: nginx\n",
        encoding="utf-8",
    )
    findings = audits.audit_yaml(str(path))
    assert findings and all(f.rule_id == "K8S-POD" for f in findings)


def test_pipeline_no_falla_por_un_yaml_valido_con_tabs(tmp_path):
    (tmp_path / "ci.yml").write_text(VALID_WITH_TABS["comentario"], encoding="utf-8")
    (tmp_path / "app.py").write_text('def ok():\n    """Doc."""\n    return 1\n', encoding="utf-8")
    report, code = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "out"), prefer_bandit=False,
                                check_vulnerabilities=False)
    assert code == 0
    assert not [f for f in report["findings"] if f["rule_id"] == "YAML"]


# --- Marcadores ----------------------------------------------------------------------

@pytest.mark.parametrize("line, expected", [
    ("x = 1", set()),
    ("x = 1  # comentario normal", set()),
    ("x = 1  # agentes: ignore", {"*"}),
    ("x = 1  # AGENTES: IGNORE - motivo", {"*"}),
    ("x = 1  # agentes: ignore[SOLID-GUARD, shell]", {"solid-guard", "shell"}),
    ("x = 1  # agentes: ignored", set()),
    ("x = 1  # noqa", set()),
    ("x = 1  # noqa: E501", set()),
    ("x = 1  # noqa: BLE001 - frontera del SDK", {"broad-except", "exception-swallow"}),
    ("x = 1  # noqa: E501, S602", {"shell"}),
    ("x = 1  # nosec", {"sast:*"}),
    ("x = 1  # nosec - comando fijo", {"sast:*"}),
    ("x = 1  # nosec B602, B324", {"shell", "weak-hash"}),
    ("x = 1  # nosec: B101", {"assert"}),
])
def test_markers(line, expected):
    assert markers(line) == expected


def test_rule_names_incluye_rule_id_prefijos_y_regla():
    f = Finding("a.py", 3, "MEDIO", "[GUARD] La función 'f' alcanza 4 niveles de anidamiento (> 3).", "SOLID-GUARD")
    assert {"solid", "solid-guard"} <= rule_names(f)
    sast = Finding("a.py", 3, "MEDIO", "Uso de 'except Exception:'. Se recomienda especificar excepciones más concretas.",
                   "SAST-MEDIO")
    assert {"sast", "sast-medio", "broad-except"} <= rule_names(sast)
    doc = Finding("a.py", 1, "BAJO", "La función pública 'f' carece de docstring explicativo.", "SAST-BAJO")
    assert "docstring" in rule_names(doc)


SOURCE = '''"""Modulo."""
import subprocess


def f(x):
    """Doc."""
    try:
        return int(x)
    except Exception:  # noqa: BLE001 - frontera del SDK
        return None


def g(cmd):
    """Doc."""
    return subprocess.run(cmd, shell=True)  # nosec B602 - comando fijo


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


def test_inline_suppressions_filtra_y_cuenta(tmp_path):
    path = tmp_path / "m.py"
    path.write_text(SOURCE, encoding="utf-8")
    raw = audits.sast([str(path)], prefer_bandit=False) + audits.scan_secrets(str(path))
    inline = InlineSuppressions()
    kept = inline.filter(raw)
    lines = _lines(kept)
    assert 9 not in lines            # noqa: BLE001 equivale a broad-except
    assert 15 not in lines           # nosec B602 equivale a shell=True
    assert 20 in lines               # un noqa sin códigos no silencia nada
    assert 25 in lines               # el marcador solo silencia la regla indicada
    assert 28 in lines               # nosec no silencia secretos
    assert 29 not in lines           # agentes: ignore[SECRET, ...] sí
    assert inline.suppressed == len(raw) - len(kept) > 0


def test_inline_conserva_el_tipo_y_los_archivos_ilegibles_no_silencian(tmp_path):
    as_dict = {"file": str(tmp_path / "no-existe.py"), "line": 1, "level": "ALTO", "message": "m", "rule_id": "X"}
    url = Finding("https://example.com", 0, "MEDIO", "[HSTS] falta", "HTTP-HEADERS")
    assert InlineSuppressions().filter([as_dict, url]) == [as_dict, url]


def test_pipeline_cuenta_los_silenciados_y_no_los_bloquea(tmp_path):
    (tmp_path / "app.py").write_text(
        '"""Modulo."""\nimport subprocess\n\n\ndef g(cmd):\n    """Doc."""\n'
        '    return subprocess.run(cmd, shell=True)  # agentes: ignore - comando fijo revisado\n',
        encoding="utf-8",
    )
    report, code = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "out"), prefer_bandit=False,
                                check_vulnerabilities=False)
    assert code == 0
    assert report["inline_suppressed"] >= 1
    assert not [f for f in report["findings"] if f["line"] == 7]


def test_pipeline_silencia_solid_y_su_recomendacion(tmp_path):
    body = "".join(f"    if x == {i}:\n        return {i}\n" for i in range(14))
    (tmp_path / "app.py").write_text(
        f'"""Modulo."""\n\n\ndef f(x):  # agentes: ignore[SOLID-OCP]\n    """Doc."""\n{body}    return -1\n',
        encoding="utf-8",
    )
    report, _ = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "out"), prefer_bandit=False,
                             check_vulnerabilities=False)
    assert not [f for f in report["findings"] if f["rule_id"] == "SOLID-OCP"]
    metrics = next(s for s in report["stages"] if s["name"] == "refactor_metrics")
    assert not [r for r in metrics["recommendations"] if "OCP" in r]
    assert report["inline_suppressed"] == 1


def test_cli_analyze_secrets_y_metrics_informan_de_los_silenciados(tmp_path, capsys):
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
    assert "silenciados en su línea" in capsys.readouterr().out
