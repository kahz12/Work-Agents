"""Categoría de cada hallazgo (seguridad o calidad) en el JSON, el SARIF y la consola."""
import json

import pytest

from agentes.common.findings import Finding
from agentes.common.orchestrator import run_pipeline
from agentes.common.reporting import findings_to_sarif
from agentes.common.rules import QUALITY, SECURITY, category, count_by_category, rule_names


@pytest.mark.parametrize("finding, expected", [
    (Finding("a.py", 1, "ALTO", "Ejecución de subproceso con 'shell=True' (riesgo de inyección de comandos).", "SAST-ALTO"),
     SECURITY),
    (Finding("a.py", 1, "MEDIO", "Posible condición de carrera TOCTOU: 'os.path.exists' seguido de 'open()' para escribir.",
             "SAST-MEDIO"), SECURITY),
    (Finding("a.py", 1, "BAJO", "[bandit] Consider possible security implications associated with pickle.", "SAST-BAJO"),
     SECURITY),
    (Finding("a.py", 1, "ALTO", "Credencial dentro de una URL de conexion", "SECRET"), SECURITY),
    (Finding("Dockerfile", 0, "ALTO", "Sin USER", "DOCKERFILE"), SECURITY),
    (Finding("r.txt", 2, "ALTO", "CVE", "VULN-GHSA-xxxx"), SECURITY),
    (Finding("a.py", 1, "BAJO", "La función pública 'f' carece de docstring explicativo.", "SAST-BAJO"), QUALITY),
    (Finding("a.py", 1, "MEDIO", "Uso de 'except Exception:'. Se recomienda especificar excepciones más concretas.",
             "SAST-MEDIO"), QUALITY),
    (Finding("a.py", 1, "MEDIO", "Uso de 'except Exception: pass' que silencia errores.", "SAST-MEDIO"), QUALITY),
    (Finding("a.py", 1, "MEDIO", "[GUARD] La función 'f' alcanza 4 niveles", "SOLID-GUARD"), QUALITY),
    (Finding("a.py", 1, "MEDIO", "[IMPACTO MEDIO] concatenación", "PERF"), QUALITY),
    (Finding("ci.yml", 2, "ALTO", "Línea 2: Error de parseo YAML", "YAML"), QUALITY),
    (Finding("a.py", 1, "ERROR", "Error de sintaxis: invalid syntax", "SAST-ERROR"), QUALITY),
])
def test_category(finding, expected):
    assert category(finding) == expected


def test_rule_names_incluye_el_rule_id_del_sarif():
    f = Finding("a.py", 1, "ALTO", "Ejecución de subproceso con 'shell=True' (riesgo de inyección de comandos).",
                "SAST-ALTO")
    assert {"sast-shell", "shell", "sast", "sast-alto"} <= rule_names(f)


def test_sarif_etiqueta_seguridad_y_gravedad(tmp_path):
    findings = [
        {"file": "a.py", "line": 3, "level": "ALTO", "rule_id": "SAST-ALTO",
         "message": "Ejecución de subproceso con 'shell=True' (riesgo de inyección de comandos)."},
        {"file": "a.py", "line": 1, "level": "BAJO", "rule_id": "SAST-BAJO",
         "message": "La función pública 'f' carece de docstring explicativo."},
    ]
    path = findings_to_sarif("T", findings, str(tmp_path / "r.sarif"))
    rules = {r["id"]: r for r in json.loads(open(path, encoding="utf-8").read())["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["SAST-SHELL"]["properties"] == {"tags": ["security"], "security-severity": "8.0"}
    assert rules["SAST-DOCSTRING"]["properties"] == {"tags": ["maintainability"]}


def test_pipeline_anota_la_categoria_y_la_cuenta(tmp_path):
    (tmp_path / "app.py").write_text(
        "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n", encoding="utf-8")
    report, _ = run_pipeline(str(tmp_path), output_dir=str(tmp_path / "out"), prefer_bandit=False,
                             check_vulnerabilities=False)
    assert all(f["category"] in (SECURITY, QUALITY) for f in report["findings"])
    assert report["findings_by_category"] == count_by_category(report["findings"])
    assert report["findings_by_category"][SECURITY] >= 1 and report["findings_by_category"][QUALITY] >= 1
    html = open(report["artifacts"]["html"], encoding="utf-8").read()
    assert "<th>Tipo</th>" in html and "Calidad del código" in html


def test_consola_separa_seguridad_de_calidad(tmp_path, capsys):
    from agentes.cli import main

    (tmp_path / "app.py").write_text(
        "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n", encoding="utf-8")
    main(["analyze", str(tmp_path), "--no-bandit", "--offline", "--no-color", "-o", str(tmp_path / "r")])
    out = capsys.readouterr().out
    assert out.index("Seguridad (") < out.index("Calidad del código (")
    assert "shell=True" in out[out.index("Seguridad ("):out.index("Calidad del código (")]

    (tmp_path / "app.py").write_text("def run(cmd):\n    return cmd\n", encoding="utf-8")
    main(["analyze", str(tmp_path), "--no-bandit", "--offline", "--no-color", "-o", str(tmp_path / "r")])
    out = capsys.readouterr().out
    assert "Ningún hallazgo de seguridad." in out and "Seguridad (" not in out

    main(["analyze", str(tmp_path), "--no-bandit", "--offline", "--json", "-o", str(tmp_path / "r")])
    data = json.loads(capsys.readouterr().out)
    assert {f["category"] for f in data["findings"]} == {QUALITY}
