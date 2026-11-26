"""Tests de la línea base de hallazgos aceptados."""
import json
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentes.common.baseline import Baseline, fingerprint, write_baseline  # noqa: E402
from agentes.common.orchestrator import run_pipeline  # noqa: E402

# Los tokens falsos van partidos en dos literales ("ghp_" "16C7..."): Python los une y el detector
# recibe el token entero, pero el archivo no contiene ninguno completo y la protección de
# secretos de GitHub no bloquea el push.
SECRETO = 'TOKEN = "ghp_' '16C7e42F292c6912E7710c838347Ae178B4a"\n'


def test_la_huella_no_depende_de_la_linea_ni_de_la_ruta_absoluta(tmp_path):
    a = {"file": str(tmp_path / "x.py"), "line": 3, "level": "ALTO", "message": "Línea 3: m", "rule_id": "R"}
    b = dict(a, line=40, message="Línea 40: m")
    assert fingerprint(a, str(tmp_path)) == fingerprint(b, str(tmp_path))
    otra_raiz = tmp_path / "copia"
    c = dict(a, file=str(otra_raiz / "x.py"))
    assert fingerprint(a, str(tmp_path)) == fingerprint(c, str(otra_raiz))


def test_las_repeticiones_de_mas_cuentan_como_nuevas(tmp_path):
    item = {"file": "x.py", "line": 1, "level": "ALTO", "message": "m", "rule_id": "R"}
    path = tmp_path / "b.json"
    write_baseline(str(path), [item], str(tmp_path))
    base = Baseline.load(str(path), str(tmp_path))
    assert base.filter([item, item]) == [item]
    assert base.suppressed == 1


def test_solo_guarda_lo_que_haria_fallar(tmp_path):
    items = [
        {"file": "a.py", "line": 1, "level": "ALTO", "message": "alto", "rule_id": "SAST-ALTO"},
        {"file": "a.py", "line": 2, "level": "BAJO", "message": "bajo", "rule_id": "SOLID-X"},
        {"file": "a.py", "line": 3, "level": "ALTO", "message": "secreto", "rule_id": "SECRET"},
    ]
    saved, skipped = write_baseline(str(tmp_path / "b.json"), items, str(tmp_path))
    assert (saved, skipped) == (2, 1)
    data = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))
    assert data["schema"] == "agentes.baseline.v1" and all(e["file"] == "a.py" for e in data["entries"])


def test_pipeline_con_linea_base_falla_solo_con_hallazgos_nuevos(tmp_path):
    proyecto = tmp_path / "p"
    proyecto.mkdir()
    (proyecto / "config.py").write_text(SECRETO, encoding="utf-8")
    opciones = dict(output_dir=str(tmp_path / "rep"), prefer_bandit=False)

    report, code = run_pipeline(str(proyecto), **opciones)
    assert code == 1
    base = tmp_path / "base.json"
    write_baseline(str(base), report["findings"], str(proyecto))

    report, code = run_pipeline(str(proyecto), baseline=str(base), **opciones)
    assert code == 0, [s for s in report["stages"] if s["status"] == "fail"]
    assert report["baseline"]["suppressed"] >= 1

    (proyecto / "nuevo.py").write_text(SECRETO.replace("TOKEN", "OTRO"), encoding="utf-8")
    _, code = run_pipeline(str(proyecto), baseline=str(base), **opciones)
    assert code == 1, "un secreto nuevo vuelve a hacer fallar"


def test_linea_base_invalida(tmp_path):
    malo = tmp_path / "b.json"
    malo.write_text('{"schema": "otra"}', encoding="utf-8")
    with pytest.raises(ValueError, match="no es una línea base"):
        Baseline.load(str(malo), str(tmp_path))


def test_cli_write_baseline_y_baseline(tmp_path, capsys):
    from agentes import cli

    (tmp_path / "config.py").write_text(SECRETO, encoding="utf-8")
    base = tmp_path / ".agentes-baseline.json"
    rep = str(tmp_path / "rep")
    assert cli.main(["pipeline", str(tmp_path), "-o", rep, "--no-bandit", "--write-baseline", str(base)]) == 0
    assert base.is_file()
    assert cli.main(["pipeline", str(tmp_path), "-o", rep, "--no-bandit", "--baseline", str(base)]) == 0
    assert "aceptados no cuentan" in capsys.readouterr().out
    assert cli.main(["pipeline", str(tmp_path), "--baseline", str(tmp_path / "no.json")]) == 2
