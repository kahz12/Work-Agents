"""Tests del cálculo de resultados esperados en las suites generadas."""
import ast
import os
import subprocess
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentes.qa import expected_values as ev  # noqa: E402
from agentes.qa.test_generator import QATestGenerator  # noqa: E402

FUENTE = '''
import subprocess

def suma(a: int, b: int) -> int:
    """El nombre engaña: no es solo a + b."""
    if a > 0:
        for i in range(b):
            if i % 2:
                a += i
    return a + b

def resta(a, b):
    return a - b

def descuento(precio, porcentaje):
    if porcentaje < 0 or porcentaje > 100:
        raise ValueError("Porcentaje inválido")
    return precio * (1 - porcentaje / 100)

def dividir(x, y):
    return x / (y - 1)

def usa_global(x):
    return x * FACTOR

def ejecuta(cmd):
    subprocess.run(cmd, shell=True)

def no_devuelve(x):
    x = x + 1
'''


def _func(name):
    tree = ast.parse(FUENTE)
    return next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)


@pytest.mark.parametrize("name,args,samples,expected", [
    ("resta", ["a", "b"], ["2", "3"], ("value", "-1", "")),
    ("descuento", ["precio", "porcentaje"], ["100.0", "10.0"], ("value", "90.0", "")),
    ("descuento", ["precio", "porcentaje"], ["100.0", "-1"], ("raises", "ValueError", "Porcentaje inválido")),
    ("dividir", ["x", "y"], ["1", "1"], ("raises", "ZeroDivisionError", "division by zero")),
    ("no_devuelve", ["x"], ["1"], ("value", "None", "")),
])
def test_evaluacion_estatica_de_funciones_puras(name, args, samples, expected):
    assert ev.static_outcome(_func(name), args, samples) == expected


@pytest.mark.parametrize("name,args,samples", [
    ("suma", ["a", "b"], ["2", "3"]),          # bucle
    ("usa_global", ["x"], ["1"]),               # nombre desconocido
    ("ejecuta", ["cmd"], ['"ls"']),             # llamada con efectos
])
def test_no_adivina_cuando_no_puede_calcular(name, args, samples):
    assert ev.static_outcome(_func(name), args, samples) is None


def test_fallback_segun_anotacion_y_cuerpo():
    assert ev.fallback_assertion(_func("suma")) == ("isinstance", "int")
    assert ev.fallback_assertion(_func("no_devuelve")) == ("is_none", "")
    assert ev.fallback_assertion(_func("ejecuta")) == ("is_none", "")
    assert ev.fallback_assertion(_func("resta")) == ("not_none", "")


def test_suite_generada_no_afirma_valores_inventados(tmp_path):
    src = tmp_path / "calc.py"
    src.write_text(FUENTE.replace("    return x * FACTOR\n", "    return x * 2\n"), encoding="utf-8")
    out = tmp_path / "test_calc.py"
    QATestGenerator.generate_test_suite(str(src), str(out))
    body = out.read_text(encoding="utf-8")

    assert "self.assertEqual(result, 5)" not in body, "suma no devuelve 5 con (2, 3): no hay que adivinarlo"
    assert "self.assertIsInstance(result, int)" in body
    assert "self.assertEqual(result, -1)" in body
    assert "self.assertAlmostEqual(result, 90.0)" in body
    assert 'patch("subprocess.run", autospec=True)' in body, "la E/S se sustituye por un doble"

    run = subprocess.run([sys.executable, "-m", "unittest", "-q", str(out.name)],
                         capture_output=True, text=True, cwd=str(tmp_path))
    assert run.returncode == 0, run.stderr


def test_record_graba_el_valor_real_y_salta_la_es(tmp_path):
    src = tmp_path / "calc.py"
    src.write_text(FUENTE.replace("    return x * FACTOR\n", "    return x * 2\n"), encoding="utf-8")
    out = tmp_path / "test_calc.py"
    QATestGenerator.generate_test_suite(str(src), str(out), record=True)
    body = out.read_text(encoding="utf-8")

    assert "self.assertEqual(result, 6)" in body, "suma(2, 3) devuelve 6 de verdad"
    assert "test de caracterización" in body
    run = subprocess.run([sys.executable, "-m", "unittest", "-q", str(out.name)],
                         capture_output=True, text=True, cwd=str(tmp_path))
    assert run.returncode == 0, run.stderr


def test_record_falla_con_mensaje_si_el_modulo_no_importa(tmp_path):
    src = tmp_path / "roto.py"
    src.write_text("import modulo_que_no_existe\n\ndef f(x):\n    return x\n", encoding="utf-8")
    with pytest.raises(ev.RecordingError, match="modulo_que_no_existe"):
        QATestGenerator.generate_test_suite(str(src), str(tmp_path / "t.py"), record=True)


def test_record_no_ejecuta_funciones_con_es(tmp_path):
    marca = tmp_path / "ejecutado.txt"
    src = tmp_path / "peligroso.py"
    src.write_text(
        "import subprocess\n\n"
        "def borrar(cmd):\n"
        f"    subprocess.run(['touch', {str(marca)!r}])\n",
        encoding="utf-8",
    )
    QATestGenerator.generate_test_suite(str(src), str(tmp_path / "t.py"), record=True)
    assert not marca.exists(), "--record no debe llamar a funciones que hacen E/S"
