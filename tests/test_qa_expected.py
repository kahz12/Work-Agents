"""Tests for how expected results are computed in the generated suites."""
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

SOURCE = '''
import subprocess

def add(a: int, b: int) -> int:
    """The name is misleading: this is not just a + b."""
    if a > 0:
        for i in range(b):
            if i % 2:
                a += i
    return a + b

def subtract(a, b):
    return a - b

def discount(price, percent):
    if percent < 0 or percent > 100:
        raise ValueError("Invalid percentage")
    return price * (1 - percent / 100)

def divide(x, y):
    return x / (y - 1)

def uses_global(x):
    return x * FACTOR

def execute(cmd):
    subprocess.run(cmd, shell=True)

def returns_nothing(x):
    x = x + 1
'''


def _func(name):
    tree = ast.parse(SOURCE)
    return next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)


@pytest.mark.parametrize("name,args,samples,expected", [
    ("subtract", ["a", "b"], ["2", "3"], ("value", "-1", "")),
    ("discount", ["price", "percent"], ["100.0", "10.0"], ("value", "90.0", "")),
    ("discount", ["price", "percent"], ["100.0", "-1"], ("raises", "ValueError", "Invalid percentage")),
    ("divide", ["x", "y"], ["1", "1"], ("raises", "ZeroDivisionError", "division by zero")),
    ("returns_nothing", ["x"], ["1"], ("value", "None", "")),
])
def test_static_evaluation_of_pure_functions(name, args, samples, expected):
    assert ev.static_outcome(_func(name), args, samples) == expected


@pytest.mark.parametrize("name,args,samples", [
    ("add", ["a", "b"], ["2", "3"]),            # loop
    ("uses_global", ["x"], ["1"]),              # unknown name
    ("execute", ["cmd"], ['"ls"']),             # call with side effects
])
def test_does_not_guess_when_it_cannot_compute(name, args, samples):
    assert ev.static_outcome(_func(name), args, samples) is None


def test_fallback_from_annotation_and_body():
    assert ev.fallback_assertion(_func("add")) == ("isinstance", "int")
    assert ev.fallback_assertion(_func("returns_nothing")) == ("is_none", "")
    assert ev.fallback_assertion(_func("execute")) == ("is_none", "")
    assert ev.fallback_assertion(_func("subtract")) == ("not_none", "")


def test_generated_suite_asserts_no_made_up_values(tmp_path):
    src = tmp_path / "calc.py"
    src.write_text(SOURCE.replace("    return x * FACTOR\n", "    return x * 2\n"), encoding="utf-8")
    out = tmp_path / "test_calc.py"
    QATestGenerator.generate_test_suite(str(src), str(out))
    body = out.read_text(encoding="utf-8")

    assert "self.assertEqual(result, 5)" not in body, "add(2, 3) does not return 5; it must not be guessed"
    assert "self.assertIsInstance(result, int)" in body
    assert "self.assertEqual(result, -1)" in body
    assert "self.assertAlmostEqual(result, 90.0)" in body
    assert 'patch("subprocess.run", autospec=True)' in body, "the I/O is replaced by a test double"

    run = subprocess.run([sys.executable, "-m", "unittest", "-q", str(out.name)],
                         capture_output=True, text=True, cwd=str(tmp_path))
    assert run.returncode == 0, run.stderr


def test_record_captures_the_real_value_and_skips_io(tmp_path):
    src = tmp_path / "calc.py"
    src.write_text(SOURCE.replace("    return x * FACTOR\n", "    return x * 2\n"), encoding="utf-8")
    out = tmp_path / "test_calc.py"
    QATestGenerator.generate_test_suite(str(src), str(out), record=True)
    body = out.read_text(encoding="utf-8")

    assert "self.assertEqual(result, 6)" in body, "add(2, 3) really returns 6"
    assert "characterisation test" in body
    run = subprocess.run([sys.executable, "-m", "unittest", "-q", str(out.name)],
                         capture_output=True, text=True, cwd=str(tmp_path))
    assert run.returncode == 0, run.stderr


def test_record_fails_with_a_message_when_the_module_does_not_import(tmp_path):
    src = tmp_path / "broken.py"
    src.write_text("import module_that_does_not_exist\n\ndef f(x):\n    return x\n", encoding="utf-8")
    with pytest.raises(ev.RecordingError, match="module_that_does_not_exist"):
        QATestGenerator.generate_test_suite(str(src), str(tmp_path / "t.py"), record=True)


def test_record_does_not_run_functions_with_io(tmp_path):
    marker = tmp_path / "executed.txt"
    src = tmp_path / "dangerous.py"
    src.write_text(
        "import subprocess\n\n"
        "def delete(cmd):\n"
        f"    subprocess.run(['touch', {str(marker)!r}])\n",
        encoding="utf-8",
    )
    QATestGenerator.generate_test_suite(str(src), str(tmp_path / "t.py"), record=True)
    assert not marker.exists(), "--record must not call functions that perform I/O"
