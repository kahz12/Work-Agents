"""Generated tests and --record must never really write, delete, move files or start processes."""
import ast
import os
import subprocess
import sys
import textwrap

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentes.qa.side_effects import ImportMap, classify, is_io  # noqa: E402
from agentes.qa.test_generator import QATestGenerator, UnitTestGenerator  # noqa: E402


def _classify(code, module="mod"):
    tree = ast.parse(code)
    imports = ImportMap.from_tree(tree, module)
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
    return classify(call, imports)


def _unused_variables(code):
    """(test, variable) pairs a test assigns and never reads: what ruff reports as F841."""
    unused = []
    for fn in ast.walk(ast.parse(code)):
        if isinstance(fn, ast.FunctionDef) and fn.name.startswith("test_"):
            names = [n for n in ast.walk(fn) if isinstance(n, ast.Name)]
            read = {n.id for n in names if isinstance(n.ctx, ast.Load)}
            assigned = {n.id for n in names if isinstance(n.ctx, ast.Store)} - {"_"}
            unused.extend((fn.name, name) for name in sorted(assigned - read))
    return unused


@pytest.mark.parametrize("code,expected", [
    ("import shutil\nshutil.rmtree(p)", ("shutil.rmtree", "shutil.rmtree")),
    ("import shutil as sh\nsh.move(a, b)", ("shutil.move", "shutil.move")),
    ("from shutil import rmtree\nrmtree(p)", ("shutil.rmtree", "mod.rmtree")),
    ("from os import remove as rm\nrm(p)", ("os.remove", "mod.rm")),
    ("import os\nos.rename(a, b)", ("os.rename", "os.rename")),
    ("from pathlib import Path\nPath(p).unlink()", ("pathlib.Path.unlink", "pathlib.Path.unlink")),
    ("item.path.write_text('x')", ("pathlib.Path.write_text", "pathlib.Path.write_text")),
    ("open(p, 'w')", ("open", "builtins.open")),
    ("from urllib.request import urlopen\nurlopen(u)", ("urllib.request.urlopen", "mod.urlopen")),
])
def test_detects_side_effects_whatever_the_import_style(code, expected):
    assert _classify(code) == expected


@pytest.mark.parametrize("code", [
    "import os\nos.path.exists(p)", "import os\nos.listdir(p)", "text.replace('a', 'b')", "len(x)",
])
def test_does_not_flag_reads_or_harmless_methods(code):
    assert _classify(code) is None


SOURCE = '''
import os
import shutil as sh
import helpers

CANARY = {canary!r}

def delete_items():
    sh.rmtree(CANARY + ".dir", ignore_errors=False)
    os.remove(CANARY)

def _delete():
    os.remove(CANARY)

def clean_up():
    _delete()
    return True

class Manager:
    def _remove(self):
        os.remove(CANARY)

    def empty(self):
        self._remove()

def delete_indirectly():
    try:
        helpers.delete_elsewhere(CANARY)
    except OSError:
        pass
    return "done"
'''


@pytest.fixture
def dangerous_module(tmp_path):
    canary = tmp_path / "canary.txt"
    canary.write_text("do not delete me", encoding="utf-8")
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "helpers.py").write_text("import os\n\ndef delete_elsewhere(p):\n    os.remove(p)\n", encoding="utf-8")
    (pkg / "cleanup.py").write_text(SOURCE.format(canary=str(canary)), encoding="utf-8")
    return pkg, canary


def test_io_propagates_from_helpers_and_methods(dangerous_module):
    pkg, _ = dangerous_module
    visitor = UnitTestGenerator(str(pkg / "cleanup.py"))
    visitor.visit(ast.parse((pkg / "cleanup.py").read_text(encoding="utf-8")))
    assert visitor.function_meta["delete_items"]["io_calls"] == ["os.remove", "shutil.rmtree"]
    assert visitor.function_meta["clean_up"]["io_calls"] == ["os.remove"], "inherits the I/O of _delete"
    assert visitor.function_meta["Manager.empty"]["io_calls"] == ["os.remove"], "inherits that of self._remove"


@pytest.mark.parametrize("framework", ["unittest", "pytest"])
def test_record_and_generated_suites_leave_the_canary_file_alone(dangerous_module, framework):
    pkg, canary = dangerous_module
    build = QATestGenerator.generate_pytest_suite if framework == "pytest" else QATestGenerator.generate_test_suite
    output = pkg / f"test_cleanup_{framework}.py"
    build(str(pkg / "cleanup.py"), str(output), record=True)

    assert canary.exists(), "--record must not delete anything"
    assert not (pkg / "__pycache__").exists(), "--record writes no bytecode into the analysed project"
    body = output.read_text(encoding="utf-8")
    assert 'patch("os.remove"' in body and 'patch("shutil.rmtree"' in body

    run = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", output.name],
                         capture_output=True, text=True, cwd=str(pkg),
                         env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert run.returncode == 0, run.stdout + run.stderr
    assert canary.exists(), "running the generated suite must not delete anything"
    assert canary.read_text(encoding="utf-8") == "do not delete me"


def test_record_blocks_indirect_io_and_the_test_patches_it(dangerous_module):
    pkg, canary = dangerous_module
    output = pkg / "test_ind.py"
    QATestGenerator.generate_test_suite(str(pkg / "cleanup.py"), str(output), record=True)
    body = output.read_text(encoding="utf-8")
    start = body.index("def test_delete_indirectly")
    block = body[start:body.index("def test_", start + 10)]
    assert 'patch("os.remove"' in block, "the deletion in another module is detected while recording"
    assert "assertEqual(result, 'done')" not in block, "a result obtained with the I/O blocked is not asserted"
    assert canary.exists()


def test_record_warns_when_the_module_writes_on_import(tmp_path):
    src = tmp_path / "writes.py"
    src.write_text(f"open({str(tmp_path / 'log.txt')!r}, 'w').write('x')\n\ndef f():\n    return 1\n", encoding="utf-8")
    from agentes.qa.expected_values import RecordingError
    with pytest.raises(RecordingError, match="builtins.open"):
        QATestGenerator.generate_test_suite(str(src), str(tmp_path / "t.py"), record=True)
    assert not (tmp_path / "log.txt").exists()


# --- subprocess exceptions, fully qualified patch targets and indirect I/O ----------------------

@pytest.mark.parametrize("code", [
    "import subprocess\nsubprocess.TimeoutExpired('cmd', 5)",
    "import subprocess\nsubprocess.CalledProcessError(1, 'cmd')",
    "import subprocess\nsubprocess.SubprocessError('failure')",
    "from subprocess import TimeoutExpired\nTimeoutExpired('cmd', 5)",
    "import subprocess\nsubprocess.CompletedProcess(['ls'], 0)",
    "from subprocess import CompletedProcess\nCompletedProcess(['ls'], 0)",
    "import sqlite3\nsqlite3.OperationalError('locked')",
    "import shutil\nshutil.Error('failure')",
    "import requests\nrequests.RequestException('network')",
])
def test_does_not_flag_exceptions_or_result_objects_of_io_modules(code):
    """Building an exception or a CompletedProcess is not I/O, and patching it would break the except clauses."""
    assert _classify(code) is None


def test_is_io_tells_subprocess_calls_from_its_exceptions():
    assert is_io("subprocess.run") and is_io("subprocess.Popen") and is_io("subprocess.check_output")
    assert not is_io("subprocess.TimeoutExpired")
    assert not is_io("subprocess.CalledProcessError")
    assert not is_io("subprocess.CompletedProcess")


def test_suite_does_not_patch_subprocess_exceptions_or_results(tmp_path):
    """subprocess.run is patched, but TimeoutExpired, CalledProcessError and CompletedProcess stay real."""
    src = tmp_path / "proc.py"
    src.write_text(textwrap.dedent('''
        import subprocess


        def execute(cmd: str) -> str:
            try:
                res = subprocess.run([cmd], capture_output=True, text=True, timeout=5)
                if res.returncode == 1:
                    raise subprocess.CalledProcessError(1, cmd)
                return res.stdout
            except subprocess.TimeoutExpired:
                return "timeout"


        def catch_timeout(cmd: str) -> str:
            try:
                raise subprocess.TimeoutExpired(cmd, 5)
            except subprocess.TimeoutExpired:
                return "timed out"


        def empty_result(cmd: str) -> subprocess.CompletedProcess:
            return subprocess.CompletedProcess([cmd], 0, stdout="", stderr="")
    '''), encoding="utf-8")

    visitor = UnitTestGenerator(str(src))
    visitor.visit(ast.parse(src.read_text(encoding="utf-8")))
    assert visitor.function_meta["execute"]["io_calls"] == ["subprocess.run"]
    assert visitor.function_meta["execute"]["io_always"] is True
    assert visitor.function_meta["catch_timeout"]["io_calls"] == []
    assert visitor.function_meta["empty_result"]["io_calls"] == []

    unit, py = tmp_path / "test_proc_unit.py", tmp_path / "test_proc_pytest.py"
    QATestGenerator.generate_test_suite(str(src), str(unit))
    QATestGenerator.generate_pytest_suite(str(src), str(py))
    for body in (unit.read_text(encoding="utf-8"), py.read_text(encoding="utf-8")):
        assert 'patch("subprocess.run", autospec=True)' in body
        assert 'patch("subprocess.TimeoutExpired"' not in body
        assert 'patch("subprocess.CalledProcessError"' not in body
        assert 'patch("subprocess.CompletedProcess"' not in body

    run = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", unit.name, py.name],
                         capture_output=True, text=True, cwd=str(tmp_path))
    assert run.returncode == 0, run.stdout + run.stderr


def test_patch_uses_the_full_module_name_inside_a_package(tmp_path):
    """from shutil import rmtree in pkg/sub/cleanup.py must patch pkg.sub.cleanup.rmtree, not cleanup.rmtree."""
    canary = tmp_path / "canary.txt"
    canary.write_text("intact", encoding="utf-8")
    canary_dir = tmp_path / "canary.txt.dir"
    canary_dir.mkdir()

    sub = tmp_path / "pkg" / "sub"
    sub.mkdir(parents=True)
    (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (sub / "__init__.py").write_text("", encoding="utf-8")
    src = sub / "cleanup.py"
    src.write_text(textwrap.dedent(f'''
        from os import remove as rm
        from shutil import rmtree

        CANARY = {str(canary)!r}


        def purge() -> None:
            rmtree(CANARY + ".dir")
            rm(CANARY)
    '''), encoding="utf-8")

    visitor = UnitTestGenerator(str(src))
    visitor.visit(ast.parse(src.read_text(encoding="utf-8")))
    assert visitor.module == "pkg.sub.cleanup"
    assert visitor.function_meta["purge"]["io_calls"] == ["pkg.sub.cleanup.rm", "pkg.sub.cleanup.rmtree"]
    assert visitor.function_meta["purge"]["io_always"] is True

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    unit, py = tests_dir / "test_cleanup_unit.py", tests_dir / "test_cleanup_pytest.py"
    QATestGenerator.generate_test_suite(str(src), str(unit))
    QATestGenerator.generate_pytest_suite(str(src), str(py))
    for body in (unit.read_text(encoding="utf-8"), py.read_text(encoding="utf-8")):
        assert 'patch("pkg.sub.cleanup.rm", autospec=True)' in body
        assert 'patch("pkg.sub.cleanup.rmtree", autospec=True)' in body
        assert 'patch("cleanup.' not in body

    run = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", unit.name, py.name],
                         capture_output=True, text=True, cwd=str(tests_dir))
    assert run.returncode == 0, run.stdout + run.stderr
    assert canary.read_text(encoding="utf-8") == "intact" and canary_dir.is_dir()


def test_indirect_io_across_project_modules_is_patched_without_record(tmp_path):
    """I/O performed by helpers in other project modules is detected statically, io_always included."""
    canary = tmp_path / "canary.txt"
    canary.write_text("intact", encoding="utf-8")
    canary_dir = tmp_path / "canary.txt.dir"
    canary_dir.mkdir()

    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "disk.py").write_text(textwrap.dedent('''
        import os
        from shutil import rmtree


        def _delete_dir(path: str) -> None:
            rmtree(path)


        def always_clean(path: str) -> None:
            _delete_dir(path + ".dir")
            os.remove(path)


        def clean_if(path: str, enabled: bool = False) -> bool:
            if enabled:
                os.remove(path)
            return enabled
    '''), encoding="utf-8")
    (pkg / "bridge.py").write_text(textwrap.dedent('''
        from .disk import always_clean


        def delegate(path: str) -> None:
            always_clean(path)
    '''), encoding="utf-8")
    app = pkg / "app.py"
    app.write_text(textwrap.dedent(f'''
        import pkg.bridge as bridge
        from . import disk
        from .disk import clean_if, always_clean as delete_now

        CANARY = {str(canary)!r}


        def delete_directly() -> None:
            delete_now(CANARY)


        def delete_via_module() -> None:
            disk.always_clean(CANARY)


        def delete_via_chain() -> None:
            bridge.delegate(CANARY)


        def _step() -> None:
            disk.always_clean(CANARY)


        def delete_via_helper() -> None:
            _step()


        def delete_conditionally(enabled: bool = False) -> bool:
            return clean_if(CANARY, enabled)
    '''), encoding="utf-8")

    visitor = UnitTestGenerator(str(app))
    visitor.visit(ast.parse(app.read_text(encoding="utf-8")))
    for fn in ("delete_directly", "delete_via_module", "delete_via_chain", "delete_via_helper"):
        assert visitor.function_meta[fn]["io_calls"] == ["os.remove", "pkg.disk.rmtree"]
        assert visitor.function_meta[fn]["io_always"] is True
    assert visitor.function_meta["delete_conditionally"]["io_calls"] == ["os.remove"]
    assert visitor.function_meta["delete_conditionally"]["io_always"] is False
    assert QATestGenerator._recording_calls(visitor) == {}

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    unit, py = tests_dir / "test_app_unit.py", tests_dir / "test_app_pytest.py"
    QATestGenerator.generate_test_suite(str(app), str(unit))
    QATestGenerator.generate_pytest_suite(str(app), str(py))
    for body in (unit.read_text(encoding="utf-8"), py.read_text(encoding="utf-8")):
        assert 'patch("pkg.disk.rmtree", autospec=True)' in body
        assert 'patch("os.remove", autospec=True)' in body
        direct_start = body.index("def test_delete_directly_happy_path")
        direct_end = body.find("def test_", direct_start + 10)
        direct_block = body[direct_start:] if direct_end == -1 else body[direct_start:direct_end]
        assert "io_0.called or io_1.called" in direct_block
        # When the test checks delegation to the doubles the value is not inspected, so no unused result is left.
        assert "result = " not in direct_block
        assert _unused_variables(body) == []
        start = body.index("def test_delete_conditionally_happy_path")
        end = body.find("def test_", start + 10)
        block = body[start:] if end == -1 else body[start:end]
        assert "io_0.called" not in block

    run = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", unit.name, py.name],
                         capture_output=True, text=True, cwd=str(tests_dir))
    assert run.returncode == 0, run.stdout + run.stderr
    assert canary.read_text(encoding="utf-8") == "intact" and canary_dir.is_dir()


def test_indirect_io_with_circular_imports_does_not_loop(tmp_path):
    """Two modules that import each other finish without infinite recursion and keep their I/O."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    mod_a = pkg / "a.py"
    mod_a.write_text(textwrap.dedent('''
        import os
        from .b import fb

        def fa(p: str) -> None:
            os.remove(p)
            fb(p)
    '''), encoding="utf-8")
    (pkg / "b.py").write_text(textwrap.dedent('''
        import os
        from .a import fa

        def fb(p: str) -> None:
            os.unlink(p)
            fa(p)
    '''), encoding="utf-8")

    visitor = UnitTestGenerator(str(mod_a))
    visitor.visit(ast.parse(mod_a.read_text(encoding="utf-8")))
    assert visitor.function_meta["fa"]["io_calls"] == ["os.remove", "os.unlink"]
    assert visitor.function_meta["fa"]["io_always"] is True
