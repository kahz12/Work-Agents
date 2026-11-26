"""Los tests generados y --record nunca deben escribir, borrar, mover ni lanzar procesos de verdad."""
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


def _clasifica(codigo, modulo="mod"):
    tree = ast.parse(codigo)
    imports = ImportMap.from_tree(tree, modulo)
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
    return classify(call, imports)


def _variables_sin_usar(codigo):
    """(test, variable) que el test asigna y nunca lee: lo que ruff marca como F841."""
    sin_usar = []
    for fn in ast.walk(ast.parse(codigo)):
        if isinstance(fn, ast.FunctionDef) and fn.name.startswith("test_"):
            nombres = [n for n in ast.walk(fn) if isinstance(n, ast.Name)]
            leidas = {n.id for n in nombres if isinstance(n.ctx, ast.Load)}
            asignadas = {n.id for n in nombres if isinstance(n.ctx, ast.Store)} - {"_"}
            sin_usar.extend((fn.name, nombre) for nombre in sorted(asignadas - leidas))
    return sin_usar


@pytest.mark.parametrize("codigo,esperado", [
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
def test_detecta_efectos_en_cualquier_forma_de_import(codigo, esperado):
    assert _clasifica(codigo) == esperado


@pytest.mark.parametrize("codigo", [
    "import os\nos.path.exists(p)", "import os\nos.listdir(p)", "texto.replace('a', 'b')", "len(x)",
])
def test_no_marca_lecturas_ni_metodos_inofensivos(codigo):
    assert _clasifica(codigo) is None


FUENTE = '''
import os
import shutil as sh
import ayuda

TESTIGO = {testigo!r}

def delete_items():
    sh.rmtree(TESTIGO + ".dir", ignore_errors=False)
    os.remove(TESTIGO)

def _borrar():
    os.remove(TESTIGO)

def limpiar():
    _borrar()
    return True

class Gestor:
    def _quitar(self):
        os.remove(TESTIGO)

    def vaciar(self):
        self._quitar()

def borrar_indirecto():
    try:
        ayuda.borrar_lejos(TESTIGO)
    except OSError:
        pass
    return "hecho"
'''


@pytest.fixture
def modulo_peligroso(tmp_path):
    testigo = tmp_path / "testigo.txt"
    testigo.write_text("no me borres", encoding="utf-8")
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "ayuda.py").write_text("import os\n\ndef borrar_lejos(p):\n    os.remove(p)\n", encoding="utf-8")
    (pkg / "limpieza.py").write_text(FUENTE.format(testigo=str(testigo)), encoding="utf-8")
    return pkg, testigo


def test_la_es_se_propaga_desde_helpers_y_metodos(modulo_peligroso):
    pkg, _ = modulo_peligroso
    visitor = UnitTestGenerator(str(pkg / "limpieza.py"))
    visitor.visit(ast.parse((pkg / "limpieza.py").read_text(encoding="utf-8")))
    assert visitor.function_meta["delete_items"]["io_calls"] == ["os.remove", "shutil.rmtree"]
    assert visitor.function_meta["limpiar"]["io_calls"] == ["os.remove"], "hereda la E/S de _borrar"
    assert visitor.function_meta["Gestor.vaciar"]["io_calls"] == ["os.remove"], "hereda la de self._quitar"


@pytest.mark.parametrize("framework", ["unittest", "pytest"])
def test_record_y_suites_generadas_no_tocan_el_archivo_testigo(modulo_peligroso, framework):
    pkg, testigo = modulo_peligroso
    build = QATestGenerator.generate_pytest_suite if framework == "pytest" else QATestGenerator.generate_test_suite
    salida = pkg / f"test_limpieza_{framework}.py"
    build(str(pkg / "limpieza.py"), str(salida), record=True)

    assert testigo.exists(), "--record no puede borrar nada"
    assert not (pkg / "__pycache__").exists(), "--record no escribe bytecode en el proyecto analizado"
    cuerpo = salida.read_text(encoding="utf-8")
    assert 'patch("os.remove"' in cuerpo and 'patch("shutil.rmtree"' in cuerpo

    run = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", salida.name],
                         capture_output=True, text=True, cwd=str(pkg),
                         env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert run.returncode == 0, run.stdout + run.stderr
    assert testigo.exists(), "ejecutar la suite generada no puede borrar nada"
    assert testigo.read_text(encoding="utf-8") == "no me borres"


def test_record_bloquea_la_es_indirecta_y_el_test_la_sustituye(modulo_peligroso):
    pkg, testigo = modulo_peligroso
    salida = pkg / "test_ind.py"
    QATestGenerator.generate_test_suite(str(pkg / "limpieza.py"), str(salida), record=True)
    cuerpo = salida.read_text(encoding="utf-8")
    inicio = cuerpo.index("def test_borrar_indirecto")
    bloque = cuerpo[inicio:cuerpo.index("def test_", inicio + 10)]
    assert 'patch("os.remove"' in bloque, "el borrado en otro módulo se detecta al grabar"
    assert "assertEqual(result, 'hecho')" not in bloque, "un resultado obtenido con la E/S bloqueada no se afirma"
    assert testigo.exists()


def test_record_avisa_si_el_modulo_escribe_al_importarse(tmp_path):
    src = tmp_path / "escribe.py"
    src.write_text(f"open({str(tmp_path / 'log.txt')!r}, 'w').write('x')\n\ndef f():\n    return 1\n", encoding="utf-8")
    from agentes.qa.expected_values import RecordingError
    with pytest.raises(RecordingError, match="builtins.open"):
        QATestGenerator.generate_test_suite(str(src), str(tmp_path / "t.py"), record=True)
    assert not (tmp_path / "log.txt").exists()


# --- Excepciones de subprocess, patch con nombre completo y E/S indirecta ------------------------

@pytest.mark.parametrize("codigo", [
    "import subprocess\nsubprocess.TimeoutExpired('cmd', 5)",
    "import subprocess\nsubprocess.CalledProcessError(1, 'cmd')",
    "import subprocess\nsubprocess.SubprocessError('fallo')",
    "from subprocess import TimeoutExpired\nTimeoutExpired('cmd', 5)",
    "import subprocess\nsubprocess.CompletedProcess(['ls'], 0)",
    "from subprocess import CompletedProcess\nCompletedProcess(['ls'], 0)",
    "import sqlite3\nsqlite3.OperationalError('bloqueada')",
    "import shutil\nshutil.Error('fallo')",
    "import requests\nrequests.RequestException('red')",
])
def test_no_marca_excepciones_ni_resultados_de_modulos_de_es(codigo):
    """Construir una excepción o un CompletedProcess no es E/S y parchearlo rompe los except."""
    assert _clasifica(codigo) is None


def test_is_io_distingue_llamadas_de_subprocess_de_sus_excepciones():
    assert is_io("subprocess.run") and is_io("subprocess.Popen") and is_io("subprocess.check_output")
    assert not is_io("subprocess.TimeoutExpired")
    assert not is_io("subprocess.CalledProcessError")
    assert not is_io("subprocess.CompletedProcess")


def test_suite_no_sustituye_excepciones_ni_resultados_de_subprocess(tmp_path):
    """subprocess.run se sustituye, pero TimeoutExpired, CalledProcessError y CompletedProcess siguen reales."""
    src = tmp_path / "proc.py"
    src.write_text(textwrap.dedent('''
        import subprocess


        def ejecuta(cmd: str) -> str:
            try:
                res = subprocess.run([cmd], capture_output=True, text=True, timeout=5)
                if res.returncode == 1:
                    raise subprocess.CalledProcessError(1, cmd)
                return res.stdout
            except subprocess.TimeoutExpired:
                return "timeout"


        def captura_timeout(cmd: str) -> str:
            try:
                raise subprocess.TimeoutExpired(cmd, 5)
            except subprocess.TimeoutExpired:
                return "agotado"


        def resultado_vacio(cmd: str) -> subprocess.CompletedProcess:
            return subprocess.CompletedProcess([cmd], 0, stdout="", stderr="")
    '''), encoding="utf-8")

    visitor = UnitTestGenerator(str(src))
    visitor.visit(ast.parse(src.read_text(encoding="utf-8")))
    assert visitor.function_meta["ejecuta"]["io_calls"] == ["subprocess.run"]
    assert visitor.function_meta["ejecuta"]["io_always"] is True
    assert visitor.function_meta["captura_timeout"]["io_calls"] == []
    assert visitor.function_meta["resultado_vacio"]["io_calls"] == []

    unit, py = tmp_path / "test_proc_unit.py", tmp_path / "test_proc_pytest.py"
    QATestGenerator.generate_test_suite(str(src), str(unit))
    QATestGenerator.generate_pytest_suite(str(src), str(py))
    for cuerpo in (unit.read_text(encoding="utf-8"), py.read_text(encoding="utf-8")):
        assert 'patch("subprocess.run", autospec=True)' in cuerpo
        assert 'patch("subprocess.TimeoutExpired"' not in cuerpo
        assert 'patch("subprocess.CalledProcessError"' not in cuerpo
        assert 'patch("subprocess.CompletedProcess"' not in cuerpo

    run = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", unit.name, py.name],
                         capture_output=True, text=True, cwd=str(tmp_path))
    assert run.returncode == 0, run.stdout + run.stderr


def test_patch_usa_el_nombre_completo_del_modulo_dentro_de_un_paquete(tmp_path):
    """from shutil import rmtree en pkg/sub/limpieza.py debe parchear pkg.sub.limpieza.rmtree, no limpieza.rmtree."""
    testigo = tmp_path / "testigo.txt"
    testigo.write_text("intacto", encoding="utf-8")
    testigo_dir = tmp_path / "testigo.txt.dir"
    testigo_dir.mkdir()

    sub = tmp_path / "pkg" / "sub"
    sub.mkdir(parents=True)
    (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (sub / "__init__.py").write_text("", encoding="utf-8")
    src = sub / "limpieza.py"
    src.write_text(textwrap.dedent(f'''
        from os import remove as rm
        from shutil import rmtree

        TESTIGO = {str(testigo)!r}


        def purga() -> None:
            rmtree(TESTIGO + ".dir")
            rm(TESTIGO)
    '''), encoding="utf-8")

    visitor = UnitTestGenerator(str(src))
    visitor.visit(ast.parse(src.read_text(encoding="utf-8")))
    assert visitor.module == "pkg.sub.limpieza"
    assert visitor.function_meta["purga"]["io_calls"] == ["pkg.sub.limpieza.rm", "pkg.sub.limpieza.rmtree"]
    assert visitor.function_meta["purga"]["io_always"] is True

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    unit, py = tests_dir / "test_limpieza_unit.py", tests_dir / "test_limpieza_pytest.py"
    QATestGenerator.generate_test_suite(str(src), str(unit))
    QATestGenerator.generate_pytest_suite(str(src), str(py))
    for cuerpo in (unit.read_text(encoding="utf-8"), py.read_text(encoding="utf-8")):
        assert 'patch("pkg.sub.limpieza.rm", autospec=True)' in cuerpo
        assert 'patch("pkg.sub.limpieza.rmtree", autospec=True)' in cuerpo
        assert 'patch("limpieza.' not in cuerpo

    run = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", unit.name, py.name],
                         capture_output=True, text=True, cwd=str(tests_dir))
    assert run.returncode == 0, run.stdout + run.stderr
    assert testigo.read_text(encoding="utf-8") == "intacto" and testigo_dir.is_dir()


def test_es_indirecta_entre_modulos_del_proyecto_se_sustituye_sin_record(tmp_path):
    """La E/S de helpers en otros módulos del proyecto se detecta estáticamente y se propaga también io_always."""
    testigo = tmp_path / "testigo.txt"
    testigo.write_text("intacto", encoding="utf-8")
    testigo_dir = tmp_path / "testigo.txt.dir"
    testigo_dir.mkdir()

    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "disco.py").write_text(textwrap.dedent('''
        import os
        from shutil import rmtree


        def _borra_dir(ruta: str) -> None:
            rmtree(ruta)


        def limpia_siempre(ruta: str) -> None:
            _borra_dir(ruta + ".dir")
            os.remove(ruta)


        def limpia_si(ruta: str, activo: bool = False) -> bool:
            if activo:
                os.remove(ruta)
            return activo
    '''), encoding="utf-8")
    (pkg / "puente.py").write_text(textwrap.dedent('''
        from .disco import limpia_siempre


        def delega(ruta: str) -> None:
            limpia_siempre(ruta)
    '''), encoding="utf-8")
    app = pkg / "app.py"
    app.write_text(textwrap.dedent(f'''
        import pkg.puente as puente
        from . import disco
        from .disco import limpia_si, limpia_siempre as borra_ya

        TESTIGO = {str(testigo)!r}


        def borra_directo() -> None:
            borra_ya(TESTIGO)


        def borra_por_modulo() -> None:
            disco.limpia_siempre(TESTIGO)


        def borra_en_cadena() -> None:
            puente.delega(TESTIGO)


        def _paso() -> None:
            disco.limpia_siempre(TESTIGO)


        def borra_por_helper() -> None:
            _paso()


        def borra_condicional(activo: bool = False) -> bool:
            return limpia_si(TESTIGO, activo)
    '''), encoding="utf-8")

    visitor = UnitTestGenerator(str(app))
    visitor.visit(ast.parse(app.read_text(encoding="utf-8")))
    for fn in ("borra_directo", "borra_por_modulo", "borra_en_cadena", "borra_por_helper"):
        assert visitor.function_meta[fn]["io_calls"] == ["os.remove", "pkg.disco.rmtree"]
        assert visitor.function_meta[fn]["io_always"] is True
    assert visitor.function_meta["borra_condicional"]["io_calls"] == ["os.remove"]
    assert visitor.function_meta["borra_condicional"]["io_always"] is False
    assert QATestGenerator._recording_calls(visitor) == {}

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    unit, py = tests_dir / "test_app_unit.py", tests_dir / "test_app_pytest.py"
    QATestGenerator.generate_test_suite(str(app), str(unit))
    QATestGenerator.generate_pytest_suite(str(app), str(py))
    for cuerpo in (unit.read_text(encoding="utf-8"), py.read_text(encoding="utf-8")):
        assert 'patch("pkg.disco.rmtree", autospec=True)' in cuerpo
        assert 'patch("os.remove", autospec=True)' in cuerpo
        inicio_dir = cuerpo.index("def test_borra_directo_happy_path")
        fin_dir = cuerpo.find("def test_", inicio_dir + 10)
        bloque_dir = cuerpo[inicio_dir:] if fin_dir == -1 else cuerpo[inicio_dir:fin_dir]
        assert "io_0.called or io_1.called" in bloque_dir
        # Al comprobar que delega en los dobles no se mira el valor: no queda un result sin usar.
        assert "result = " not in bloque_dir
        assert _variables_sin_usar(cuerpo) == []
        inicio = cuerpo.index("def test_borra_condicional_happy_path")
        fin = cuerpo.find("def test_", inicio + 10)
        bloque = cuerpo[inicio:] if fin == -1 else cuerpo[inicio:fin]
        assert "io_0.called" not in bloque

    run = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", unit.name, py.name],
                         capture_output=True, text=True, cwd=str(tests_dir))
    assert run.returncode == 0, run.stdout + run.stderr
    assert testigo.read_text(encoding="utf-8") == "intacto" and testigo_dir.is_dir()


def test_es_indirecta_con_imports_circulares_no_entra_en_bucle(tmp_path):
    """Dos módulos que se importan entre sí terminan sin recursión infinita y conservan su E/S."""
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
