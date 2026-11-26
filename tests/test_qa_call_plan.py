"""
Cómo llaman a cada objetivo las suites generadas: valores de ejemplo según el tipo, construcción
de objetos, tipos de método, import del módulo analizado, excepciones que la suite puede nombrar
y el análisis de None. Al final, suites completas generadas para un paquete de ejemplo con
imports relativos, clases de datos, E/S, red y un punto de entrada de línea de órdenes, que
tienen que pasar sin tocar nada.
"""
import ast
import os
import socket
import subprocess
import sys
import textwrap

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentes.qa import ast_inspector as ai  # noqa: E402
from agentes.qa import call_plan as cp  # noqa: E402
from agentes.qa import emitters  # noqa: E402
from agentes.qa.project import ProjectIndex  # noqa: E402
from agentes.qa.test_generator import QATestGenerator  # noqa: E402


def _ctx(source: str = "") -> cp.SampleContext:
    return cp.SampleContext(ast.parse(textwrap.dedent(source)))


def _ann(text: str) -> ast.AST:
    return ast.parse(text, mode="eval").body


def _func(source: str):
    return ast.parse(textwrap.dedent(source)).body[0]


# --- Valores de ejemplo según la anotación -------------------------------------------------------

@pytest.mark.parametrize("anotacion, expr, item", [
    ("int", "1", None),
    ("List[int]", "[1]", "1"),
    ("Sequence[float]", "[1.0]", "1.0"),
    ("Dict[str, int]", '{"sample": 1}', '"sample": 1'),
    ("Set[str]", '{"sample"}', '"sample"'),
    ("Optional[str]", '"sample"', None),
    ("int | None", "1", None),
    ("Union[None, int]", "1", None),
    ('Literal["a", "b"]', "'a'", None),
    ("'int'", "1", None),
    ("Type[int]", "int", None),
    ("Iterator[int]", "iter([])", None),
    # Any dentro de un contenedor admite cualquier valor.
    ("Tuple[str, Any]", '("sample", "sample",)', None),
    # Una lista de elementos que no se saben construir sigue siendo válida vacía.
    ("List[Raro]", "[]", None),
])
def test_valor_de_ejemplo_segun_la_anotacion(anotacion, expr, item):
    sample = cp.annotation_sample(_ann(anotacion), _ctx())
    assert sample is not None
    assert (sample.expr, sample.item, sample.assumed) == (expr, item, False)


@pytest.mark.parametrize("anotacion", ["Raro", "Tuple[str, Raro]", "Type[Raro]"])
def test_sin_valor_de_ejemplo_si_el_tipo_no_se_sabe_construir(anotacion):
    """Una tupla tiene aridad fija: si falta un elemento, no hay ejemplo válido."""
    assert cp.annotation_sample(_ann(anotacion), _ctx()) is None


def test_tipos_de_la_biblioteca_estandar_anotan_su_modulo():
    ctx = _ctx()
    assert cp.annotation_sample(_ann("Path"), ctx).expr == 'pathlib.Path("sample.txt")'
    assert cp.annotation_sample(_ann("datetime.date"), ctx).expr == "datetime.date(2024, 1, 1)"
    assert ctx.used_modules == {"pathlib", "datetime"}


def test_alias_de_tipo_del_modulo():
    ctx = _ctx("from typing import List\nIds = List[int]\n")
    assert cp.annotation_sample(_ann("Ids"), ctx).expr == "[1]"


def test_valores_limite_de_un_contenedor_tipado_respetan_el_tipo_del_elemento():
    lista = cp.Sample("[1]", "list", False, "1")
    assert cp.boundary_values(lista, "ids") == [("empty_list", "[]"), ("single_elem", "[1]"),
                                                ("two_elems", "[1, 1]")]
    tabla = cp.Sample('{"sample": 1}', "dict", False, '"sample": 1')
    assert cp.boundary_values(tabla, "tabla") == [("empty_dict", "{}"), ("single_kv", '{"sample": 1}')]
    assert cp.boundary_values(cp.Sample("Item()", "object", False), "item") == []


# --- Construcción de objetos ---------------------------------------------------------------------

MODELOS = '''
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, NamedTuple, Protocol


class Color(Enum):
    ROJO = 1


@dataclass
class Item:
    nombre: str
    cantidad: int = 1
    etiquetas: List[str] = field(default_factory=list)


class Punto(NamedTuple):
    x: float
    y: float


class Base(ABC):
    @abstractmethod
    def area(self) -> float: ...


class Cuadrado(Base):
    def __init__(self, lado: float, *, color: Color):
        self.lado = lado

    def area(self) -> float:
        return self.lado ** 2


class Dibujable(Protocol):
    def dibuja(self) -> None: ...
'''


@pytest.mark.parametrize("clase, esperado", [
    ("Color", "list(Color)[0]"),
    # Los campos con valor por defecto (también default_factory) no se pasan.
    ("Item", 'Item("alice")'),
    ("Punto", "Punto(1, 1)"),
    ("Cuadrado", "Cuadrado(1, color=list(Color)[0])"),
    ("Base", None),
    ("Dibujable", None),
])
def test_construccion_de_clases_del_modulo(clase, esperado):
    assert cp.construct_expr(clase, _ctx(MODELOS)) == esperado


def test_una_clase_abstracta_se_omite_con_su_motivo():
    expr, motivo = cp.instantiation_for("Base", _ctx(MODELOS))
    assert expr is None and motivo == "Base es abstracta: no se puede instanciar."


def test_tipos_de_metodo():
    clase = _func('''
        class C:
            @property
            def p(self): ...
            @p.setter
            def p(self, v): ...
            @staticmethod
            def s(): ...
            @classmethod
            def c(cls): ...
            @functools.cached_property
            def cp(self): ...
            @typing.overload
            def o(self, x: int) -> int: ...
            @abc.abstractmethod
            def a(self): ...
            def m(self): ...
    ''')
    kinds = [ai.method_kind(item) for item in clase.body]
    assert kinds == ["property", "setter", "static", "class", "property", "overload", "abstract", "method"]


def test_receptor_de_metodos_estaticos_propiedades_y_metodos_normales():
    ctx = _ctx('''
        class C:
            def __init__(self, x: int):
                self.x = x
            @staticmethod
            def s(): ...
            @property
            def p(self): ...
            def m(self): ...
    ''')
    assert cp.receiver_for("C", "s", ctx) == cp.Receiver("C.s", None, False, None, "static")
    assert cp.receiver_for("C", "p", ctx) == cp.Receiver("obj.p", "C(1)", False, None, "property")
    assert cp.receiver_for("C", "m", ctx).setup == "C(1)"


def test_plan_de_llamada():
    """Solo se pasan los obligatorios; los literales por defecto entran en la evaluación estática."""
    plan = cp.plan_call(_func("def f(a: int, b, c=3, *, d: str, e=None):\n    return b.lower()\n"), _ctx())
    assert plan.arg_str == '2, "sample", d="sample"'
    assert plan.static_names == ["a", "b", "c", "d", "e"]
    assert plan.static_values == ["2", '"sample"', "3", '"sample"', "None"]
    # b no tiene tipo: su valor sale de cómo lo usa el cuerpo (.lower()) y es un supuesto.
    assert plan.assumed == ["b"] and plan.missing == []
    assert plan.with_first("None") == 'None, "sample", d="sample"'


def test_plan_de_llamada_con_un_tipo_que_no_se_sabe_construir():
    plan = cp.plan_call(_func("def f(x: Raro):\n    return x\n"), _ctx())
    assert plan.missing == ["x (Raro)"] and plan.first is None


# --- Nombres del módulo y excepciones ------------------------------------------------------------

def test_nombres_que_define_seguro_el_modulo():
    tree = ast.parse(textwrap.dedent('''
        import os.path
        import json as js
        from typing import TYPE_CHECKING
        from otro import *
        try:
            import yaml
        except ImportError:
            yaml = None
        try:
            import tomllib
        except ImportError:
            pass
        if TYPE_CHECKING:
            from foo import Bar
        if sys.version_info >= (3, 11):
            A = 1
        else:
            A = 2
        CONST: int = 1
        class K: ...
        def f(): ...
    '''))
    assert cp.module_bindings(tree.body) == {"os", "js", "TYPE_CHECKING", "yaml", "A", "CONST", "K", "f"}


@pytest.mark.parametrize("nombre, importar", [
    ("ValueError", ""),
    ("ErrorPropio", "ErrorPropio"),
    ("binascii.Error", "binascii"),
    # os ya lo importa la cabecera de la suite.
    ("os.error", ""),
    # Un nombre del módulo tapa al de builtins.
    ("TimeoutError", "TimeoutError"),
    ("exc", None),
    ("self.error", None),
    ("print", None),
    ("json.JSONDecodeError", None),
])
def test_como_nombra_la_suite_cada_excepcion(nombre, importar):
    ctx = _ctx("import binascii\nimport os\nclass ErrorPropio(Exception): ...\nclass TimeoutError(Exception): ...\n")
    assert ctx.exception_import(nombre) == importar


def test_usar_una_excepcion_anota_lo_que_hay_que_importar():
    ctx = _ctx("import binascii\n")
    assert ctx.use_exception("binascii.Error") and ctx.used_names == {"binascii"}
    assert ctx.use_exception("ValueError") and ctx.used_names == {"binascii"}
    assert not ctx.use_exception("exc")


def test_las_excepciones_y_los_assert_de_los_helpers_se_propagan_a_quien_los_llama(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(textwrap.dedent('''
        class ErrorPropio(Exception):
            pass

        def _valida(x):
            if not x:
                raise ErrorPropio("vacío")

        def publica(x):
            _valida(x)
            return x

        def _positivo(x):
            assert x > 0

        def mitad(x):
            _positivo(x)
            return x // 2
    '''), encoding="utf-8")
    visitor = ai.UnitTestGenerator(str(src))
    visitor.visit(ast.parse(src.read_text(encoding="utf-8")))
    meta = visitor.function_meta["publica"]
    assert meta["raises"] == [] and meta["raises_reachable"] == [("ErrorPropio", "vacío")]
    assert not meta["bare_assert"] and visitor.function_meta["mitad"]["bare_assert"]


# --- Import del módulo analizado -----------------------------------------------------------------

def test_nombre_del_modulo_dentro_de_un_paquete(tmp_path):
    sub = tmp_path / "pkg" / "sub"
    sub.mkdir(parents=True)
    for init in (tmp_path / "pkg" / "__init__.py", sub / "__init__.py"):
        init.write_text("", encoding="utf-8")
    (sub / "mod.py").write_text("", encoding="utf-8")
    (tmp_path / "suelto.py").write_text("", encoding="utf-8")
    assert cp.module_import(str(sub / "mod.py")) == ("pkg.sub.mod", str(tmp_path))
    assert cp.module_import(str(sub / "__init__.py")) == ("pkg.sub", str(tmp_path))
    assert cp.module_import(str(tmp_path / "suelto.py")) == ("suelto", str(tmp_path))


def test_cabecera_de_import_relativa_a_la_suite(tmp_path):
    lines = cp.import_header(str(tmp_path / "pkg" / "mod.py"), str(tmp_path / "tests" / "test_mod.py"),
                             {"b", "a"}, {"pathlib"})
    assert "import pathlib" in lines
    assert '_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../pkg"))' in lines
    assert lines[-1] == "from mod import a, b  # noqa: E402"


# --- Análisis del cuerpo -------------------------------------------------------------------------

@pytest.mark.parametrize("source, esperado", [
    ("def main():\n    return sys.argv[1:]\n", True),
    ("def main():\n    sys.exit(1)\n", True),
    ("def main():\n    raise SystemExit(2)\n", True),
    ("def main():\n    exit()\n", True),
    ("def f(argv):\n    return argv\n", False),
])
def test_punto_de_entrada_de_linea_de_ordenes(source, esperado):
    assert ai.is_cli_entrypoint(_func(source)) is esperado


@pytest.mark.parametrize("source, esperado", [
    ("def f(x):\n    return len(x)\n", {"x"}),
    ("def f(x):\n    if x is None:\n        return 0\n    return x + 1\n", set()),
    ("def f(x):\n    yield len(x)\n", set()),
    ("def f(x):\n    try:\n        return len(x)\n    except TypeError:\n        return 0\n", set()),
])
def test_parametros_que_el_cuerpo_usa_sin_comprobar_si_son_none(source, esperado):
    assert ai.none_unsafe_params(_func(source)) == esperado


def test_assert_sin_mensaje():
    assert ai.has_bare_assert(_func("def f(x):\n    assert x > 0\n    return x\n"))
    assert not ai.has_bare_assert(_func("def f(x):\n    assert x > 0, 'positivo'\n    return x\n"))
    assert not ai.has_bare_assert(None)


# --- Aislamiento de las suites generadas ---------------------------------------------------------

def _isolation_namespace() -> dict:
    import io

    namespace = {"io": io, "socket": socket}
    exec("\n".join(emitters._ISOLATION_HELPERS), namespace)  # agentes: ignore[dynamic-exec] - código fijo del generador
    return namespace


def test_el_aislamiento_bloquea_la_red_salvo_las_conexiones_locales():
    ns = _isolation_namespace()
    with pytest.raises(socket.gaierror, match="Red bloqueada"):
        ns["_qa_local_getaddrinfo"]("example.com", 80)
    assert ns["_qa_local_getaddrinfo"]("127.0.0.1", 80)
    with socket.socket() as sock, pytest.raises(OSError, match="Red bloqueada"):
        ns["_qa_local_connect"](sock, ("203.0.113.1", 80))
    with socket.socket() as server, socket.socket() as client:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        ns["_qa_local_connect"](client, server.getsockname())


def test_el_aislamiento_da_una_entrada_estandar_vacia():
    stdin = _isolation_namespace()["_qa_empty_stdin"]()
    assert stdin.readline() == "" and stdin.buffer.read() == b""


# --- Suites completas sobre un paquete de ejemplo ------------------------------------------------

UTIL = '''import urllib.request


def doble(x: int) -> int:
    return x * 2


def consulta(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.read()
'''

PAQUETE = '''"""Módulo de ejemplo para las suites generadas."""
import binascii
import os
import sys
from dataclasses import dataclass
from enum import Enum
from typing import List

from .util import consulta, doble


class ErrorDeValidacion(Exception):
    pass


class Color(Enum):
    ROJO = 1
    VERDE = 2


@dataclass
class Item:
    nombre: str
    cantidad: int = 1


class Inventario:
    def __init__(self, items: List[Item]):
        self.items = items

    @property
    def total(self) -> int:
        return sum(i.cantidad for i in self.items)

    @staticmethod
    def vacio() -> "Inventario":
        return Inventario([])

    @classmethod
    def de_nombres(cls, nombres: List[str]) -> "Inventario":
        return cls([Item(n) for n in nombres])

    def nombres(self) -> List[str]:
        return [i.nombre for i in self.items]


def cantidades(items: List[Item]) -> List[int]:
    return [doble(i.cantidad) for i in items]


def pinta(color: Color) -> str:
    return color.name.lower()


def _comprueba(texto: str) -> None:
    if not texto.strip():
        raise ErrorDeValidacion("texto vacío")


def normaliza(texto: str) -> str:
    _comprueba(texto)
    return texto.strip()


def codifica(datos: bytes) -> bytes:
    if len(datos) % 2:
        raise binascii.Error("longitud impar")
    return binascii.hexlify(datos)


def lee(ruta: str) -> str:
    with open(ruta, encoding="utf-8") as f:
        return f.read()


def borra_si(ruta: str, activo: bool = False) -> bool:
    if activo:
        os.remove(ruta)
    return activo


def pregunta() -> str:
    return sys.stdin.readline().strip()


def estado(url: str = "http://example.com/") -> str:
    try:
        consulta(url)
    except OSError as exc:
        return str(exc)
    return "conectado"


def main() -> int:
    print(Inventario.de_nombres(sys.argv[1:]).nombres())
    return 0
'''


@pytest.fixture
def paquete(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "util.py").write_text(UTIL, encoding="utf-8")
    (pkg / "modelos.py").write_text(PAQUETE, encoding="utf-8")
    (tmp_path / "tests").mkdir()
    return tmp_path


def _run(args, cwd):
    return subprocess.run([sys.executable, "-m", *args], capture_output=True, text=True, cwd=str(cwd))


@pytest.mark.parametrize("framework", ["pytest", "unittest"])
def test_suite_de_un_paquete_pasa_sin_tocarla(paquete, framework):
    """La suite vive en otro directorio: importa el paquete por su nombre completo desde su raíz."""
    suite = paquete / "tests" / f"test_modelos_{framework}.py"
    generate = QATestGenerator.generate_pytest_suite if framework == "pytest" else QATestGenerator.generate_test_suite
    generate(str(paquete / "pkg" / "modelos.py"), str(suite))
    body = suite.read_text(encoding="utf-8")

    assert "from pkg.modelos import (  # noqa: E402" in body
    # Clases del módulo construidas con valores de su tipo, enums y métodos estáticos y de clase.
    assert "cantidades([Item(\"alice\")])" in body and "pinta(list(Color)[0])" in body
    assert "obj = Inventario([Item(\"alice\")])" in body and "Inventario.vacio()" in body
    # open() se sustituye por un archivo vacío, no por un MagicMock que nunca termina de leerse.
    assert 'patch("builtins.open", new=mock_open(read_data=""))' in body
    # main lee sys.argv: se omite con su motivo y no se importa.
    assert "Lee sys.argv o termina el proceso" in body
    assert "    main,\n" not in body

    run = _run(["pytest", "-q", "-rs", "-p", "no:cacheprovider", suite.name], paquete / "tests")
    assert run.returncode == 0, run.stdout + run.stderr


def test_suite_pytest_de_un_paquete_nombra_las_excepciones_del_modulo(paquete):
    suite = paquete / "tests" / "test_modelos.py"
    QATestGenerator.generate_pytest_suite(str(paquete / "pkg" / "modelos.py"), str(suite))
    body = suite.read_text(encoding="utf-8")
    # La excepción de un helper privado y la de un módulo que importa el analizado.
    assert "    ErrorDeValidacion,\n" in body and "    binascii,\n" in body
    assert "except (ArithmeticError, AssertionError, ErrorDeValidacion, LookupError" in body
    assert "LookupError, OSError, TypeError, ValueError, binascii.Error) as exc:" in body
    # La propiedad se lee, no se llama, y una lista tipada varía su número de elementos.
    assert "result = obj.total\n" in body
    assert 'ids=["empty_list", "single_elem", "two_elems"]' in body
    # Si la función no llega a la E/S sustituida, el test de fallo de E/S se omite.
    assert "Con los valores de ejemplo la función no llega a la E/S sustituida." in body
    assert "@pytest.fixture(autouse=True)\ndef _qa_isolation(monkeypatch):" in body

    run = _run(["pytest", "-q", "-rs", "-p", "no:cacheprovider", suite.name], paquete / "tests")
    assert run.returncode == 0, run.stdout + run.stderr
    assert "no llega a la E/S sustituida" in run.stdout


def test_suite_con_valores_supuestos_se_omite_si_no_encajan(tmp_path):
    """Sin tipos ni pistas, el valor de x es un supuesto: si no le sirve a la función, se omite."""
    src = tmp_path / "supuestos.py"
    src.write_text("def usa(x):\n    return x.campo\n", encoding="utf-8")
    suite = tmp_path / "test_supuestos.py"
    QATestGenerator.generate_pytest_suite(str(src), str(suite))
    body = suite.read_text(encoding="utf-8")
    assert "Valores de ejemplo supuestos para x" in body
    run = _run(["pytest", "-q", "-rs", "-p", "no:cacheprovider", suite.name], tmp_path)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "no encajan con la función" in run.stdout


def test_suite_con_asserts_de_validacion_los_acepta_como_rechazo(tmp_path):
    src = tmp_path / "validado.py"
    # El valor nominal cumple la precondición y el límite -1 no: el assert sin texto es un rechazo válido.
    src.write_text("def mitad(n: int) -> int:\n    assert n >= 0\n    return n // 2\n", encoding="utf-8")
    suite = tmp_path / "test_validado.py"
    QATestGenerator.generate_pytest_suite(str(src), str(suite))
    body = suite.read_text(encoding="utf-8")
    assert "assert str(exc) or isinstance(exc, (AssertionError,))" in body
    run = _run(["pytest", "-q", "-p", "no:cacheprovider", suite.name], tmp_path)
    assert run.returncode == 0, run.stdout + run.stderr


# --- Entrada inválida y valores límite -----------------------------------------------------------

@pytest.mark.parametrize("source, esperado", [
    # Un raise bajo un if que menciona el parámetro, con su mensaje literal.
    ("def f(porcentaje):\n    if porcentaje < 0:\n        raise ValueError('negativo')\n    return 1\n",
     [("ValueError", "negativo")]),
    # También en un elif, en orden de aparición, y con un assert.
    ("def f(porcentaje):\n    assert porcentaje is not None\n    if porcentaje > 100:\n        raise ValueError('alto')\n"
     "    elif porcentaje < 0:\n        raise KeyError()\n    return 1\n",
     [("AssertionError", ""), ("ValueError", "alto"), ("KeyError", "")]),
    ("def f(path):\n    assert path, 'ruta vacía'\n    return path\n", [("AssertionError", "ruta vacía")]),
    # Un raise que depende de otra cosa no valida el parámetro.
    ("def f(path, modo):\n    if modo == 'x':\n        raise RuntimeError('modo')\n    return path\n", []),
    ("def f(path):\n    return path\n", []),
])
def test_excepciones_con_las_que_la_funcion_valida_un_parametro(source, esperado):
    func = _func(source)
    nombre = func.args.args[0].arg
    assert ai.validating_raises(func, nombre) == esperado


def _suites(tmp_path, source, name="validado"):
    src = tmp_path / f"{name}.py"
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    unit, py = tmp_path / f"test_{name}_unit.py", tmp_path / f"test_{name}_pytest.py"
    QATestGenerator.generate_test_suite(str(src), str(unit))
    QATestGenerator.generate_pytest_suite(str(src), str(py))
    run = _run(["pytest", "-q", "-p", "no:cacheprovider", unit.name, py.name], tmp_path)
    return unit.read_text(encoding="utf-8"), py.read_text(encoding="utf-8"), run


def test_entrada_invalida_solo_si_la_funcion_valida_ese_parametro(tmp_path):
    """walk_files("../../etc/passwd") recorre una ruta relativa: exigirle una excepción sería un error."""
    unit, py, run = _suites(tmp_path, '''
        import os

        def recorre(path):
            return sorted(os.listdir(path)) if os.path.isdir(path) else []

        def descuento(precio, porcentaje):
            if porcentaje < 0 or porcentaje > 100:
                raise ValueError("porcentaje fuera de rango")
            return precio - precio * porcentaje / 100
    ''')
    assert "test_recorre_invalid_input" not in unit and "test_recorre_adversarial_raises" not in py
    assert 'with self.assertRaisesRegex(ValueError, r"porcentaje\\ fuera\\ de\\ rango"):' in unit
    assert 'with pytest.raises(ValueError, match=r"porcentaje\\ fuera\\ de\\ rango"):' in py
    assert run.returncode == 0, run.stdout + run.stderr


def test_entrada_invalida_con_varias_validaciones_acepta_cualquiera(tmp_path):
    unit, py, run = _suites(tmp_path, '''
        def cobra(email):
            if "@" not in email:
                raise ValueError("sin arroba")
            if email.endswith("."):
                raise TypeError("dominio incompleto")
            return email
    ''')
    assert "with self.assertRaisesRegex((ValueError, TypeError), 'sin\\\\ arroba|dominio\\\\ incompleto'):" in unit
    assert run.returncode == 0, run.stdout + run.stderr


def test_valores_limite_de_una_ruta_aceptan_oserror(tmp_path):
    """"" no existe y 2.048 caracteres son un nombre demasiado largo: los dos son rechazos válidos."""
    _, py, run = _suites(tmp_path, '''
        import os

        def tamano(path: str) -> int:
            if path.startswith("/tmp/"):
                return 0
            return os.stat(path).st_size
    ''', name="rutas")
    assert "LookupError, OSError, TypeError, ValueError) as exc:" in py
    assert run.returncode == 0, run.stdout + run.stderr


# --- Tests que nunca se cuelgan ------------------------------------------------------------------

@pytest.mark.parametrize("source, esperado", [
    ("def f():\n    while True:\n        tick()\n", True),
    # Dentro de un try: solo lo para Ctrl+C.
    ("def f():\n    try:\n        while True:\n            tick()\n    except KeyboardInterrupt:\n        return 1\n", True),
    # Un break en un bucle interior no sale del exterior.
    ("def f():\n    while True:\n        for x in y:\n            break\n", True),
    ("def f():\n    while True:\n        if listo():\n            break\n", False),
    ("def f():\n    while True:\n        if listo():\n            return 1\n", False),
    ("def f():\n    while 1:\n        sys.exit(0)\n", False),
    # Solo si se llega siempre: aquí depende del argumento.
    ("def f(continuo):\n    if not continuo:\n        return 0\n    while True:\n        tick()\n", False),
    # Un generador infinito no hace nada al llamarlo.
    ("def f():\n    while True:\n        yield 1\n", False),
])
def test_bucle_sin_fin(source, esperado):
    assert ai.has_endless_loop(_func(source)) is esperado


def test_parametros_que_son_una_duracion():
    func = _func(
        "def f(interval_minutes, espera, tope, seconds, nombre, items):\n"
        "    time.sleep(interval_minutes * 60)\n"
        "    evento.wait(espera)\n"
        "    requests.get(nombre, timeout=tope)\n"
        "    return ', '.join(items)\n"
    )
    assert ai.duration_params(func) == {"interval_minutes", "espera", "tope", "seconds"}


@pytest.mark.parametrize("source, llamadas", [
    # Una validación no corta: con un valor válido no se dispara.
    ("def f(url):\n    if not url:\n        raise ValueError('x')\n    return abrir(url).leer()\n", ["leer", "abrir"]),
    # Un return en una rama sí.
    ("def f(x):\n    a()\n    if x:\n        return 0\n    b()\n", ["a"]),
    # Dentro de un with o de un try se sigue; lo de un if o un and puede no ejecutarse.
    ("def f(x):\n    with abrir(x) as h:\n        try:\n            h.leer()\n        except OSError:\n            c()\n"
     "    if x:\n        d()\n    x and e()\n", ["abrir", "leer"]),
])
def test_llamadas_que_siempre_se_alcanzan(source, llamadas):
    calls = ai.always_reached_calls(_func(source))
    assert sorted(c.func.attr if isinstance(c.func, ast.Attribute) else c.func.id for c in calls) == sorted(llamadas)


def test_e_s_siempre_alcanzada_a_traves_de_helpers(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(textwrap.dedent('''
        import os
        import requests

        def _publica(token, texto):
            if not token:
                return
            requests.post("https://api.example.com", json={"t": texto}, timeout=5)

        def _borra(ruta):
            os.remove(ruta)

        def avisa(texto, ajustes):
            _publica(ajustes.get("token"), texto)

        def limpia(ruta):
            _borra(ruta)
            return True
    '''), encoding="utf-8")
    visitor = ai.UnitTestGenerator(str(src))
    visitor.visit(ast.parse(src.read_text(encoding="utf-8")))
    # avisa llama siempre a _publica, pero _publica solo publica si hay token.
    assert visitor.function_meta["avisa"]["io_calls"] and not visitor.function_meta["avisa"]["io_always"]
    assert visitor.function_meta["limpia"]["io_always"]


def test_suite_de_funciones_que_esperan_o_no_terminan(tmp_path):
    """El bucle sin fin se omite sin ejecutarlo y la duración no recibe 10**6 segundos."""
    unit, py, run = _suites(tmp_path, '''
        import time

        def vigila():
            while True:
                time.sleep(60)

        def pausa(seconds: float) -> None:
            time.sleep(seconds)
    ''', name="esperas")
    assert "Entra en un bucle sin fin" in py and "Entra en un bucle sin fin" in unit
    assert 'ids=["zero", "negative_one"]' in py
    assert run.returncode == 0, run.stdout + run.stderr


def test_limite_de_tiempo_de_cada_test_generado(tmp_path):
    """Lo que el análisis no ve también termina: se omite y, si el código se traga la omisión, se corta."""
    src = tmp_path / "bloquea.py"
    src.write_text(textwrap.dedent('''
        import threading
        import time

        def espera():
            threading.Event().wait()

        def terco(n: int = 0):
            while n >= 0:
                try:
                    time.sleep(0.05)
                except Exception:
                    pass
    '''), encoding="utf-8")
    for framework, generate in (("pytest", QATestGenerator.generate_pytest_suite),
                                ("unit", QATestGenerator.generate_test_suite)):
        suite = tmp_path / f"test_bloquea_{framework}.py"
        generate(str(src), str(suite))
        suite.write_text(suite.read_text(encoding="utf-8").replace("_QA_TIMEOUT = 10", "_QA_TIMEOUT = 1"),
                         encoding="utf-8")
        run = _run(["pytest", "-q", "-rs", "-p", "no:cacheprovider", suite.name], tmp_path)
        assert "No terminó en 1 s con los valores de ejemplo" in run.stdout, run.stdout + run.stderr
        if framework == "pytest":
            # pytest.skip no deriva de Exception: el except del bucle no la atrapa.
            assert run.returncode == 0 and "2 skipped" in run.stdout, run.stdout
        else:
            # self.skipTest sí: el bucle se la traga y a los dos segundos lo corta _QaTimeout.
            assert "_QaTimeout" in run.stdout and "1 failed, 1 skipped" in run.stdout, run.stdout


def test_una_funcion_de_ejemplo_como_argumento_no_permite_afirmar_el_valor(tmp_path):
    """interruptible(call) devuelve call(), y la función de ejemplo devuelve None."""
    unit, py, run = _suites(tmp_path, '''
        from typing import Callable

        def corre(call: Callable[[], int]) -> int:
            return call()
    ''', name="corre")
    assert "assert isinstance(result, int)" not in py and "assertIsInstance(result, int)" not in unit
    assert run.returncode == 0, run.stdout + run.stderr


# --- Índice de imports, clases con choque de nombres y componentes de interfaz -------------------

def _write_package(root, files):
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content), encoding="utf-8")


def _package_suites(root, src):
    tests_dir = root / "tests"
    tests_dir.mkdir(exist_ok=True)
    stem = src.stem
    unit, py = tests_dir / f"test_{stem}_unit.py", tests_dir / f"test_{stem}_pytest.py"
    QATestGenerator.generate_test_suite(str(src), str(unit))
    QATestGenerator.generate_pytest_suite(str(src), str(py))
    run = _run(["pytest", "-q", "-rs", "-p", "no:cacheprovider", unit.name, py.name], tests_dir)
    return unit.read_text(encoding="utf-8"), py.read_text(encoding="utf-8"), run


def test_indice_resuelve_rutas_arboles_e_imports_del_proyecto(tmp_path):
    """ProjectIndex localiza módulos del paquete, sigue imports relativos y tolera archivos rotos."""
    _write_package(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/core.py": "class Base:\n    pass\n",
        "pkg/sub/__init__.py": "from .util import helper\nfrom ..core import Base\n",
        "pkg/sub/util.py": "def helper():\n    return 1\n",
        "pkg/sub/roto.py": "def (\n",
        "pkg/sub/mod.py": '''
            import json as js
            import pkg.core
            import pkg.core as core_alias
            from typing import TYPE_CHECKING

            from . import util
            from .util import helper as ayuda
            from .util import *
            from ..core import Base
            from pkg.core import Base as BaseAbs

            if TYPE_CHECKING:
                from .util import solo_tipos
            else:
                from .. import core as core_else

            try:
                from .roto import algo
            except ImportError:
                from .util import respaldo
        ''',
    })

    mod_path = tmp_path / "pkg" / "sub" / "mod.py"
    idx = ProjectIndex(str(mod_path))
    assert (idx.module, idx.root) == ("pkg.sub.mod", str(tmp_path))
    assert idx.path_of("pkg.sub.mod") == str(mod_path)
    assert idx.path_of("pkg.sub") == str(tmp_path / "pkg" / "sub" / "__init__.py")
    assert idx.path_of("json") is None and idx.path_of("pkg.inexistente") is None

    # Caché de árboles y tolerancia a sintaxis inválida o módulos fuera del proyecto.
    util_tree = idx.tree("pkg.sub.util")
    assert util_tree is not None and idx.tree("pkg.sub.util") is util_tree
    assert idx.tree("pkg.sub.roto") is None and idx.tree("json") is None

    # Imports relativos y absolutos desde un módulo y desde __init__.py, incluidos if y try.
    names, modules = idx.imports_of("pkg.sub.mod")
    assert names == {
        "ayuda": ("pkg.sub.util", "helper"),
        "Base": ("pkg.core", "Base"),
        "BaseAbs": ("pkg.core", "Base"),
        "solo_tipos": ("pkg.sub.util", "solo_tipos"),
        "algo": ("pkg.sub.roto", "algo"),
        "respaldo": ("pkg.sub.util", "respaldo"),
    }
    assert modules == {
        "core_alias": "pkg.core",
        "util": "pkg.sub.util",
        "core_else": "pkg.core",
    }
    pkg_names, pkg_modules = idx.imports_of("pkg.sub")
    assert pkg_names == {"helper": ("pkg.sub.util", "helper"), "Base": ("pkg.core", "Base")}
    assert pkg_modules == {}

    # Un módulo roto o en curso de carga no provoca errores ni recursión infinita.
    assert idx.visitor("pkg.sub.roto") is None
    assert idx.function_io("pkg.sub.roto", "algo") == (set(), False)
    with idx.loading("pkg.sub.util"):
        assert idx.visitor("pkg.sub.util") is None
    assert idx.visitor("pkg.sub.util") is not None


def test_construccion_de_clases_importadas_de_otros_modulos(tmp_path):
    """Los parámetros de una clase importada se resuelven en su módulo y los objetivos omitidos no dejan imports."""
    _write_package(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/base.py": '''
            from dataclasses import dataclass
            from enum import Enum

            class Modo(Enum):
                RAPIDO = "rapido"

            @dataclass
            class Spec:
                nombre: str
                modo: Modo

            @dataclass
            class Etiqueta:
                texto: str
        ''',
        "pkg/extra.py": '''
            from dataclasses import dataclass
            from enum import Enum

            class Sello(Enum):
                OK = 1

            @dataclass
            class Sobre:
                sello: Sello
        ''',
        "pkg/servicio.py": '''
            from __future__ import annotations
            from typing import Type

            from .base import Etiqueta as Tag, Spec
            from .extra import Sobre

            def describe(spec: Spec) -> str:
                return f"{spec.nombre}:{spec.modo.value}"

            def nombre_clase(cls: Type[Spec]) -> str:
                return cls.__name__

            def lee_tag(tag: Tag) -> str:
                return tag.texto

            def no_construible(sobre: Sobre, raro: Desconocido) -> str:
                return str(sobre)
        ''',
    })

    unit, py, run = _package_suites(tmp_path, tmp_path / "pkg" / "servicio.py")
    for body in (unit, py):
        assert "from pkg.servicio import Spec, describe, lee_tag, nombre_clase  # noqa: E402" in body
        assert "from pkg.base import Etiqueta, Modo  # noqa: E402" in body
        assert 'describe(Spec("alice", list(Modo)[0]))' in body
        assert "nombre_clase(Spec)" in body
        assert 'lee_tag(Etiqueta("sample"))' in body
        assert "pkg.extra" not in body and "Sello" not in body
    assert run.returncode == 0, run.stdout + run.stderr


def test_clases_con_choque_de_nombres_no_se_mezclan_ni_rompen_la_suite(tmp_path):
    """Si una clase de otro módulo choca con un nombre local o con otra clase homónima, el objetivo se omite."""
    _write_package(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/modelos.py": '''
            from dataclasses import dataclass
            from enum import Enum

            class Estado(Enum):
                ACTIVO = "activo"

            @dataclass
            class Orden:
                estado: Estado
        ''',
        "pkg/servicio.py": '''
            from .modelos import Estado as EstadoOrden, Orden

            class Estado:
                def etiqueta(self) -> str:
                    return "local"

            class Gestor:
                def __init__(self, orden: Orden):
                    self.orden = orden

                def actual(self) -> str:
                    return self.orden.estado.value

            def procesa(orden: Orden) -> str:
                return orden.estado.value

            def muestra(estado: EstadoOrden) -> str:
                return estado.value
        ''',
        "pkg/alfa.py": '''
            from dataclasses import dataclass
            from enum import Enum

            class Config(Enum):
                A = "a"

            @dataclass
            class TareaA:
                cfg: Config
        ''',
        "pkg/beta.py": '''
            from dataclasses import dataclass
            from enum import Enum

            class Config(Enum):
                B = "b"

            @dataclass
            class TareaB:
                cfg: Config
        ''',
        "pkg/orquestador.py": '''
            from .alfa import TareaA
            from .beta import TareaB

            def corre_a(tarea: TareaA) -> str:
                return tarea.cfg.value

            def otra_a(tarea: TareaA) -> str:
                return tarea.cfg.name

            def corre_b(tarea: TareaB) -> str:
                return tarea.cfg.value
        ''',
        "pkg/ciclo_a.py": "from .ciclo_b import B\n\nclass A(B):\n    pass\n",
        "pkg/ciclo_b.py": "from .ciclo_a import A\n\nclass B(A):\n    pass\n",
    })

    # Choque con un nombre local del módulo analizado (Estado): ni procesa ni Gestor se construyen.
    servicio = tmp_path / "pkg" / "servicio.py"
    idx_servicio = ProjectIndex(str(servicio))
    ctx_servicio = cp.SampleContext(idx_servicio.tree("pkg.servicio"), idx_servicio)
    assert cp.instantiation_for("Gestor", ctx_servicio) == (
        None,
        "No se sabe construir Gestor: complétalo a mano con valores válidos.",
    )

    unit_s, py_s, run_s = _package_suites(tmp_path, servicio)
    for body in (unit_s, py_s):
        assert "from pkg.modelos import Estado" not in body
        assert "Falta un valor de ejemplo para orden (Orden): complétalo a mano." in body
        assert "Falta un valor de ejemplo para estado (EstadoOrden): complétalo a mano." in body
        assert "No se sabe construir Gestor: complétalo a mano con valores válidos." in body
    assert run_s.returncode == 0, run_s.stdout + run_s.stderr

    # Choque entre dos clases homónimas de módulos ajenos (alfa.Config y beta.Config): el primero entra,
    # reutilizar el mismo módulo sigue valiendo y el segundo se omite sin pisar al primero.
    unit_o, py_o, run_o = _package_suites(tmp_path, tmp_path / "pkg" / "orquestador.py")
    for body in (unit_o, py_o):
        assert "from pkg.alfa import Config  # noqa: E402" in body
        assert "from pkg.beta import Config" not in body
        assert "corre_a(TareaA(list(Config)[0]))" in body
        assert "otra_a(TareaA(list(Config)[0]))" in body
        assert "Falta un valor de ejemplo para tarea (TareaB): complétalo a mano." in body
    assert run_o.returncode == 0, run_o.stdout + run_o.stderr

    # Imports circulares entre contextos hijos no entran en bucle.
    ciclo_a = tmp_path / "pkg" / "ciclo_a.py"
    idx_ciclo = ProjectIndex(str(ciclo_a))
    ctx_ciclo = cp.SampleContext(idx_ciclo.tree("pkg.ciclo_a"), idx_ciclo)
    assert ctx_ciclo.child("pkg.ciclo_a") is ctx_ciclo
    child_b = ctx_ciclo.child("pkg.ciclo_b")
    assert child_b is not None and ctx_ciclo.child("pkg.ciclo_b") is child_b
    found_b = ctx_ciclo.lookup("B")
    assert found_b is not None and found_b[1].name == "B"


def test_deteccion_de_componentes_de_interfaz_directos_genericos_y_heredados(tmp_path):
    """Reconoce componentes de frameworks de interfaz: genéricos, con alias, dentro de if/try y heredados."""
    ctx = _ctx('''
        from typing import TYPE_CHECKING
        import tkinter
        import tkinter as tk
        from textual.screen import ModalScreen
        from .textual import Falso

        if TYPE_CHECKING:
            from PyQt6.QtWidgets import QWidget

        try:
            from wx import Frame
        except ImportError:
            class Frame:
                pass

        class Dialogo(ModalScreen[bool]):
            def compose(self): ...
            @staticmethod
            def ayuda(): ...

        class SubDialogo(Dialogo):
            def cierra(self): ...

        class Panel(tk.Frame):
            def dibuja(self): ...

        class Boton(tkinter.Button):
            def pulsa(self): ...

        class Ventana(QWidget):
            def muestra(self): ...

        class Marco(Frame):
            def abre(self): ...

        class Normal(Falso):
            def hace(self): ...
    ''')
    assert ctx.classes["Dialogo"].ui == "Textual"
    assert ctx.classes["SubDialogo"].ui == "Textual"
    assert ctx.classes["Panel"].ui == "Tkinter"
    assert ctx.classes["Boton"].ui == "Tkinter"
    assert ctx.classes["Ventana"].ui == "Qt"
    assert ctx.classes["Marco"].ui == "wxPython"
    assert ctx.classes["Normal"].ui == ""

    for method in ("compose", "ayuda"):
        rec = cp.receiver_for("Dialogo", method, ctx)
        assert rec.setup is None
        assert rec.skip == ("Es un componente de interfaz de Textual: necesita la aplicación en marcha. "
                            "Pruébalo con las herramientas del framework (en Textual, App.run_test()).")

    # Herencia de un componente definido en otro módulo del proyecto.
    _write_package(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/base_ui.py": '''
            from textual.screen import Screen

            class PantallaBase(Screen):
                pass
        ''',
        "pkg/vistas.py": '''
            from .base_ui import PantallaBase

            class SubVista(Vista):
                pass

            class Vista(PantallaBase):
                def on_mount(self): ...
        ''',
    })
    vistas = tmp_path / "pkg" / "vistas.py"
    idx = ProjectIndex(str(vistas))
    ctx_vistas = cp.SampleContext(idx.tree("pkg.vistas"), idx)
    assert ctx_vistas.classes["Vista"].ui == "Textual"
    assert ctx_vistas.classes["SubVista"].ui == "Textual"


def test_suite_omite_los_metodos_de_componentes_de_interfaz(tmp_path):
    """Los métodos y propiedades de un componente de interfaz se omiten con motivo y el resto se prueba."""
    _write_package(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/base_ui.py": '''
            try:
                from textual.screen import ModalScreen
            except ImportError:
                class ModalScreen:
                    def __class_getitem__(cls, _item):
                        return cls


            class PantallaBase(ModalScreen[bool]):
                pass
        ''',
        "pkg/vistas.py": '''
            from .base_ui import PantallaBase


            class DialogoConfirmacion(PantallaBase):
                def on_mount(self) -> None:
                    raise RuntimeError("sin pantalla montada")

                @property
                def titulo(self) -> str:
                    raise RuntimeError("sin pantalla montada")


            def formatea(texto: str) -> str:
                return texto.strip().upper()
        ''',
    })

    unit, py, run = _package_suites(tmp_path, tmp_path / "pkg" / "vistas.py")
    for body in (unit, py):
        assert "Es un componente de interfaz de Textual: necesita la aplicación en marcha." in body
        assert "from pkg.vistas import formatea  # noqa: E402" in body
        assert "DialogoConfirmacion," not in body
    assert run.returncode == 0, run.stdout + run.stderr
    assert "Es un componente de interfaz de Textual" in run.stdout
