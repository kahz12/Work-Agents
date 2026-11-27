"""
How the generated suites call each target: sample values by type, object construction, method
kinds, importing the analysed module, the exceptions a suite can name, and the None analysis.
At the end, complete suites generated for a sample package with relative imports, dataclasses,
I/O, network access and a command-line entry point, which must pass without any manual edits.
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


# --- Sample values by annotation -----------------------------------------------------------------

@pytest.mark.parametrize("annotation, expr, item", [
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
    # Any inside a container accepts any value.
    ("Tuple[str, Any]", '("sample", "sample",)', None),
    # A list of elements that cannot be built is still valid when empty.
    ("List[Odd]", "[]", None),
])
def test_sample_value_from_the_annotation(annotation, expr, item):
    sample = cp.annotation_sample(_ann(annotation), _ctx())
    assert sample is not None
    assert (sample.expr, sample.item, sample.assumed) == (expr, item, False)


@pytest.mark.parametrize("annotation", ["Odd", "Tuple[str, Odd]", "Type[Odd]"])
def test_no_sample_value_when_the_type_cannot_be_built(annotation):
    """A tuple has a fixed arity: with one element missing there is no valid sample."""
    assert cp.annotation_sample(_ann(annotation), _ctx()) is None


def test_standard_library_types_record_their_module():
    ctx = _ctx()
    assert cp.annotation_sample(_ann("Path"), ctx).expr == 'pathlib.Path("sample.txt")'
    assert cp.annotation_sample(_ann("datetime.date"), ctx).expr == "datetime.date(2024, 1, 1)"
    assert ctx.used_modules == {"pathlib", "datetime"}


def test_module_type_alias():
    ctx = _ctx("from typing import List\nIds = List[int]\n")
    assert cp.annotation_sample(_ann("Ids"), ctx).expr == "[1]"


def test_boundary_values_of_a_typed_container_respect_the_element_type():
    items = cp.Sample("[1]", "list", False, "1")
    assert cp.boundary_values(items, "ids") == [("empty_list", "[]"), ("single_elem", "[1]"),
                                                ("two_elems", "[1, 1]")]
    table = cp.Sample('{"sample": 1}', "dict", False, '"sample": 1')
    assert cp.boundary_values(table, "table") == [("empty_dict", "{}"), ("single_kv", '{"sample": 1}')]
    assert cp.boundary_values(cp.Sample("Item()", "object", False), "item") == []


# --- Object construction ---------------------------------------------------------------------------

MODELS = '''
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, NamedTuple, Protocol


class Color(Enum):
    RED = 1


@dataclass
class Item:
    name: str
    quantity: int = 1
    tags: List[str] = field(default_factory=list)


class Point(NamedTuple):
    x: float
    y: float


class Base(ABC):
    @abstractmethod
    def area(self) -> float: ...


class Square(Base):
    def __init__(self, side: float, *, color: Color):
        self.side = side

    def area(self) -> float:
        return self.side ** 2


class Drawable(Protocol):
    def draw(self) -> None: ...
'''


@pytest.mark.parametrize("class_name, expected", [
    ("Color", "list(Color)[0]"),
    # Fields with a default value (default_factory included) are not passed.
    ("Item", 'Item("alice")'),
    ("Point", "Point(1, 1)"),
    ("Square", "Square(1, color=list(Color)[0])"),
    ("Base", None),
    ("Drawable", None),
])
def test_constructing_module_classes(class_name, expected):
    assert cp.construct_expr(class_name, _ctx(MODELS)) == expected


def test_an_abstract_class_is_skipped_with_its_reason():
    expr, reason = cp.instantiation_for("Base", _ctx(MODELS))
    assert expr is None and reason == "Base is abstract: it cannot be instantiated."


def test_method_kinds():
    klass = _func('''
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
    kinds = [ai.method_kind(item) for item in klass.body]
    assert kinds == ["property", "setter", "static", "class", "property", "overload", "abstract", "method"]


def test_receiver_for_static_methods_properties_and_plain_methods():
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


def test_call_plan():
    """Only required arguments are passed; literal defaults still feed the static evaluation."""
    plan = cp.plan_call(_func("def f(a: int, b, c=3, *, d: str, e=None):\n    return b.lower()\n"), _ctx())
    assert plan.arg_str == '2, "sample", d="sample"'
    assert plan.static_names == ["a", "b", "c", "d", "e"]
    assert plan.static_values == ["2", '"sample"', "3", '"sample"', "None"]
    # b has no type: its value comes from how the body uses it (.lower()) and is an assumption.
    assert plan.assumed == ["b"] and plan.missing == []
    assert plan.with_first("None") == 'None, "sample", d="sample"'


def test_call_plan_with_a_type_that_cannot_be_built():
    plan = cp.plan_call(_func("def f(x: Odd):\n    return x\n"), _ctx())
    assert plan.missing == ["x (Odd)"] and plan.first is None


# --- Module names and exceptions -------------------------------------------------------------------

def test_names_the_module_certainly_binds():
    tree = ast.parse(textwrap.dedent('''
        import os.path
        import json as js
        from typing import TYPE_CHECKING
        from other import *
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


@pytest.mark.parametrize("name, to_import", [
    ("ValueError", ""),
    ("CustomError", "CustomError"),
    ("binascii.Error", "binascii"),
    # The suite header already imports os.
    ("os.error", ""),
    # A module-level name shadows the builtin.
    ("TimeoutError", "TimeoutError"),
    ("exc", None),
    ("self.error", None),
    ("print", None),
    ("json.JSONDecodeError", None),
])
def test_how_the_suite_names_each_exception(name, to_import):
    ctx = _ctx("import binascii\nimport os\nclass CustomError(Exception): ...\nclass TimeoutError(Exception): ...\n")
    assert ctx.exception_import(name) == to_import


def test_using_an_exception_records_what_to_import():
    ctx = _ctx("import binascii\n")
    assert ctx.use_exception("binascii.Error") and ctx.used_names == {"binascii"}
    assert ctx.use_exception("ValueError") and ctx.used_names == {"binascii"}
    assert not ctx.use_exception("exc")


def test_helpers_exceptions_and_asserts_propagate_to_their_callers(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(textwrap.dedent('''
        class CustomError(Exception):
            pass

        def _validate(x):
            if not x:
                raise CustomError("empty")

        def public(x):
            _validate(x)
            return x

        def _positive(x):
            assert x > 0

        def half(x):
            _positive(x)
            return x // 2
    '''), encoding="utf-8")
    visitor = ai.UnitTestGenerator(str(src))
    visitor.visit(ast.parse(src.read_text(encoding="utf-8")))
    meta = visitor.function_meta["public"]
    assert meta["raises"] == [] and meta["raises_reachable"] == [("CustomError", "empty")]
    assert not meta["bare_assert"] and visitor.function_meta["half"]["bare_assert"]


# --- Importing the analysed module -------------------------------------------------------------------

def test_module_name_inside_a_package(tmp_path):
    sub = tmp_path / "pkg" / "sub"
    sub.mkdir(parents=True)
    for init in (tmp_path / "pkg" / "__init__.py", sub / "__init__.py"):
        init.write_text("", encoding="utf-8")
    (sub / "mod.py").write_text("", encoding="utf-8")
    (tmp_path / "standalone.py").write_text("", encoding="utf-8")
    assert cp.module_import(str(sub / "mod.py")) == ("pkg.sub.mod", str(tmp_path))
    assert cp.module_import(str(sub / "__init__.py")) == ("pkg.sub", str(tmp_path))
    assert cp.module_import(str(tmp_path / "standalone.py")) == ("standalone", str(tmp_path))


def test_import_header_relative_to_the_suite(tmp_path):
    lines = cp.import_header(str(tmp_path / "pkg" / "mod.py"), str(tmp_path / "tests" / "test_mod.py"),
                             {"b", "a"}, {"pathlib"})
    assert "import pathlib" in lines
    assert '_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../pkg"))' in lines
    assert lines[-1] == "from mod import a, b  # noqa: E402"


# --- Body analysis -----------------------------------------------------------------------------------

@pytest.mark.parametrize("source, expected", [
    ("def main():\n    return sys.argv[1:]\n", True),
    ("def main():\n    sys.exit(1)\n", True),
    ("def main():\n    raise SystemExit(2)\n", True),
    ("def main():\n    exit()\n", True),
    ("def f(argv):\n    return argv\n", False),
])
def test_command_line_entry_point(source, expected):
    assert ai.is_cli_entrypoint(_func(source)) is expected


@pytest.mark.parametrize("source, expected", [
    ("def f(x):\n    return len(x)\n", {"x"}),
    ("def f(x):\n    if x is None:\n        return 0\n    return x + 1\n", set()),
    ("def f(x):\n    yield len(x)\n", set()),
    ("def f(x):\n    try:\n        return len(x)\n    except TypeError:\n        return 0\n", set()),
])
def test_parameters_the_body_uses_without_checking_for_none(source, expected):
    assert ai.none_unsafe_params(_func(source)) == expected


def test_assert_without_a_message():
    assert ai.has_bare_assert(_func("def f(x):\n    assert x > 0\n    return x\n"))
    assert not ai.has_bare_assert(_func("def f(x):\n    assert x > 0, 'positive'\n    return x\n"))
    assert not ai.has_bare_assert(None)


# --- Isolation of the generated suites ---------------------------------------------------------------

def _isolation_namespace() -> dict:
    import io

    namespace = {"io": io, "socket": socket}
    exec("\n".join(emitters._ISOLATION_HELPERS), namespace)  # agentes: ignore[dynamic-exec] - fixed generator code
    return namespace


def test_isolation_blocks_the_network_except_local_connections():
    ns = _isolation_namespace()
    with pytest.raises(socket.gaierror, match="Network blocked"):
        ns["_qa_local_getaddrinfo"]("example.com", 80)
    assert ns["_qa_local_getaddrinfo"]("127.0.0.1", 80)
    with socket.socket() as sock, pytest.raises(OSError, match="Network blocked"):
        ns["_qa_local_connect"](sock, ("203.0.113.1", 80))
    with socket.socket() as server, socket.socket() as client:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        ns["_qa_local_connect"](client, server.getsockname())


def test_isolation_provides_an_empty_standard_input():
    stdin = _isolation_namespace()["_qa_empty_stdin"]()
    assert stdin.readline() == "" and stdin.buffer.read() == b""


# --- Complete suites for a sample package ----------------------------------------------------------

UTIL = '''import urllib.request


def double(x: int) -> int:
    return x * 2


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.read()
'''

PACKAGE = '''"""Sample module for the generated suites."""
import binascii
import os
import sys
from dataclasses import dataclass
from enum import Enum
from typing import List

from .util import double, fetch


class InvalidInputError(Exception):
    pass


class Color(Enum):
    RED = 1
    GREEN = 2


@dataclass
class Item:
    name: str
    quantity: int = 1


class Inventory:
    def __init__(self, items: List[Item]):
        self.items = items

    @property
    def total(self) -> int:
        return sum(i.quantity for i in self.items)

    @staticmethod
    def empty() -> "Inventory":
        return Inventory([])

    @classmethod
    def from_names(cls, names: List[str]) -> "Inventory":
        return cls([Item(n) for n in names])

    def names(self) -> List[str]:
        return [i.name for i in self.items]


def quantities(items: List[Item]) -> List[int]:
    return [double(i.quantity) for i in items]


def paint(color: Color) -> str:
    return color.name.lower()


def _check(raw: str) -> None:
    if not raw.strip():
        raise InvalidInputError("empty text")


def normalise(raw: str) -> str:
    _check(raw)
    return raw.strip()


def encode(data: bytes) -> bytes:
    if len(data) % 2:
        raise binascii.Error("odd length")
    return binascii.hexlify(data)


def read_file(file_path: str) -> str:
    with open(file_path, encoding="utf-8") as f:
        return f.read()


def delete_if(file_path: str, enabled: bool = False) -> bool:
    if enabled:
        os.remove(file_path)
    return enabled


def ask() -> str:
    return sys.stdin.readline().strip()


def status(url: str = "http://example.com/") -> str:
    try:
        fetch(url)
    except OSError as exc:
        return str(exc)
    return "connected"


def main() -> int:
    print(Inventory.from_names(sys.argv[1:]).names())
    return 0
'''


@pytest.fixture
def package(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "util.py").write_text(UTIL, encoding="utf-8")
    (pkg / "models.py").write_text(PACKAGE, encoding="utf-8")
    (tmp_path / "tests").mkdir()
    return tmp_path


def _run(args, cwd):
    return subprocess.run([sys.executable, "-m", *args], capture_output=True, text=True, cwd=str(cwd))


@pytest.mark.parametrize("framework", ["pytest", "unittest"])
def test_suite_for_a_package_passes_untouched(package, framework):
    """The suite lives in another directory: it imports the package by its full name from its root."""
    suite = package / "tests" / f"test_models_{framework}.py"
    generate = QATestGenerator.generate_pytest_suite if framework == "pytest" else QATestGenerator.generate_test_suite
    generate(str(package / "pkg" / "models.py"), str(suite))
    body = suite.read_text(encoding="utf-8")

    assert "from pkg.models import (  # noqa: E402" in body
    # Module classes built from values of their type, enums, and static and class methods.
    assert "quantities([Item(\"alice\")])" in body and "paint(list(Color)[0])" in body
    assert "obj = Inventory([Item(\"alice\")])" in body and "Inventory.empty()" in body
    # open() is replaced by an empty file, not by a MagicMock that can never be read to the end.
    assert 'patch("builtins.open", new=mock_open(read_data=""))' in body
    # main reads sys.argv: it is skipped with its reason and not imported.
    assert "It reads sys.argv or ends the process" in body
    assert "    main,\n" not in body

    run = _run(["pytest", "-q", "-rs", "-p", "no:cacheprovider", suite.name], package / "tests")
    assert run.returncode == 0, run.stdout + run.stderr


def test_pytest_suite_for_a_package_names_the_modules_exceptions(package):
    suite = package / "tests" / "test_models.py"
    QATestGenerator.generate_pytest_suite(str(package / "pkg" / "models.py"), str(suite))
    body = suite.read_text(encoding="utf-8")
    # The exception raised by a private helper, and one from a module the analysed module imports.
    assert "    InvalidInputError,\n" in body and "    binascii,\n" in body
    assert "except (ArithmeticError, AssertionError, InvalidInputError, LookupError" in body
    assert "LookupError, OSError, TypeError, ValueError, binascii.Error) as exc:" in body
    # The property is read, not called, and a typed list varies its number of elements.
    assert "result = obj.total\n" in body
    assert 'ids=["empty_list", "single_elem", "two_elems"]' in body
    # When the function never reaches the patched I/O, the I/O failure test skips itself.
    assert "With the sample values the function never reaches the patched I/O." in body
    assert "@pytest.fixture(autouse=True)\ndef _qa_isolation(monkeypatch):" in body

    run = _run(["pytest", "-q", "-rs", "-p", "no:cacheprovider", suite.name], package / "tests")
    assert run.returncode == 0, run.stdout + run.stderr
    assert "never reaches the patched I/O" in run.stdout


def test_suite_with_assumed_values_skips_when_they_do_not_fit(tmp_path):
    """With no types or hints, the value of x is an assumption: if it does not suit the function, the test skips."""
    src = tmp_path / "assumptions.py"
    src.write_text("def uses(x):\n    return x.field\n", encoding="utf-8")
    suite = tmp_path / "test_assumptions.py"
    QATestGenerator.generate_pytest_suite(str(src), str(suite))
    body = suite.read_text(encoding="utf-8")
    assert "Assumed sample values for x" in body
    run = _run(["pytest", "-q", "-rs", "-p", "no:cacheprovider", suite.name], tmp_path)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "do not fit the function" in run.stdout


def test_suite_accepts_validation_asserts_as_a_rejection(tmp_path):
    src = tmp_path / "validated.py"
    # The nominal value meets the precondition and the -1 boundary does not: a message-less assert is a valid rejection.
    src.write_text("def half(n: int) -> int:\n    assert n >= 0\n    return n // 2\n", encoding="utf-8")
    suite = tmp_path / "test_validated.py"
    QATestGenerator.generate_pytest_suite(str(src), str(suite))
    body = suite.read_text(encoding="utf-8")
    assert "assert str(exc) or isinstance(exc, (AssertionError,))" in body
    run = _run(["pytest", "-q", "-p", "no:cacheprovider", suite.name], tmp_path)
    assert run.returncode == 0, run.stdout + run.stderr


# --- Invalid input and boundary values -----------------------------------------------------------------

@pytest.mark.parametrize("source, expected", [
    # A raise under an if that mentions the parameter, with its literal message.
    ("def f(percent):\n    if percent < 0:\n        raise ValueError('negative')\n    return 1\n",
     [("ValueError", "negative")]),
    # Also in an elif, in source order, and with an assert.
    ("def f(percent):\n    assert percent is not None\n    if percent > 100:\n        raise ValueError('too high')\n"
     "    elif percent < 0:\n        raise KeyError()\n    return 1\n",
     [("AssertionError", ""), ("ValueError", "too high"), ("KeyError", "")]),
    ("def f(path):\n    assert path, 'empty path'\n    return path\n", [("AssertionError", "empty path")]),
    # A raise that depends on something else does not validate the parameter.
    ("def f(path, mode):\n    if mode == 'x':\n        raise RuntimeError('mode')\n    return path\n", []),
    ("def f(path):\n    return path\n", []),
])
def test_exceptions_the_function_uses_to_validate_a_parameter(source, expected):
    func = _func(source)
    name = func.args.args[0].arg
    assert ai.validating_raises(func, name) == expected


def _suites(tmp_path, source, name="validated"):
    src = tmp_path / f"{name}.py"
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    unit, py = tmp_path / f"test_{name}_unit.py", tmp_path / f"test_{name}_pytest.py"
    QATestGenerator.generate_test_suite(str(src), str(unit))
    QATestGenerator.generate_pytest_suite(str(src), str(py))
    run = _run(["pytest", "-q", "-p", "no:cacheprovider", unit.name, py.name], tmp_path)
    return unit.read_text(encoding="utf-8"), py.read_text(encoding="utf-8"), run


def test_invalid_input_only_when_the_function_validates_that_parameter(tmp_path):
    """walk_files("../../etc/passwd") walks a relative path: demanding an exception from it would be wrong."""
    unit, py, run = _suites(tmp_path, '''
        import os

        def walk(path):
            return sorted(os.listdir(path)) if os.path.isdir(path) else []

        def discount(price, percent):
            if percent < 0 or percent > 100:
                raise ValueError("percent out of range")
            return price - price * percent / 100
    ''')
    assert "test_walk_invalid_input" not in unit and "test_walk_adversarial_raises" not in py
    assert 'with self.assertRaisesRegex(ValueError, r"percent\\ out\\ of\\ range"):' in unit
    assert 'with pytest.raises(ValueError, match=r"percent\\ out\\ of\\ range"):' in py
    assert run.returncode == 0, run.stdout + run.stderr


def test_invalid_input_with_several_validations_accepts_any_of_them(tmp_path):
    unit, py, run = _suites(tmp_path, '''
        def charge(email):
            if "@" not in email:
                raise ValueError("missing at sign")
            if email.endswith("."):
                raise TypeError("incomplete domain")
            return email
    ''')
    assert "with self.assertRaisesRegex((ValueError, TypeError), 'missing\\\\ at\\\\ sign|incomplete\\\\ domain'):" in unit
    assert run.returncode == 0, run.stdout + run.stderr


def test_boundary_values_of_a_path_accept_oserror(tmp_path):
    """"" does not exist and 2,048 characters is too long a name: both are valid rejections."""
    _, py, run = _suites(tmp_path, '''
        import os

        def file_size(path: str) -> int:
            if path.startswith("/tmp/"):
                return 0
            return os.stat(path).st_size
    ''', name="paths")
    assert "LookupError, OSError, TypeError, ValueError) as exc:" in py
    assert run.returncode == 0, run.stdout + run.stderr


# --- Tests that never hang -------------------------------------------------------------------------------

@pytest.mark.parametrize("source, expected", [
    ("def f():\n    while True:\n        tick()\n", True),
    # Inside a try: only Ctrl+C stops it.
    ("def f():\n    try:\n        while True:\n            tick()\n    except KeyboardInterrupt:\n        return 1\n", True),
    # A break in an inner loop does not leave the outer one.
    ("def f():\n    while True:\n        for x in y:\n            break\n", True),
    ("def f():\n    while True:\n        if ready():\n            break\n", False),
    ("def f():\n    while True:\n        if ready():\n            return 1\n", False),
    ("def f():\n    while 1:\n        sys.exit(0)\n", False),
    # Only when it is always reached: here it depends on the argument.
    ("def f(continuous):\n    if not continuous:\n        return 0\n    while True:\n        tick()\n", False),
    # Calling an infinite generator does nothing.
    ("def f():\n    while True:\n        yield 1\n", False),
])
def test_endless_loop(source, expected):
    assert ai.has_endless_loop(_func(source)) is expected


def test_parameters_that_are_a_duration():
    func = _func(
        "def f(interval_minutes, pause, cap, seconds, target, items):\n"
        "    time.sleep(interval_minutes * 60)\n"
        "    event.wait(pause)\n"
        "    requests.get(target, timeout=cap)\n"
        "    return ', '.join(items)\n"
    )
    assert ai.duration_params(func) == {"interval_minutes", "pause", "cap", "seconds"}


@pytest.mark.parametrize("source, calls", [
    # A validation does not cut the walk: a valid value never triggers it.
    ("def f(url):\n    if not url:\n        raise ValueError('x')\n    return fetch(url).read()\n", ["read", "fetch"]),
    # A return in a branch does.
    ("def f(x):\n    a()\n    if x:\n        return 0\n    b()\n", ["a"]),
    # The walk continues into with blocks and try bodies; whatever sits behind an if or an and may not run.
    ("def f(x):\n    with fetch(x) as h:\n        try:\n            h.read()\n        except OSError:\n            c()\n"
     "    if x:\n        d()\n    x and e()\n", ["fetch", "read"]),
])
def test_calls_that_are_always_reached(source, calls):
    found = ai.always_reached_calls(_func(source))
    assert sorted(c.func.attr if isinstance(c.func, ast.Attribute) else c.func.id for c in found) == sorted(calls)


def test_io_always_reached_through_helpers(tmp_path):
    src = tmp_path / "m.py"
    src.write_text(textwrap.dedent('''
        import os
        import requests

        def _post(token, text):
            if not token:
                return
            requests.post("https://api.example.com", json={"t": text}, timeout=5)

        def _delete(file_path):
            os.remove(file_path)

        def notify(text, settings):
            _post(settings.get("token"), text)

        def clean(file_path):
            _delete(file_path)
            return True
    '''), encoding="utf-8")
    visitor = ai.UnitTestGenerator(str(src))
    visitor.visit(ast.parse(src.read_text(encoding="utf-8")))
    # notify always calls _post, but _post only posts when there is a token.
    assert visitor.function_meta["notify"]["io_calls"] and not visitor.function_meta["notify"]["io_always"]
    assert visitor.function_meta["clean"]["io_always"]


def test_suite_for_functions_that_wait_or_never_finish(tmp_path):
    """The endless loop is skipped without running it, and the duration never receives 10**6 seconds."""
    unit, py, run = _suites(tmp_path, '''
        import time

        def watch():
            while True:
                time.sleep(60)

        def pause(seconds: float) -> None:
            time.sleep(seconds)
    ''', name="waits")
    assert "It enters an endless loop" in py and "It enters an endless loop" in unit
    assert 'ids=["zero", "negative_one"]' in py
    assert run.returncode == 0, run.stdout + run.stderr


def test_time_limit_of_every_generated_test(tmp_path):
    """Whatever the analysis cannot see still ends: it is skipped and, if the code swallows the skip, stopped."""
    src = tmp_path / "blocks.py"
    src.write_text(textwrap.dedent('''
        import threading
        import time

        def wait():
            threading.Event().wait()

        def stubborn(n: int = 0):
            while n >= 0:
                try:
                    time.sleep(0.05)
                except Exception:
                    pass
    '''), encoding="utf-8")
    for framework, generate in (("pytest", QATestGenerator.generate_pytest_suite),
                                ("unit", QATestGenerator.generate_test_suite)):
        suite = tmp_path / f"test_blocks_{framework}.py"
        generate(str(src), str(suite))
        suite.write_text(suite.read_text(encoding="utf-8").replace("_QA_TIMEOUT = 10", "_QA_TIMEOUT = 1"),
                         encoding="utf-8")
        run = _run(["pytest", "-q", "-rs", "-p", "no:cacheprovider", suite.name], tmp_path)
        assert "Did not finish within 1 s with the sample values" in run.stdout, run.stdout + run.stderr
        if framework == "pytest":
            # pytest.skip does not derive from Exception, so the loop's except cannot catch it.
            assert run.returncode == 0 and "2 skipped" in run.stdout, run.stdout
        else:
            # self.skipTest does: the loop swallows it and _QaTimeout stops it two seconds later.
            assert "_QaTimeout" in run.stdout and "1 failed, 1 skipped" in run.stdout, run.stdout


def test_a_sample_callable_argument_prevents_asserting_the_value(tmp_path):
    """interruptible(call) returns call(), and the sample callable returns None."""
    unit, py, run = _suites(tmp_path, '''
        from typing import Callable

        def run_it(call: Callable[[], int]) -> int:
            return call()
    ''', name="runs")
    assert "assert isinstance(result, int)" not in py and "assertIsInstance(result, int)" not in unit
    assert run.returncode == 0, run.stdout + run.stderr


# --- Import index, classes with clashing names and UI components ------------------------------------

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


def test_index_resolves_paths_trees_and_project_imports(tmp_path):
    """ProjectIndex finds the package's modules, follows relative imports and tolerates broken files."""
    _write_package(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/core.py": "class Base:\n    pass\n",
        "pkg/sub/__init__.py": "from .util import helper\nfrom ..core import Base\n",
        "pkg/sub/util.py": "def helper():\n    return 1\n",
        "pkg/sub/broken.py": "def (\n",
        "pkg/sub/mod.py": '''
            import json as js
            import pkg.core
            import pkg.core as core_alias
            from typing import TYPE_CHECKING

            from . import util
            from .util import helper as assist
            from .util import *
            from ..core import Base
            from pkg.core import Base as AbsoluteBase

            if TYPE_CHECKING:
                from .util import types_only
            else:
                from .. import core as core_else

            try:
                from .broken import something
            except ImportError:
                from .util import fallback
        ''',
    })

    mod_path = tmp_path / "pkg" / "sub" / "mod.py"
    idx = ProjectIndex(str(mod_path))
    assert (idx.module, idx.root) == ("pkg.sub.mod", str(tmp_path))
    assert idx.path_of("pkg.sub.mod") == str(mod_path)
    assert idx.path_of("pkg.sub") == str(tmp_path / "pkg" / "sub" / "__init__.py")
    assert idx.path_of("json") is None and idx.path_of("pkg.missing") is None

    # Tree cache, and tolerance of invalid syntax or modules outside the project.
    util_tree = idx.tree("pkg.sub.util")
    assert util_tree is not None and idx.tree("pkg.sub.util") is util_tree
    assert idx.tree("pkg.sub.broken") is None and idx.tree("json") is None

    # Relative and absolute imports from a module and from __init__.py, inside if and try included.
    names, modules = idx.imports_of("pkg.sub.mod")
    assert names == {
        "assist": ("pkg.sub.util", "helper"),
        "Base": ("pkg.core", "Base"),
        "AbsoluteBase": ("pkg.core", "Base"),
        "types_only": ("pkg.sub.util", "types_only"),
        "something": ("pkg.sub.broken", "something"),
        "fallback": ("pkg.sub.util", "fallback"),
    }
    assert modules == {
        "core_alias": "pkg.core",
        "util": "pkg.sub.util",
        "core_else": "pkg.core",
    }
    pkg_names, pkg_modules = idx.imports_of("pkg.sub")
    assert pkg_names == {"helper": ("pkg.sub.util", "helper"), "Base": ("pkg.core", "Base")}
    assert pkg_modules == {}

    # A broken module, or one that is still loading, causes neither errors nor infinite recursion.
    assert idx.visitor("pkg.sub.broken") is None
    assert idx.function_io("pkg.sub.broken", "something") == (set(), False)
    with idx.loading("pkg.sub.util"):
        assert idx.visitor("pkg.sub.util") is None
    assert idx.visitor("pkg.sub.util") is not None


def test_constructing_classes_imported_from_other_modules(tmp_path):
    """An imported class's parameters are resolved in its own module, and skipped targets leave no imports."""
    _write_package(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/base.py": '''
            from dataclasses import dataclass
            from enum import Enum

            class Mode(Enum):
                FAST = "fast"

            @dataclass
            class Spec:
                name: str
                mode: Mode

            @dataclass
            class Label:
                caption: str
        ''',
        "pkg/extra.py": '''
            from dataclasses import dataclass
            from enum import Enum

            class Seal(Enum):
                OK = 1

            @dataclass
            class Envelope:
                seal: Seal
        ''',
        "pkg/service.py": '''
            from __future__ import annotations
            from typing import Type

            from .base import Label as Tag, Spec
            from .extra import Envelope

            def describe(spec: Spec) -> str:
                return f"{spec.name}:{spec.mode.value}"

            def class_name(cls: Type[Spec]) -> str:
                return cls.__name__

            def read_tag(tag: Tag) -> str:
                return tag.caption

            def not_buildable(envelope: Envelope, odd: Unknown) -> str:
                return str(envelope)
        ''',
    })

    unit, py, run = _package_suites(tmp_path, tmp_path / "pkg" / "service.py")
    for body in (unit, py):
        assert "from pkg.service import Spec, class_name, describe, read_tag  # noqa: E402" in body
        assert "from pkg.base import Label, Mode  # noqa: E402" in body
        assert 'describe(Spec("alice", list(Mode)[0]))' in body
        assert "class_name(Spec)" in body
        assert 'read_tag(Label("sample"))' in body
        assert "pkg.extra" not in body and "Seal" not in body
    assert run.returncode == 0, run.stdout + run.stderr


def test_classes_with_clashing_names_are_not_mixed_up_and_do_not_break_the_suite(tmp_path):
    """When a class from another module clashes with a local name or another class of the same name, the target is skipped."""
    _write_package(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/models.py": '''
            from dataclasses import dataclass
            from enum import Enum

            class State(Enum):
                ACTIVE = "active"

            @dataclass
            class Order:
                state: State
        ''',
        "pkg/service.py": '''
            from .models import State as OrderState, Order

            class State:
                def label(self) -> str:
                    return "local"

            class Manager:
                def __init__(self, order: Order):
                    self.order = order

                def current(self) -> str:
                    return self.order.state.value

            def process(order: Order) -> str:
                return order.state.value

            def show(state: OrderState) -> str:
                return state.value
        ''',
        "pkg/alpha.py": '''
            from dataclasses import dataclass
            from enum import Enum

            class Config(Enum):
                A = "a"

            @dataclass
            class TaskA:
                cfg: Config
        ''',
        "pkg/beta.py": '''
            from dataclasses import dataclass
            from enum import Enum

            class Config(Enum):
                B = "b"

            @dataclass
            class TaskB:
                cfg: Config
        ''',
        "pkg/coordinator.py": '''
            from .alpha import TaskA
            from .beta import TaskB

            def run_a(task: TaskA) -> str:
                return task.cfg.value

            def other_a(task: TaskA) -> str:
                return task.cfg.name

            def run_b(task: TaskB) -> str:
                return task.cfg.value
        ''',
        "pkg/cycle_a.py": "from .cycle_b import B\n\nclass A(B):\n    pass\n",
        "pkg/cycle_b.py": "from .cycle_a import A\n\nclass B(A):\n    pass\n",
    })

    # Clash with a local name of the analysed module (State): neither process nor Manager can be built.
    service = tmp_path / "pkg" / "service.py"
    idx_service = ProjectIndex(str(service))
    ctx_service = cp.SampleContext(idx_service.tree("pkg.service"), idx_service)
    assert cp.instantiation_for("Manager", ctx_service) == (
        None,
        "Cannot work out how to construct Manager: fill it in by hand with valid values.",
    )

    unit_s, py_s, run_s = _package_suites(tmp_path, service)
    for body in (unit_s, py_s):
        assert "from pkg.models import State" not in body
        assert "No sample value for order (Order): fill it in by hand." in body
        assert "No sample value for state (OrderState): fill it in by hand." in body
        assert "Cannot work out how to construct Manager: fill it in by hand with valid values." in body
    assert run_s.returncode == 0, run_s.stdout + run_s.stderr

    # Clash between two same-named classes from other modules (alpha.Config and beta.Config): the first
    # one is used, reusing the same module keeps working, and the second is skipped without replacing it.
    unit_o, py_o, run_o = _package_suites(tmp_path, tmp_path / "pkg" / "coordinator.py")
    for body in (unit_o, py_o):
        assert "from pkg.alpha import Config  # noqa: E402" in body
        assert "from pkg.beta import Config" not in body
        assert "run_a(TaskA(list(Config)[0]))" in body
        assert "other_a(TaskA(list(Config)[0]))" in body
        assert "No sample value for task (TaskB): fill it in by hand." in body
    assert run_o.returncode == 0, run_o.stdout + run_o.stderr

    # Circular imports between child contexts do not loop.
    cycle_a = tmp_path / "pkg" / "cycle_a.py"
    idx_cycle = ProjectIndex(str(cycle_a))
    ctx_cycle = cp.SampleContext(idx_cycle.tree("pkg.cycle_a"), idx_cycle)
    assert ctx_cycle.child("pkg.cycle_a") is ctx_cycle
    child_b = ctx_cycle.child("pkg.cycle_b")
    assert child_b is not None and ctx_cycle.child("pkg.cycle_b") is child_b
    found_b = ctx_cycle.lookup("B")
    assert found_b is not None and found_b[1].name == "B"


def test_detecting_direct_generic_and_inherited_ui_components(tmp_path):
    """UI framework components are recognised: generic, aliased, inside if/try and inherited."""
    ctx = _ctx('''
        from typing import TYPE_CHECKING
        import tkinter
        import tkinter as tk
        from textual.screen import ModalScreen
        from .textual import Fake

        if TYPE_CHECKING:
            from PyQt6.QtWidgets import QWidget

        try:
            from wx import Frame
        except ImportError:
            class Frame:
                pass

        class Dialog(ModalScreen[bool]):
            def compose(self): ...
            @staticmethod
            def assist(): ...

        class SubDialog(Dialog):
            def close(self): ...

        class Panel(tk.Frame):
            def draw(self): ...

        class PushButton(tkinter.Button):
            def press(self): ...

        class Window(QWidget):
            def show(self): ...

        class Border(Frame):
            def open_it(self): ...

        class Plain(Fake):
            def do(self): ...
    ''')
    assert ctx.classes["Dialog"].ui == "Textual"
    assert ctx.classes["SubDialog"].ui == "Textual"
    assert ctx.classes["Panel"].ui == "Tkinter"
    assert ctx.classes["PushButton"].ui == "Tkinter"
    assert ctx.classes["Window"].ui == "Qt"
    assert ctx.classes["Border"].ui == "wxPython"
    assert ctx.classes["Plain"].ui == ""

    for method in ("compose", "assist"):
        rec = cp.receiver_for("Dialog", method, ctx)
        assert rec.setup is None
        assert rec.skip == ("It is a Textual UI component: it needs the application running. "
                            "Test it with the framework's own tools (in Textual, App.run_test()).")

    # Inheriting from a component defined in another project module.
    _write_package(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/base_ui.py": '''
            from textual.screen import Screen

            class BaseScreen(Screen):
                pass
        ''',
        "pkg/views.py": '''
            from .base_ui import BaseScreen

            class SubView(View):
                pass

            class View(BaseScreen):
                def on_mount(self): ...
        ''',
    })
    views = tmp_path / "pkg" / "views.py"
    idx = ProjectIndex(str(views))
    ctx_views = cp.SampleContext(idx.tree("pkg.views"), idx)
    assert ctx_views.classes["View"].ui == "Textual"
    assert ctx_views.classes["SubView"].ui == "Textual"


def test_suite_skips_methods_of_ui_components(tmp_path):
    """Methods and properties of a UI component are skipped with a reason; everything else is tested."""
    _write_package(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/base_ui.py": '''
            try:
                from textual.screen import ModalScreen
            except ImportError:
                class ModalScreen:
                    def __class_getitem__(cls, _item):
                        return cls


            class BaseScreen(ModalScreen[bool]):
                pass
        ''',
        "pkg/views.py": '''
            from .base_ui import BaseScreen


            class ConfirmDialog(BaseScreen):
                def on_mount(self) -> None:
                    raise RuntimeError("no mounted screen")

                @property
                def heading(self) -> str:
                    raise RuntimeError("no mounted screen")


            def format_value(value: str) -> str:
                return value.strip().upper()
        ''',
    })

    unit, py, run = _package_suites(tmp_path, tmp_path / "pkg" / "views.py")
    for body in (unit, py):
        assert "It is a Textual UI component: it needs the application running." in body
        assert "from pkg.views import format_value  # noqa: E402" in body
        assert "ConfirmDialog," not in body
    assert run.returncode == 0, run.stdout + run.stderr
    assert "It is a Textual UI component" in run.stdout
