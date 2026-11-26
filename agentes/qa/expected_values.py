"""
Resultado esperado de los tests generados.

El generador no adivina qué devuelve una función a partir de su nombre. Hay dos fuentes
fiables:

- Evaluación estática: si el cuerpo es puro (asignaciones, if, return y raise sobre los
  parámetros y unos pocos builtins sin efectos), se calcula el resultado sin ejecutar el
  código del usuario.
- Grabación (opcional): se importa el módulo en un proceso aparte, se llama a cada función
  con los valores de ejemplo y se guarda lo que devuelve. Son tests de caracterización:
  fijan el comportamiento actual, sea correcto o no.

Un resultado es una tupla (tipo, dato, mensaje):
  ("value", repr_del_valor, "")          devuelve ese valor literal
  ("raises", NombreExcepción, mensaje)   lanza esa excepción; mensaje es None si no se conoce
  ("type", nombre_de_tipo, "")           devuelve un objeto no literal de ese tipo (solo al grabar)
  ("blocked", objetivos, "")             intentó escribir, borrar, lanzar un proceso o conectarse
                                         y se bloqueó (solo al grabar); objetivos son los patch
"""
from __future__ import annotations

import ast
import builtins
import json
import math
import operator
import subprocess
import sys
import tempfile
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union, cast

Outcome = Tuple[str, str, Optional[str]]
FuncNode = Union[ast.FunctionDef, ast.AsyncFunctionDef]

_SAFE_BUILTINS = {
    name: getattr(builtins, name)
    for name in ("abs", "bool", "dict", "float", "int", "len", "list", "max", "min",
                 "round", "set", "sorted", "str", "sum", "tuple")
}
_LITERAL_TYPES = (int, float, str, bool, bytes, list, tuple, dict, set, type(None))


class _GiveUp(Exception):
    """La función no es evaluable de forma estática."""


class _Raised(Exception):
    def __init__(self, exc: BaseException) -> None:
        super().__init__(str(exc))
        self.exc = exc


def is_literal(value: Any) -> bool:
    """True si repr(value) vuelve a dar el mismo valor y puede escribirse en un test."""
    if not isinstance(value, _LITERAL_TYPES):
        return False
    if isinstance(value, float) and not math.isfinite(value):
        return False
    try:
        return ast.literal_eval(repr(value)) == value
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        return False


_BIN_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod, ast.Pow: operator.pow,
    ast.LShift: operator.lshift, ast.RShift: operator.rshift, ast.BitOr: operator.or_,
    ast.BitXor: operator.xor, ast.BitAnd: operator.and_,
}
_UNARY_OPS = {ast.UAdd: operator.pos, ast.USub: operator.neg, ast.Not: operator.not_, ast.Invert: operator.invert}
_CMP_OPS = {
    ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt, ast.LtE: operator.le,
    ast.Gt: operator.gt, ast.GtE: operator.ge, ast.Is: operator.is_, ast.IsNot: operator.is_not,
    ast.In: lambda a, b: a in b, ast.NotIn: lambda a, b: a not in b,
}
_CONVERSIONS: Dict[int, Callable[[Any], Any]] = {-1: lambda v: v, 115: str, 114: repr, 97: ascii}


def _interpret(node: ast.AST, env: Dict[str, Any]) -> Any:
    """
    Evalúa una expresión pura recorriendo el árbol. Cualquier nodo fuera del subconjunto
    admitido (atributos, lambdas, comprensiones, llamadas no permitidas...) abandona con _GiveUp.
    No usa eval: el código analizado nunca se ejecuta.
    """
    for node_types, handler in _INTERPRETERS:
        if isinstance(node, node_types):
            return handler(node, env)
    raise _GiveUp


def _interpret_constant(node: ast.Constant, env: Dict[str, Any]) -> Any:
    return node.value


def _interpret_name(node: ast.Name, env: Dict[str, Any]) -> Any:
    if node.id not in env:
        raise _GiveUp  # global, import o nombre desconocido
    return env[node.id]


def _interpret_binop(node: ast.BinOp, env: Dict[str, Any]) -> Any:
    if type(node.op) not in _BIN_OPS:
        raise _GiveUp  # @ y operadores futuros
    left, right = _interpret(node.left, env), _interpret(node.right, env)
    if isinstance(node.op, (ast.Pow, ast.LShift)) and not (isinstance(right, int) and 0 <= right <= 64):
        raise _GiveUp  # evita resultados gigantes
    return _apply(_BIN_OPS[type(node.op)], left, right)


def _interpret_unaryop(node: ast.UnaryOp, env: Dict[str, Any]) -> Any:
    if type(node.op) not in _UNARY_OPS:
        raise _GiveUp
    return _apply(_UNARY_OPS[type(node.op)], _interpret(node.operand, env))


def _interpret_boolop(node: ast.BoolOp, env: Dict[str, Any]) -> Any:
    """and/or con cortocircuito: devuelve el primer operando que decide, como Python."""
    result = None
    for value in node.values:
        result = _interpret(value, env)
        if isinstance(node.op, ast.And) and not result:
            return result
        if isinstance(node.op, ast.Or) and result:
            return result
    return result


def _interpret_compare(node: ast.Compare, env: Dict[str, Any]) -> Any:
    """Comparaciones encadenadas (a < b <= c): se detiene en la primera que no se cumple."""
    left = _interpret(node.left, env)
    for op, comparator in zip(node.ops, node.comparators):
        if type(op) not in _CMP_OPS:
            raise _GiveUp
        right = _interpret(comparator, env)
        if not _apply(_CMP_OPS[type(op)], left, right):
            return False
        left = right
    return True


def _interpret_ifexp(node: ast.IfExp, env: Dict[str, Any]) -> Any:
    return _interpret(node.body if _interpret(node.test, env) else node.orelse, env)


_SEQUENCE_TYPES = {ast.Tuple: tuple, ast.List: list, ast.Set: set}


def _interpret_sequence(node: Union[ast.Tuple, ast.List, ast.Set], env: Dict[str, Any]) -> Any:
    if any(isinstance(e, ast.Starred) for e in node.elts):
        raise _GiveUp
    items = [_interpret(e, env) for e in node.elts]
    return _apply(_SEQUENCE_TYPES[type(node)], items)


def _interpret_dict(node: ast.Dict, env: Dict[str, Any]) -> Any:
    if any(k is None for k in node.keys):
        raise _GiveUp  # desempaquetado **
    return _apply(dict, [(_interpret(cast(ast.expr, k), env), _interpret(v, env)) for k, v in zip(node.keys, node.values)])


def _interpret_subscript(node: ast.Subscript, env: Dict[str, Any]) -> Any:
    return _apply(operator.getitem, _interpret(node.value, env), _interpret(node.slice, env))


def _interpret_slice(node: ast.Slice, env: Dict[str, Any]) -> Any:
    parts = [_interpret(p, env) if p is not None else None for p in (node.lower, node.upper, node.step)]
    return slice(*parts)


def _interpret_call(node: ast.Call, env: Dict[str, Any]) -> Any:
    """Solo builtins sin efectos (_SAFE_BUILTINS), sin argumentos con nombre ni desempaquetados."""
    if node.keywords or not (isinstance(node.func, ast.Name) and node.func.id in _SAFE_BUILTINS):
        raise _GiveUp
    if any(isinstance(a, ast.Starred) for a in node.args):
        raise _GiveUp
    return _apply(_SAFE_BUILTINS[node.func.id], *[_interpret(a, env) for a in node.args])


def _interpret_joinedstr(node: ast.JoinedStr, env: Dict[str, Any]) -> Any:
    return "".join(str(_interpret(part, env)) for part in node.values)


def _interpret_formatted(node: ast.FormattedValue, env: Dict[str, Any]) -> Any:
    """Un campo de f-string: conversión (!r, !s, !a) y especificación de formato."""
    value = _CONVERSIONS.get(node.conversion, str)(_interpret(node.value, env))
    spec = _interpret(node.format_spec, env) if node.format_spec is not None else ""
    return _apply(format, value, spec)


# Tipos de nodo que sabe evaluar _interpret y quién los evalúa.
_INTERPRETERS: Tuple[Tuple[Any, Callable[[Any, Dict[str, Any]], Any]], ...] = (
    (ast.Constant, _interpret_constant),
    (ast.Name, _interpret_name),
    (ast.BinOp, _interpret_binop),
    (ast.UnaryOp, _interpret_unaryop),
    (ast.BoolOp, _interpret_boolop),
    (ast.Compare, _interpret_compare),
    (ast.IfExp, _interpret_ifexp),
    ((ast.Tuple, ast.List, ast.Set), _interpret_sequence),
    (ast.Dict, _interpret_dict),
    (ast.Subscript, _interpret_subscript),
    (ast.Slice, _interpret_slice),
    (ast.Call, _interpret_call),
    (ast.JoinedStr, _interpret_joinedstr),
    (ast.FormattedValue, _interpret_formatted),
)


def _apply(func: Any, *args: Any) -> Any:
    """Aplica una operación; si falla, esa excepción es el resultado esperado."""
    try:
        return func(*args)
    except Exception as exc:  # noqa: BLE001 - se devuelve como resultado, no se oculta
        raise _Raised(exc) from exc


def _eval(node: ast.AST, env: Dict[str, Any]) -> Any:
    return _interpret(node, env)


def _exception_name(node: Optional[ast.AST]) -> str:
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _raise_message(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Call):
        if not node.args:
            return ""
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
    return None


def _run(stmts: List[ast.stmt], env: Dict[str, Any]) -> Optional[Tuple[str, Any, Optional[str]]]:
    for st in stmts:
        if isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant):
            continue  # docstring o literal suelto
        if isinstance(st, ast.Pass):
            continue
        if isinstance(st, ast.Return):
            return ("value", _eval(st.value, env) if st.value is not None else None, "")
        if isinstance(st, ast.Raise):
            name = _exception_name(st.exc)
            if not name:
                raise _GiveUp
            return ("raises", name, _raise_message(st.exc))
        if isinstance(st, ast.If):
            result = _run(st.body if _eval(st.test, env) else st.orelse, env)
            if result is not None:
                return result
            continue
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
            env[st.targets[0].id] = _eval(st.value, env)
            continue
        if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name) and st.value is not None:
            env[st.target.id] = _eval(st.value, env)
            continue
        if isinstance(st, ast.AugAssign) and isinstance(st.target, ast.Name):
            combined = ast.BinOp(left=ast.Name(id=st.target.id, ctx=ast.Load()), op=st.op, right=st.value)
            env[st.target.id] = _eval(combined, env)
            continue
        raise _GiveUp  # bucles, with, try, llamadas con efectos...
    return None


def static_outcome(func: Optional[FuncNode], arg_names: List[str], samples: List[str]) -> Optional[Outcome]:
    """Resultado de llamar a func con samples, calculado sin ejecutar el código. None si no es posible."""
    if func is None or len(arg_names) != len(samples):
        return None
    try:
        env = {name: ast.literal_eval(sample) for name, sample in zip(arg_names, samples)}
    except (ValueError, SyntaxError):
        return None
    try:
        result = _run(list(func.body), env) or ("value", None, "")
    except _GiveUp:
        return None
    except _Raised as raised:
        exc = raised.exc
        # Solo excepciones de builtins: son las únicas que el test puede nombrar con seguridad.
        if type(exc).__module__ != "builtins":
            return None
        return ("raises", type(exc).__name__, str(exc))
    kind, value, message = result
    if kind == "raises":
        return ("raises", str(value), message)
    return ("value", repr(value), "") if is_literal(value) else None


def is_pure_binop(func: Optional[FuncNode], arg_names: List[str]) -> bool:
    """True si el cuerpo es un único `return a <op> b` sobre dos parámetros."""
    if func is None or len(arg_names) != 2:
        return False
    body = [st for st in func.body if not (isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant))]
    if len(body) != 1 or not isinstance(body[0], ast.Return) or not isinstance(body[0].value, ast.BinOp):
        return False
    op = body[0].value
    names = {getattr(op.left, "id", None), getattr(op.right, "id", None)}
    return names == set(arg_names) and isinstance(op.op, (ast.Add, ast.Sub, ast.Mult))


def _returns_none(node: ast.Return) -> bool:
    """return a secas o return None."""
    return node.value is None or (isinstance(node.value, ast.Constant) and node.value.value is None)


def _optional_annotation(ann: Optional[ast.AST]) -> bool:
    """La anotación de retorno admite None: Optional[X], X | None, Union[X, None] o Any."""
    if ann is None:
        return False
    if any(isinstance(n, ast.Constant) and n.value is None for n in ast.walk(ann)):
        return True
    return any(isinstance(n, (ast.Name, ast.Attribute)) and (getattr(n, "id", None) or getattr(n, "attr", ""))
               in ("Optional", "Any") for n in ast.walk(ann))


def fallback_assertion(func: Optional[FuncNode]) -> Tuple[str, str]:
    """
    Qué se puede afirmar sin conocer el valor:
      ("isinstance", T)  la anotación de retorno es un tipo simple
      ("is_none", "")    la función nunca devuelve un valor
      ("not_none", "")   termina siempre con un return de valor y ningún camino devuelve None
      ("none", "")       no hay nada seguro que afirmar (generadores, Optional, algún return None)
    """
    if func is None:
        return ("none", "")
    ann = func.returns
    if isinstance(ann, ast.Constant) and ann.value is None:
        return ("is_none", "")
    if isinstance(ann, ast.Name) and ann.id in ("int", "float", "str", "bool", "bytes", "list", "dict", "tuple", "set"):
        return ("isinstance", ann.id)
    returns_value = False
    returns_none = False
    stack: List[ast.AST] = list(func.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            return ("none", "")
        if isinstance(node, ast.Return):
            if _returns_none(node):
                returns_none = True
            else:
                returns_value = True
        stack.extend(ast.iter_child_nodes(node))
    if not returns_value:
        return ("is_none", "")
    if returns_none or _optional_annotation(ann):
        return ("none", "")
    last = func.body[-1] if func.body else None
    if isinstance(last, ast.Return) and not _returns_none(last):
        return ("not_none", "")
    return ("none", "")


def uses_nondeterminism(func: Optional[FuncNode], nondet_calls: Iterable[str]) -> bool:
    """True si la función llama a reloj, azar, uuid o entorno: su resultado no se puede fijar."""
    if func is None:
        return False
    names = set(nondet_calls)
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            chain = _chain(node.func)
            if chain in names or chain.startswith("random.") or chain.startswith("secrets."):
                return True
    return False


def _chain(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _chain(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


# --- Grabación --------------------------------------------------------------

_RECORDER = r'''
import ast, asyncio, builtins, importlib, io, json, math, os, pathlib, shutil, socket, subprocess, sys

# No escribir __pycache__ dentro del proyecto analizado.
sys.dont_write_bytecode = True
src_dir, module_name = sys.argv[1], sys.argv[2]
calls = json.loads(sys.stdin.read())
sys.path.insert(0, src_dir)

# Bloqueo de efectos: escribir, borrar, mover, lanzar procesos y conectarse a la red.
# No es un sandbox (código hostil puede saltárselo), es una red de seguridad para código
# normal que hace E/S a través de otros módulos que el análisis estático no ve.
class BlockedSideEffect(PermissionError):
    pass

triggered = []

def blocker(target):
    def blocked(*args, **kwargs):
        triggered.append(target)
        raise BlockedSideEffect(f"bloqueado al grabar: {target}")
    return blocked

for mod, names in (
    (os, ["remove", "unlink", "rmdir", "removedirs", "rename", "renames", "replace", "mkdir", "makedirs",
          "chmod", "chown", "symlink", "link", "truncate", "system", "popen", "kill", "fork",
          "execv", "execve", "execvp", "spawnv", "spawnl"]),
    (shutil, ["rmtree", "move", "copy", "copy2", "copyfile", "copytree", "make_archive", "unpack_archive", "chown"]),
    (subprocess, ["run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput"]),
    (socket, ["create_connection"]),
):
    for name in names:
        if hasattr(mod, name):
            setattr(mod, name, blocker(f"{mod.__name__}.{name}"))
for name in ["unlink", "rmdir", "rename", "replace", "write_text", "write_bytes", "mkdir", "touch",
             "chmod", "symlink_to", "hardlink_to"]:
    if hasattr(pathlib.Path, name):
        setattr(pathlib.Path, name, blocker(f"pathlib.Path.{name}"))
socket.socket.connect = blocker("socket.socket.connect")
_real_open = builtins.open
def guarded_open(file, mode="r", *args, **kwargs):
    if any(flag in str(mode) for flag in "wax+"):
        triggered.append("builtins.open")
        raise BlockedSideEffect(f"bloqueado al grabar: open({file!r}, {mode!r})")
    return _real_open(file, mode, *args, **kwargs)
builtins.open = io.open = guarded_open
_real_os_open = os.open
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
def guarded_os_open(path, flags, *args, **kwargs):
    if flags & _WRITE_FLAGS:
        triggered.append("os.open")
        raise BlockedSideEffect(f"bloqueado al grabar: os.open({path!r})")
    return _real_os_open(path, flags, *args, **kwargs)
os.open = guarded_os_open

try:
    module = importlib.import_module(module_name)
except BaseException as exc:
    detail = f"{type(exc).__name__}: {exc}"
    if triggered:
        detail = f"el módulo intenta {', '.join(sorted(set(triggered)))} al importarse"
    print(json.dumps({"__error__": detail}))
    raise SystemExit(0)

def literal(value):
    if isinstance(value, float) and not math.isfinite(value):
        return None
    try:
        text = repr(value)
        return text if ast.literal_eval(text) == value else None
    except Exception:
        return None

namespace = dict(vars(module))
# Los valores de ejemplo de algunos tipos usan estos módulos (pathlib.Path("..."), datetime.date(...)).
for extra in ("pathlib", "datetime", "decimal", "fractions", "re"):
    namespace.setdefault(extra, importlib.import_module(extra))
out = {}
for key, expr in calls.items():
    del triggered[:]
    try:
        value = eval(expr, namespace)
        if asyncio.iscoroutine(value):
            value = asyncio.run(value)
    except BaseException as exc:
        if triggered:
            out[key] = ["blocked", ",".join(sorted(set(triggered))), ""]
            continue
        cls = type(exc)
        name = cls.__name__ if cls.__module__ in ("builtins", module_name) else "Exception"
        out[key] = ["raises", name, str(exc)]
        continue
    if triggered:
        # La función capturó el bloqueo y siguió: su resultado no refleja lo que haría de verdad.
        out[key] = ["blocked", ",".join(sorted(set(triggered))), ""]
        continue
    text = literal(value)
    out[key] = ["value", text, ""] if text is not None else ["type", type(value).__name__, ""]
print(json.dumps(out))
'''


class RecordingError(RuntimeError):
    """No se pudo importar o ejecutar el módulo para grabar resultados."""


def record_outcomes(source_filepath: str, calls: Dict[str, str], *, timeout: float = 20.0) -> Dict[str, Outcome]:
    """
    Ejecuta cada expresión de calls (clave -> "func(1, 2)") en un proceso aparte y devuelve
    lo que produce. Importa el módulo, así que ejecuta su código de nivel superior.
    """
    if not calls:
        return {}
    from .call_plan import module_import

    # En un paquete se importa con su ruta completa desde la raíz: así funcionan sus imports relativos.
    module_name, src_dir = module_import(source_filepath)
    with tempfile.TemporaryDirectory(prefix="agentes-record-") as workdir:
        try:
            proc = subprocess.run(
                [sys.executable, "-I", "-c", _RECORDER, src_dir, module_name],
                input=json.dumps(calls), capture_output=True, text=True, timeout=timeout, cwd=workdir,
            )
        except subprocess.TimeoutExpired as exc:
            raise RecordingError(f"La grabación superó {timeout:.0f} s: alguna función no termina.") from exc
    lines = [ln for ln in proc.stdout.strip().splitlines() if ln.startswith("{")]
    if proc.returncode != 0 or not lines:
        detail = (proc.stderr.strip().splitlines() or ["sin salida"])[-1]
        raise RecordingError(f"No se pudo grabar: {detail}")
    data = json.loads(lines[-1])
    if "__error__" in data:
        raise RecordingError(f"No se pudo importar {module_name}: {data['__error__']}")
    return {key: (item[0], item[1], item[2] if len(item) > 2 else None) for key, item in data.items()}
