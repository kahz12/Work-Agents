import ast
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from ..common.imports import ImportMap, attr_chain


def _is_test_file(filepath: str) -> bool:
    """Detecta archivos de prueba por su nombre base (no por directorios padre)."""
    name = os.path.basename(filepath.replace("\\", "/")).lower()
    return name == "conftest.py" or (
        name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))
    )


def _has_keyword(call: ast.Call, name: str) -> bool:
    return any(kw.arg == name for kw in call.keywords)


def _keyword_is(call: ast.Call, name: str, value: bool) -> bool:
    """La llamada pasa name=value con un literal (verify=False, shell=True...)."""
    return any(
        kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is value
        for kw in call.keywords
    )


def _is_built_string(node: ast.AST) -> bool:
    """Texto construido en el momento: f-string, concatenación con + o formato con %."""
    return isinstance(node, ast.JoinedStr) or (
        isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod))
    )


def _open_mode(call: ast.Call) -> Optional[str]:
    """Modo de un open(): 'r' si no se indica, None si no es un literal."""
    mode = call.args[1] if len(call.args) >= 2 else next((kw.value for kw in call.keywords if kw.arg == "mode"), None)
    if mode is None:
        return "r"
    return mode.value if isinstance(mode, ast.Constant) and isinstance(mode.value, str) else None


def _handler_nodes(body: List[ast.stmt]):
    """Nodos del cuerpo de un except, sin entrar en funciones ni clases definidas dentro."""
    pending: List[ast.AST] = list(body)
    while pending:
        node = pending.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            pending.extend(ast.iter_child_nodes(node))


def _propagates_or_logs(body: List[ast.stmt]) -> bool:
    """
    El except vuelve a lanzar (raise, raise X from e) o registra la traza (logger.exception,
    exc_info=True). Es lo que ruff (BLE001) tampoco considera una captura amplia.
    """
    for node in _handler_nodes(body):
        if isinstance(node, ast.Raise):
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "exception":
                return True
            if any(kw.arg == "exc_info" and not (isinstance(kw.value, ast.Constant) and not kw.value.value)
                   for kw in node.keywords):
                return True
    return False


def _uses_name(body: List[ast.stmt], name: Optional[str]) -> bool:
    """El cuerpo del except usa la excepción capturada: la informa, la guarda o la examina."""
    return bool(name) and any(
        isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Load)
        for node in _handler_nodes(body)
    )


def _sql_construction(node: ast.AST) -> Optional[str]:
    """Cómo se construyó a mano una sentencia SQL, o None si es un literal o una variable."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return "concatenate"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return "formato dinámico (%)"
    if isinstance(node, ast.JoinedStr):
        return "f-string"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return "formato dinámico (.format)"
    return None


# --- Constantes de las reglas ---------------------------------------------------------------

DANGEROUS_FUNCTIONS = frozenset({"eval", "exec"})
HTTP_CLIENT_LIBS = frozenset({"requests", "httpx"})
HTTP_METHODS = frozenset({"get", "post", "put", "delete", "patch", "head", "request"})
RANDOM_GENERATORS = frozenset({"choice", "choices", "randint", "random", "randrange", "getrandbits", "sample"})
SENSITIVE_RANDOM_HINTS = ("nonce", "salt", "otp")

# Formas de importar el urlopen de la biblioteca estándar. Un método `.urlopen` de otro
# objeto (YoutubeDL de yt-dlp, un opener propio) aplica su propio timeout y no cuenta.
URLLIB_URLOPEN = frozenset({"urllib.request.urlopen", "urllib2.urlopen", "six.moves.urllib.request.urlopen"})
_URLOPEN_MODULES = frozenset(name.rsplit(".", 1)[0] for name in URLLIB_URLOPEN)

# Clases base cuyos visit_* son el protocolo del visitante y se documentan en la base.
_VISITOR_BASES = frozenset({"NodeVisitor", "NodeTransformer"})

# Identificadores vinculados a credenciales frente a sufijos de metadatos que solo nombran
# columnas o etiquetas de interfaz.
SECRET_NAME_HINTS = (
    "password", "passwd", "passphrase", "secret", "api_key", "apikey",
    "token", "credential", "access_key", "client_secret", "private_key",
)
FIELD_NAME_SUFFIXES = ("_name", "_names", "_field", "_fields", "_label", "_column", "_header", "_param", "_attr")
# Valores de relleno de la documentación y las plantillas: no son secretos aunque la clave lo parezca.
_PLACEHOLDERS = ("changeme", "change_me", "your", "tu-", "tu_", "placeholder", "example",
                 "ejemplo", "todo", "tbd", "dummy", "sample", "fake", "redacted", "aqui", "here")

# Mensajes que comparten varias reglas. Otras partes del paquete reconocen los hallazgos por
# su texto (audits._TOPICS, rules._MESSAGE_RULES, reporting._SAST_SARIF_RULES): cambiar uno
# obliga a revisar esas tablas.
BLOCKING_IN_ASYNC = "Llamada síncrona bloqueante dentro de función 'async def' (bloquea el event loop)."
URLOPEN_WITHOUT_TIMEOUT = "Llamada a 'urlopen()' sin 'timeout' explícito (riesgo de DoS)."
BROAD_EXCEPT = "Uso de 'except Exception:'. Se recomienda especificar excepciones más concretas."
BROAD_EXCEPT_REPORTED = (
    "Uso de 'except Exception:' que informa del error. Correcto en una frontera (CLI, SDK, hilo); "
    "en otro sitio, especifica excepciones más concretas."
)
TOCTOU = (
    "Posible condición de carrera TOCTOU: 'os.path.exists' seguido de 'open()' para escribir. "
    "Entre la comprobación y la apertura el archivo puede cambiar (por ejemplo, por un enlace "
    "simbólico); usa open(..., 'x') para crearlo solo si no existe."
)

Issue = Tuple[int, str, str]


# --- Estado del recorrido -------------------------------------------------------------------

def _nothing() -> None:
    return None


class AnalysisState:
    """
    Estado del recorrido de un archivo: lo que las reglas necesitan saber del punto que se está
    visitando y la lista donde dejan sus hallazgos.

    CodeQualityChecker lo ajusta con enter() antes de visitar los hijos de cada nodo. Las reglas
    lo leen y añaden hallazgos con issue(); la única que lo modifica es la que anota en
    checked_paths las rutas comprobadas con os.path.exists(), que usa después la regla TOCTOU.
    """

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.is_test = _is_test_file(filename)
        self.issues: List[Issue] = []
        # Vacío hasta que enter() visita el módulo; es un valor del recorrido, no un colaborador.
        self.imports = ImportMap("")  # agentes: ignore[SOLID-DIP]
        # Clases y funciones que contienen el nodo que se visita, de fuera adentro.
        self.scopes: List[ast.AST] = []
        # El nodo está en el cuerpo de una `async def` (no en una función normal definida dentro).
        self.in_async = False
        # id() de los open() que se cierran solos: en un `with`, en un ExitStack o con close()
        # garantizado por un try. Se anotan al entrar en el ámbito, antes de visitar la llamada.
        self.managed_opens: Set[int] = set()
        # Variables comprobadas con os.path.exists() o isfile() en la función actual.
        self.checked_paths: Set[str] = set()

    def issue(self, line: int, level: str, message: str) -> None:
        self.issues.append((line, level, message))

    def enter(self, node: ast.AST) -> Callable[[], object]:
        """
        Prepara el estado para visitar los hijos de node y devuelve la función que lo deja como
        estaba al terminar. Solo lo cambian el módulo (sus imports), los `with` (sus open()),
        las clases y las funciones (que abren un ámbito).
        """
        if isinstance(node, ast.Module):
            self.imports = ImportMap.from_tree(node)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            self.managed_opens.update(id(item.context_expr) for item in node.items if _is_open_call(item.context_expr))
        elif isinstance(node, ast.ClassDef):
            self.scopes.append(node)
            return self.scopes.pop
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return self._enter_function(node)
        return _nothing

    def _enter_function(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> Callable[[], object]:
        """Una función empieza sin rutas comprobadas y fija si su cuerpo es asíncrono."""
        self.managed_opens |= _managed_opens(node)
        saved = (self.checked_paths, self.in_async)
        self.checked_paths, self.in_async = set(), isinstance(node, ast.AsyncFunctionDef)
        self.scopes.append(node)

        def restore() -> None:
            self.scopes.pop()
            self.checked_paths, self.in_async = saved

        return restore


def _is_open_call(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open"


def _closed_names(stmts: List[ast.stmt]) -> Set[str]:
    """Nombres X con una llamada X.close() en esas sentencias."""
    names = set()
    for stmt in stmts:
        for sub in ast.walk(stmt):
            if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr == "close"
                    and isinstance(sub.func.value, ast.Name)):
                names.add(sub.func.value.id)
    return names


def _managed_opens(func: ast.AST) -> Set[int]:
    """
    id() de los open() de la función que no hace falta meter en un `with` porque el archivo se
    cierra igual:

    - `f = open(...)` y un try posterior con `f.close()` en el finally;
    - o con `f.close()` en todos los except y en el else (cerrar antes de renombrar, por ejemplo);
    - `stack.enter_context(open(...))` dentro de un ExitStack.
    """
    managed: Set[int] = set()
    assigned: Dict[str, List[ast.Call]] = {}
    try_types = tuple(t for t in (getattr(ast, "Try", None), getattr(ast, "TryStar", None)) if t)
    closed: Set[str] = set()
    for sub in ast.walk(func):
        if isinstance(sub, (ast.Assign, ast.AnnAssign)):
            targets = sub.targets if isinstance(sub, ast.Assign) else [sub.target]
            if len(targets) == 1 and isinstance(targets[0], ast.Name) and isinstance(sub.value, ast.Call) \
                    and _is_open_call(sub.value):
                assigned.setdefault(targets[0].id, []).append(sub.value)
        elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr == "enter_context":
            managed.update(id(arg) for arg in sub.args if _is_open_call(arg))
        elif isinstance(sub, try_types):
            if sub.finalbody:
                closed |= _closed_names(sub.finalbody)
            if sub.handlers and sub.orelse:
                every_handler = set.intersection(*(_closed_names(h.body) for h in sub.handlers))
                closed |= every_handler & _closed_names(sub.orelse)
    for name in closed & assigned.keys():
        managed.update(id(call) for call in assigned[name])
    return managed


# --- Reglas de funciones --------------------------------------------------------------------

def _needs_docstring(state: AnalysisState, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> bool:
    """
    Función que forma parte de la API pública y no documenta nada por sí misma. No lo son:
    las privadas y los tests; las definidas dentro de otra función; las que sobrescriben un
    método documentado en otro sitio (@override, visit_* de un ast.NodeVisitor), y el setter
    o deleter de una propiedad, que se documenta en el getter.
    """
    if state.is_test or node.name.startswith(("_", "test_")) or ast.get_docstring(node):
        return False
    if any(isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) for scope in state.scopes):
        return False
    decorators = {attr_chain(d).rsplit(".", 1)[-1] for d in node.decorator_list if attr_chain(d)}
    if decorators & {"override", "setter", "deleter"}:
        return False
    parent = state.scopes[-1] if state.scopes else None
    if isinstance(parent, ast.ClassDef) and (node.name.startswith("visit_") or node.name == "generic_visit"):
        bases = {attr_chain(b).rsplit(".", 1)[-1] for b in parent.bases if attr_chain(b)}
        return not bases & _VISITOR_BASES
    return True


def _rule_missing_docstring(state: AnalysisState, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> None:
    if _needs_docstring(state, node):
        state.issue(node.lineno, "BAJO", f"La función pública '{node.name}' carece de docstring explicativo.")


def _rule_too_many_args(state: AnalysisState, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> None:
    """Cuenta los argumentos posicionales sin self ni cls."""
    count = sum(1 for a in node.args.args if a.arg not in ("self", "cls"))
    if count > 5:
        state.issue(node.lineno, "MEDIO", f"La función '{node.name}' recibe {count} argumentos (máximo recomendado: 5).")


def _rule_mutable_default(state: AnalysisState, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> None:
    """Una lista, dict o set por defecto se crea una sola vez y lo comparten todas las llamadas."""
    defaults = [*node.args.defaults, *(d for d in node.args.kw_defaults if d is not None)]
    if any(isinstance(d, (ast.List, ast.Dict, ast.Set)) for d in defaults):
        state.issue(node.lineno, "MEDIO",
                    f"La función '{node.name}' usa un argumento por defecto mutable (lista/dict/set); usa None.")


# --- Reglas de excepciones ------------------------------------------------------------------

def _is_silencing_body(body: List[ast.stmt]) -> bool:
    """El cuerpo es solo `pass` o `...`."""
    if len(body) != 1:
        return False
    stmt = body[0]
    if isinstance(stmt, ast.Pass):
        return True
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis


def _rule_bare_except(state: AnalysisState, node: ast.ExceptHandler) -> None:
    if node.type is None:
        state.issue(node.lineno, "ALTO", "Uso de 'except:' genérico. Captura todas las excepciones indeseadas.")


def _rule_broad_except(state: AnalysisState, node: ast.ExceptHandler) -> None:
    """
    except Exception según lo que hace con el error: silenciarlo es lo grave; informar de él
    es habitual en una frontera; relanzarlo o registrar su traza no lo oculta.
    """
    if not (isinstance(node.type, ast.Name) and node.type.id == "Exception"):
        return
    if _is_silencing_body(node.body):
        state.issue(node.lineno, "ALTO", "Uso de 'except Exception: pass' que silencia errores.")
    elif _propagates_or_logs(node.body):
        return
    elif _uses_name(node.body, node.name):
        state.issue(node.lineno, "BAJO", BROAD_EXCEPT_REPORTED)
    else:
        state.issue(node.lineno, "MEDIO", BROAD_EXCEPT)


# --- Reglas de llamadas ---------------------------------------------------------------------

def _rule_call(state: AnalysisState, node: ast.Call) -> None:
    """
    Aplica la cadena de reglas que toca según a qué se llama: a un nombre suelto (eval(),
    open()...) o a un atributo (os.system(), requests.get()...). En cada cadena la primera
    regla cuya condición se cumple decide, aunque no emita ningún aviso: yaml.load con
    SafeLoader, por ejemplo, no debe seguir evaluándose como otra cosa.
    """
    func = node.func
    if isinstance(func, ast.Name):
        for name_rule in NAME_CALL_RULES:
            if name_rule(state, node, func.id):
                return
    elif isinstance(func, ast.Attribute):
        owner = func.value.id if isinstance(func.value, ast.Name) else None
        for attribute_rule in ATTRIBUTE_CALL_RULES:
            if attribute_rule(state, node, func.attr, owner):
                return


def _is_urllib_urlopen(state: AnalysisState, func: ast.AST) -> bool:
    """La llamada es el urlopen de urllib, por el nombre con que lo importa el módulo."""
    if isinstance(func, ast.Name):
        if func.id in state.imports.names:
            return state.imports.names[func.id] in URLLIB_URLOPEN
        # Sin import explícito solo puede venir de `from urllib.request import *`.
        return func.id == "urlopen" and bool(state.imports.star & _URLOPEN_MODULES)
    chain = attr_chain(func)
    return bool(chain) and state.imports.resolve(chain) in URLLIB_URLOPEN


def _check_blocking_in_async(state: AnalysisState, node: ast.Call) -> None:
    if state.in_async:
        state.issue(node.lineno, "MEDIO", BLOCKING_IN_ASYNC)


def _check_urlopen(state: AnalysisState, node: ast.Call) -> None:
    # El tercer argumento posicional de urlopen es el timeout.
    if not (len(node.args) >= 3 or _has_keyword(node, "timeout")):
        state.issue(node.lineno, "MEDIO", URLOPEN_WITHOUT_TIMEOUT)
    _check_blocking_in_async(state, node)


def _writes(node: ast.Call) -> bool:
    """
    El open() escribe o crea el archivo, o su modo no es un literal. Leer tras comprobar que
    existe solo arriesga un FileNotFoundError, no una carrera explotable.
    """
    mode = _open_mode(node)
    return mode is None or any(flag in mode for flag in "wax+")


# Reglas de llamadas a un nombre suelto: (estado, llamada, nombre) -> True si la regla decide.

def _call_dynamic_exec(state: AnalysisState, node: ast.Call, name: str) -> bool:
    if name not in DANGEROUS_FUNCTIONS:
        return False
    state.issue(node.lineno, "CRITICO", f"Uso de función de riesgo dinámico '{name}()'.")
    return True


def _call_open(state: AnalysisState, node: ast.Call, name: str) -> bool:
    """open() fuera de un `with`, con una ruta construida a mano o tras comprobar que existe."""
    if name != "open":
        return False
    if id(node) not in state.managed_opens:
        state.issue(node.lineno, "MEDIO",
                    "Llamada a 'open()' fuera de un context manager 'with' (riesgo de fuga de descriptores).")
    if not node.args:
        return True
    path = node.args[0]
    if _is_built_string(path):
        state.issue(node.lineno, "MEDIO",
                    "Apertura de archivo con ruta construida dinámicamente; valida con Path.resolve() contra Path Traversal.")
    elif isinstance(path, ast.Name) and path.id in state.checked_paths and _writes(node):
        state.issue(node.lineno, "MEDIO", TOCTOU)
    return True


def _call_urlopen(state: AnalysisState, node: ast.Call, name: str) -> bool:
    """urlopen importado de urllib con su nombre o con un alias (from urllib.request import urlopen as uo)."""
    if not _is_urllib_urlopen(state, node.func):
        return False
    _check_urlopen(state, node)
    return True


# Reglas de llamadas a un atributo: (estado, llamada, atributo, nombre del objeto o None) -> True
# si la regla decide.

def _attr_path_check(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    """os.path.exists(x) / isfile(x): x queda anotada para detectar un open(x) posterior (TOCTOU)."""
    if not (_is_os_path_check(node.func) and node.args and isinstance(node.args[0], ast.Name)):
        return False
    state.checked_paths.add(node.args[0].id)
    return True


def _attr_pickle(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    if not (attr == "loads" and owner == "pickle"):
        return False
    state.issue(node.lineno, "CRITICO", "Uso inseguro de 'pickle.loads()' (deserialización de datos no confiables).")
    return True


def _attr_os_command(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    if not (owner == "os" and attr in ("system", "popen")):
        return False
    state.issue(node.lineno, "CRITICO", f"Ejecución insegura de comandos con 'os.{attr}()' (riesgo de Command Injection).")
    return True


def _attr_yaml_load(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    if not (owner == "yaml" and attr == "load"):
        return False
    if not _has_safe_yaml_loader(node):
        state.issue(node.lineno, "ALTO", "Uso inseguro de 'yaml.load()' sin SafeLoader (usa yaml.safe_load).")
    return True


def _attr_weak_hash(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    if not (owner == "hashlib" and attr in ("md5", "sha1")):
        return False
    if not _keyword_is(node, "usedforsecurity", False):
        state.issue(node.lineno, "MEDIO", f"Uso de hash criptográfico débil 'hashlib.{attr}()' (usa SHA-256 o superior).")
    return True


def _attr_http_client(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    """requests o httpx: TLS sin verificar, sin timeout o bloqueando una corrutina."""
    if not (owner in HTTP_CLIENT_LIBS and attr in HTTP_METHODS):
        return False
    if _keyword_is(node, "verify", False):
        state.issue(node.lineno, "ALTO", "Verificación TLS desactivada ('verify=False') en petición HTTP.")
    if not _has_keyword(node, "timeout"):
        state.issue(node.lineno, "MEDIO", "Petición HTTP sin 'timeout' explícito (riesgo de DoS).")
    _check_blocking_in_async(state, node)
    return True


def _attr_urlopen(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    if not (attr == "urlopen" and _is_urllib_urlopen(state, node.func)):
        return False
    _check_urlopen(state, node)
    return True


def _attr_sleep_in_async(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    if not (owner == "time" and attr == "sleep" and state.in_async):
        return False
    state.issue(node.lineno, "MEDIO", BLOCKING_IN_ASYNC)
    return True


def _attr_shell(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    if not (attr in ("Popen", "run", "call") and owner == "subprocess"):
        return False
    if _keyword_is(node, "shell", True):
        state.issue(node.lineno, "ALTO", "Ejecución de subproceso con 'shell=True' (riesgo de inyección de comandos).")
    return True


def _attr_sql(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    """SQL construido a mano en execute(): concatenación, %, f-string o .format."""
    if not (attr in ("execute", "executemany") and node.args):
        return False
    how = _sql_construction(node.args[0])
    if how:
        state.issue(node.lineno, "ALTO", f"Posible SQL injection: {how} en execute().")
    return True


def _attr_jinja(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    """Plantillas Jinja sin escape automático garantizado."""
    if not (attr in ("render", "from_string") and owner and "jinja" in owner.lower()):
        return False
    state.issue(node.lineno, "MEDIO", "Uso de Jinja render/from_string: revisar autoescape.")
    return True


def _is_os_path_check(func_node: ast.AST) -> bool:
    return (
        isinstance(func_node, ast.Attribute)
        and func_node.attr in ("exists", "isfile")
        and isinstance(func_node.value, ast.Attribute)
        and func_node.value.attr == "path"
        and isinstance(func_node.value.value, ast.Name)
        and func_node.value.value.id == "os"
    )


def _is_safe_yaml_loader(loader_node: ast.AST) -> bool:
    if isinstance(loader_node, ast.Name):
        return loader_node.id in ("SafeLoader", "CSafeLoader")
    if isinstance(loader_node, ast.Attribute):
        return loader_node.attr in ("SafeLoader", "CSafeLoader")
    return False


def _has_safe_yaml_loader(node: ast.Call) -> bool:
    """yaml.load con Loader=SafeLoader (o CSafeLoader), por nombre o como segundo argumento."""
    if any(kw.arg == "Loader" and _is_safe_yaml_loader(kw.value) for kw in node.keywords):
        return True
    return len(node.args) >= 2 and _is_safe_yaml_loader(node.args[1])


# --- Reglas de secretos y aserciones --------------------------------------------------------

def _names_a_secret(name: str) -> bool:
    low = name.lower()
    if low.endswith(FIELD_NAME_SUFFIXES):
        return False
    return any(k in low for k in SECRET_NAME_HINTS)


def _is_real_secret_value(node: Optional[ast.AST]) -> bool:
    """Constante de texto no vacía y que no sea un relleno evidente."""
    if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
        return False
    val = node.value.strip()
    if len(val) < 8:
        return False
    low = val.lower()
    if any(low.startswith(r) or low == r for r in _PLACEHOLDERS):
        return False
    if val.startswith("<") and val.endswith(">"):
        return False
    if val.startswith("$") or (val.startswith("{") and val.endswith("}")):
        return False
    return set(val) - set("xX*-_.") != set()


def _uses_insecure_random(value: ast.AST) -> bool:
    """Detecta uso de random.* en expresiones asignadas a secretos/tokens."""
    for sub in ast.walk(value):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and isinstance(sub.func.value, ast.Name)
            and sub.func.value.id == "random"
            and sub.func.attr in RANDOM_GENERATORS
        ):
            return True
    return False


def _names_sensitive_random(name: str) -> bool:
    """Un nombre de secreto, o de material que también debe ser impredecible (nonce, salt, otp)."""
    if _names_a_secret(name):
        return True
    low = name.lower()
    return not low.endswith(FIELD_NAME_SUFFIXES) and any(k in low for k in SENSITIVE_RANDOM_HINTS)


def _check_secret_target(state: AnalysisState, target: ast.AST, value: Optional[ast.AST], lineno: int) -> None:
    """
    Una asignación a una variable o atributo con nombre de secreto: un valor literal real es un
    secreto incrustado (salvo en tests) y un valor de random.* es material predecible.
    """
    if value is None:
        return
    name = target.id if isinstance(target, ast.Name) else target.attr if isinstance(target, ast.Attribute) else None
    if not name:
        return
    if not state.is_test and _names_a_secret(name) and _is_real_secret_value(value):
        state.issue(lineno, "ALTO", f"Posible secreto hardcodeado en '{name}'.")
    elif _names_sensitive_random(name) and _uses_insecure_random(value):
        state.issue(lineno, "ALTO", "Uso del módulo 'random' para generar material sensible; usa 'secrets'.")


def _rule_secret_in_assign(state: AnalysisState, node: ast.Assign) -> None:
    """Asignaciones directas y encadenadas: PASSWORD = "..." o a = b = "..."."""
    for target in node.targets:
        _check_secret_target(state, target, node.value, node.lineno)


def _rule_secret_in_annassign(state: AnalysisState, node: ast.AnnAssign) -> None:
    """Asignaciones con anotación de tipo (API_KEY: str = "..."); sin valor no hay nada que revisar."""
    _check_secret_target(state, node.target, node.value, node.lineno)


def _rule_secret_in_dict(state: AnalysisState, node: ast.Dict) -> None:
    """Claves de un literal dict ({"token": "..."}), que no pasan por ninguna asignación."""
    if state.is_test:
        return
    for key, value in zip(node.keys, node.values):
        if isinstance(key, ast.Constant) and isinstance(key.value, str) \
                and _names_a_secret(key.value) and _is_real_secret_value(value):
            state.issue(node.lineno, "ALTO", f"Posible secreto hardcodeado en la clave '{key.value}'.")


def _rule_secret_in_keyword(state: AnalysisState, node: ast.keyword) -> None:
    """Argumentos con nombre (conectar(password="...")): el secreto va directo a la llamada."""
    if not state.is_test and node.arg and _names_a_secret(node.arg) and _is_real_secret_value(node.value):
        state.issue(getattr(node.value, "lineno", 0), "ALTO", f"Posible secreto hardcodeado en el argumento '{node.arg}'.")


def _rule_assert(state: AnalysisState, node: ast.Assert) -> None:
    if not state.is_test:
        state.issue(node.lineno, "BAJO", "Uso de assert (se elimina con python -O); no usar para validación en producción.")


# --- Tabla de reglas ------------------------------------------------------------------------

Rule = Callable[[AnalysisState, Any], None]
NameCallRule = Callable[[AnalysisState, ast.Call, str], bool]
AttributeCallRule = Callable[[AnalysisState, ast.Call, str, Optional[str]], bool]

_FUNCTION_RULES: Tuple[Rule, ...] = (_rule_missing_docstring, _rule_too_many_args, _rule_mutable_default)

# Reglas de cada tipo de nodo. Los hallazgos de un mismo nodo salen en el orden de su tupla.
RULES: Dict[type, Tuple[Rule, ...]] = {
    ast.FunctionDef: _FUNCTION_RULES,
    ast.AsyncFunctionDef: _FUNCTION_RULES,
    ast.ExceptHandler: (_rule_bare_except, _rule_broad_except),
    ast.Call: (_rule_call,),
    ast.Assert: (_rule_assert,),
    ast.Assign: (_rule_secret_in_assign,),
    ast.AnnAssign: (_rule_secret_in_annassign,),
    ast.Dict: (_rule_secret_in_dict,),
    ast.keyword: (_rule_secret_in_keyword,),
}

# Cadenas de _rule_call: se prueban en este orden y la primera que devuelve True decide.
NAME_CALL_RULES: Tuple[NameCallRule, ...] = (_call_dynamic_exec, _call_open, _call_urlopen)
ATTRIBUTE_CALL_RULES: Tuple[AttributeCallRule, ...] = (
    _attr_path_check, _attr_pickle, _attr_os_command, _attr_yaml_load, _attr_weak_hash,
    _attr_http_client, _attr_urlopen, _attr_sleep_in_async, _attr_shell, _attr_sql, _attr_jinja,
)


class CodeQualityChecker(ast.NodeVisitor):
    """
    Análisis estático por AST: seguridad al estilo de Bandit y calidad del código.

    Recorre el árbol en preorden. En cada nodo aplica las reglas que RULES registra para su
    tipo, ajusta el estado con AnalysisState.enter() y visita sus hijos. Una regla nueva es una
    función más en la tabla: el recorrido no cambia. Los hallazgos son (línea, nivel, mensaje).
    """

    def __init__(self, filename: str) -> None:
        self.filename = filename
        # Cada recorrido tiene su propio estado: no hay nada que inyectar ni que sustituir.
        self.state = AnalysisState(filename)  # agentes: ignore[SOLID-DIP]

    @property
    def issues(self) -> List[Issue]:
        """Hallazgos en el orden en que se encontraron."""
        return self.state.issues

    def visit(self, node: ast.AST) -> None:
        for rule in RULES.get(type(node), ()):
            rule(self.state, node)
        restore = self.state.enter(node)
        try:
            self.generic_visit(node)
        finally:
            restore()


# En los tests, assert (B101) y las contraseñas de ejemplo (B105 a B107) son lo normal; el motor
# AST tampoco los señala en archivos de test.
_BANDIT_SKIPPED_IN_TESTS = frozenset({"B101", "B105", "B106", "B107"})


def _run_bandit(command: List[str], chunk: List[str]) -> Optional[Dict[str, Any]]:
    """
    Informe JSON de Bandit para un grupo de archivos, o None si no se pudo obtener: no
    terminó en 60 segundos, no se pudo lanzar o su salida está vacía o no es un objeto JSON.
    Ese grupo queda entonces solo con el motor AST.
    """
    try:
        proc = subprocess.run(
            [*command, "-f", "json", "-q", *chunk],
            capture_output=True,
            text=True,
            timeout=60,
        )
        raw = proc.stdout.strip()
        data = json.loads(raw) if raw else None
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _bandit_issues_by_file(data: Dict[str, Any], chunk: List[str]) -> Dict[str, List[Issue]]:
    """
    Hallazgos de un informe de Bandit agrupados por archivo, con la ruta tal como la pasó
    quien llama: Bandit puede devolverla con otra forma, así que se comparan las rutas reales.
    Todos los archivos del grupo aparecen aunque no tengan hallazgos, para distinguir «sin
    hallazgos» de «Bandit no lo analizó».
    """
    real_to_orig = {os.path.realpath(fp): fp for fp in chunk}
    grouped: Dict[str, List[Issue]] = {fp: [] for fp in chunk}
    for item in data.get("results", []):
        fname = item.get("filename")
        orig_fp = real_to_orig.get(os.path.realpath(fname)) if fname else None
        if orig_fp is None or (_is_test_file(orig_fp) and item.get("test_id") in _BANDIT_SKIPPED_IN_TESTS):
            continue
        grouped[orig_fp].append(StaticCodeAnalyzer._bandit_item_to_issue(item))
    return grouped


class StaticCodeAnalyzer:
    """
    Analizador de calidad de código: Bandit real si está instalado, AST como fallback.
    Incluye exportador SARIF v2.1.0.
    """

    _SEVERITY_MAP = {
        "HIGH": "ALTO",
        "MEDIUM": "MEDIO",
        "LOW": "BAJO",
        "UNDEFINED": "BAJO",
    }

    @staticmethod
    def _bandit_item_to_issue(item: dict) -> Tuple[int, str, str]:
        sev = StaticCodeAnalyzer._SEVERITY_MAP.get(str(item.get("issue_severity", "LOW")).upper(), "MEDIO")
        if str(item.get("issue_confidence", "")).upper() == "HIGH" and sev == "ALTO":
            sev = "CRITICO"
        line = int(item.get("line_number") or 0)
        text = item.get("issue_text") or item.get("test_name") or "Hallazgo Bandit"
        return (line, sev, f"[bandit] {text}")

    @staticmethod
    def bandit_command() -> Optional[List[str]]:
        """
        Cómo lanzar Bandit, o None si no está instalado.

        Primero se busca junto al intérprete que ejecuta agentes (`python -m bandit`): así se
        encuentra aunque el entorno virtual no esté activado (pipx, ruta absoluta, CI con
        `python -m agentes`). Después, en el PATH.
        """
        if importlib.util.find_spec("bandit") is not None:
            return [sys.executable, "-m", "bandit"]
        exe = shutil.which("bandit")
        return [exe] if exe else None

    @staticmethod
    def _analyze_batch_with_bandit(
        filepaths: List[str],
        chunk_size: int = 100,
    ) -> Optional[Dict[str, List[Tuple[int, str, str]]]]:
        """
        Hallazgos de Bandit por archivo, con un subproceso por cada grupo de chunk_size archivos.
        Un grupo en el que Bandit falla no aparece en el resultado (sus archivos quedan solo con
        el motor AST). None si Bandit no está instalado o no pudo con ningún grupo.
        """
        command = StaticCodeAnalyzer.bandit_command()
        if not command or not filepaths:
            return None
        grouped: Dict[str, List[Tuple[int, str, str]]] = {}
        any_chunk_ok = False
        for start in range(0, len(filepaths), chunk_size):
            chunk = filepaths[start:start + chunk_size]
            data = _run_bandit(command, chunk)
            if data is None:
                continue
            any_chunk_ok = True
            grouped.update(_bandit_issues_by_file(data, chunk))
        return grouped if any_chunk_ok else None

    @staticmethod
    def _analyze_with_bandit(filepath: str) -> Optional[List[Tuple[int, str, str]]]:
        batch = StaticCodeAnalyzer._analyze_batch_with_bandit([filepath])
        if batch is None:
            return None
        return batch.get(filepath)

    @staticmethod
    def _merge_issues(
        bandit_issues: Optional[List[Tuple[int, str, str]]],
        ast_issues: List[Tuple[int, str, str]],
    ) -> List[Tuple[int, str, str]]:
        if bandit_issues is None:
            return ast_issues
        merged = list(bandit_issues)
        seen = {(ln, msg) for ln, _, msg in bandit_issues}
        for item in ast_issues:
            key = (item[0], item[2])
            if key not in seen:
                merged.append(item)
                seen.add(key)
        return merged

    @staticmethod
    def _analyze_with_ast(filepath: str) -> List[Tuple[int, str, str]]:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                code_content = f.read()
            tree = ast.parse(code_content, filename=filepath)
            checker = CodeQualityChecker(filepath)
            checker.visit(tree)
            return checker.issues
        except SyntaxError as e:
            return [(e.lineno or 0, "ALTO", f"Error de sintaxis: {e.msg}")]
        except Exception as e:
            return [(0, "ERROR", f"Error durante el análisis: {str(e)}")]

    @staticmethod
    def analyze_python_files(
        filepaths: List[str],
        *,
        prefer_bandit: bool = True,
    ) -> Dict[str, List[Tuple[int, str, str]]]:
        """
        Analiza múltiples archivos Python en lote (un subproceso Bandit por chunk + AST).
        """
        existing = [fp for fp in filepaths if os.path.exists(fp)]
        batch_map = (
            StaticCodeAnalyzer._analyze_batch_with_bandit(existing)
            if (prefer_bandit and existing) else None
        )
        results: Dict[str, List[Tuple[int, str, str]]] = {}
        for fp in filepaths:
            if not os.path.exists(fp):
                results[fp] = [(0, "ERROR", f"El archivo {fp} no existe.")]
                continue
            b_issues = batch_map.get(fp) if batch_map is not None else None
            ast_issues = StaticCodeAnalyzer._analyze_with_ast(fp)
            results[fp] = StaticCodeAnalyzer._merge_issues(b_issues, ast_issues)
        return results

    @staticmethod
    def analyze_python_file(filepath: str, *, prefer_bandit: bool = True) -> List[Tuple[int, str, str]]:
        """
        Analiza un archivo Python. Usa Bandit si está disponible; si no, AST local.
        """
        return StaticCodeAnalyzer.analyze_python_files([filepath], prefer_bandit=prefer_bandit)[filepath]

    @staticmethod
    def export_to_sarif(filepath: str, issues: List[Tuple[int, str, str]], output_sarif_path: str) -> str:
        """
        Exporta los hallazgos en formato JSON SARIF v2.1.0 compatible con GitHub Code Scanning.
        """
        from ..common.reporting import findings_to_sarif

        abs_file = os.path.abspath(filepath)
        findings = [
            {
                "file": abs_file,
                "line": line,
                "level": level,
                "message": desc,
                "rule_id": f"SAST-{level}",
            }
            for line, level, desc in issues
        ]
        return findings_to_sarif(
            "DefensiveCodeQualityChecker",
            findings,
            output_sarif_path,
            base_dir=os.path.dirname(abs_file),
        )
