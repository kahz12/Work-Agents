import ast
import builtins
from typing import List, Optional, Tuple, Union

from ..common.imports import ImportMap

_BUILTIN_NAMES = frozenset(dir(builtins))

_STDLIB_VALUE_MODULES = frozenset({
    "collections", "pathlib", "threading", "decimal", "fractions", "uuid",
    "datetime", "io", "queue", "weakref", "ipaddress", "zoneinfo", "enum",
    "re", "dataclasses", "typing",
})

_STDLIB_VALUE_TYPES = frozenset({
    "Counter", "OrderedDict", "ChainMap",
    "Path", "PurePath", "PurePosixPath", "PureWindowsPath", "PosixPath", "WindowsPath",
    "Lock", "RLock", "Event", "Condition", "Semaphore", "BoundedSemaphore", "Barrier",
    "Queue", "LifoQueue", "PriorityQueue", "SimpleQueue",
    "Decimal", "Fraction", "UUID", "StringIO", "BytesIO", "ZoneInfo",
    "IPv4Address", "IPv6Address", "IPv4Network", "IPv6Network",
    "WeakSet", "WeakKeyDictionary", "WeakValueDictionary", "ExitStack", "AsyncExitStack",
})

_EXCEPTION_SUFFIXES = ("Error", "Exception", "Warning")

_CONTROL_FLOW_TYPES = tuple(
    t for t in (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        ast.With,
        ast.AsyncWith,
        getattr(ast, "TryStar", None),
    )
    if t is not None
)


def _is_broad_exception_type(exc_node: Optional[ast.AST]) -> bool:
    """Indica si la cláusula except captura Exception o BaseException de forma amplia."""
    if exc_node is None:
        return True
    if isinstance(exc_node, ast.Name):
        return exc_node.id in ("Exception", "BaseException")
    if isinstance(exc_node, ast.Tuple):
        return any(_is_broad_exception_type(elt) for elt in exc_node.elts)
    return False


def _is_mutable_default_expr(expr: ast.AST) -> bool:
    """Detecta literales o constructores mutables usados como valores por defecto."""
    if isinstance(expr, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)):
        return True
    return isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name) and expr.func.id in ("list", "dict", "set")


def _is_dataclass_decorator(dec: ast.AST) -> Tuple[bool, bool]:
    """
    Retorna (es_dataclass, tiene_slots_true) evaluando el decorador @dataclass(...).
    """
    if isinstance(dec, ast.Name) and dec.id == "dataclass":
        return True, False
    if isinstance(dec, ast.Attribute) and dec.attr == "dataclass":
        return True, False
    if isinstance(dec, ast.Call):
        is_dc, _ = _is_dataclass_decorator(dec.func)
        if is_dc:
            has_slots = any(
                kw.arg == "slots" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in dec.keywords
            )
            return True, has_slots
    return False, False


def _defines_slots(node: ast.ClassDef) -> bool:
    """True si la clase declara `__slots__` en su cuerpo."""
    for stmt in node.body:
        if isinstance(stmt, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "__slots__" for t in stmt.targets
        ):
            return True
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.target.id == "__slots__":
            return True
    return False


def _is_self_attr(node: ast.AST) -> bool:
    return isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self"


def _stmt_mutates_self(stmt: ast.AST) -> bool:
    if isinstance(stmt, (ast.Assign, ast.Delete)):
        return any(_is_self_attr(t) for t in stmt.targets)
    if isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
        return _is_self_attr(stmt.target)
    return False


def _mutates_self(node: ast.ClassDef) -> bool:
    """True si algún método de la clase reasigna o elimina un atributo de `self`."""
    for stmt in node.body:
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(_stmt_mutates_self(sub) for sub in ast.walk(stmt)):
            return True
    return False


# Como ruff (PLR0912) y pylint (too-many-branches): se permiten hasta 12 ramas. Un umbral
# más bajo marcaría sobre todo funciones con cláusulas de guarda, que es justo el estilo que
# se quiere fomentar.
MAX_BRANCHES = 12


class SOLIDAuditor(ast.NodeVisitor):
    """
    Evaluador estático de principios SOLID y arquitectura/fiabilidad Python:
    SRP, DIP, OCP, Cláusulas de Guarda (Fail Fast), Higiene de Excepciones,
    Inmutabilidad/Estado y Contratos de Datos (@dataclass con slots).
    """

    def __init__(self, filename: str) -> None:
        self.filename: str = filename
        self.findings: List[Tuple[int, str, str, str]] = []
        self._imports = ImportMap("")

    def visit_Module(self, node: ast.Module) -> None:
        self._imports = ImportMap.from_tree(node)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        # El principio de responsabilidad única (SRP) alerta clases monolíticas con más de diez métodos declarados.
        methods = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        if len(methods) > 10:
            self.findings.append((
                node.lineno,
                "SRP",
                "MEDIO",
                f"La clase '{node.name}' contiene {len(methods)} métodos. Considera dividirla en clases más pequeñas especializadas.",
            ))

        # Inspeccionar el constructor para detectar acoplamiento concreto contrario al principio de inversión de dependencias (DIP).
        init_func = next((m for m in methods if m.name == "__init__"), None)
        if init_func:
            self._audit_init_dip(init_func)

        # Verificar que las dataclasses definan slots=True (o __slots__) para evitar __dict__ por instancia.
        self._check_dataclass_contract(node)

        self.generic_visit(node)

    def _check_dataclass_contract(self, node: ast.ClassDef) -> None:
        if _defines_slots(node):
            return
        for dec in node.decorator_list:
            is_dc, has_slots = _is_dataclass_decorator(dec)
            if not is_dc or has_slots:
                continue
            if _mutates_self(node):
                advice = "Considera '@dataclass(slots=True)' (Python 3.10+) o '__slots__' para menor huella de memoria."
            else:
                advice = (
                    "Considera '@dataclass(frozen=True, slots=True)' (Python 3.10+; o '__slots__' en 3.9) "
                    "para contratos inmutables y menor huella de memoria."
                )
            self.findings.append((
                node.lineno,
                "DATA-CONTRACT",
                "BAJO",
                f"La dataclass '{node.name}' no especifica 'slots=True'. {advice}",
            ))
            return

    def _is_ignored_di_name(self, name: str) -> bool:
        if not name or not name[0].isupper():
            return True
        if name in _BUILTIN_NAMES or name in _STDLIB_VALUE_TYPES or name.endswith(_EXCEPTION_SUFFIXES):
            return True
        origin_mod = self._imports.names.get(name, "").split(".")[0]
        return origin_mod in _STDLIB_VALUE_MODULES

    def _audit_init_dip(self, init_func: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> None:
        stack: List[ast.AST] = list(reversed(init_func.body))
        while stack:
            curr = stack.pop()
            if isinstance(curr, (ast.Raise, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(curr, ast.Call) and isinstance(curr.func, ast.Name):
                name = curr.func.id
                if not self._is_ignored_di_name(name):
                    self.findings.append((
                        curr.lineno,
                        "DIP",
                        "BAJO",
                        f"Instanciación directa de '{name}' dentro de __init__. Considera aplicar Inyección de Dependencias.",
                    ))
            stack.extend(reversed(list(ast.iter_child_nodes(curr))))

    @staticmethod
    def _count_local_ifs(func_node: ast.AST) -> int:
        """Cuenta nodos ast.If de la función actual sin entrar en funciones/clases anidadas."""
        count = 0
        stack = list(ast.iter_child_nodes(func_node))
        while stack:
            curr = stack.pop()
            if isinstance(curr, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(curr, ast.If):
                count += 1
            stack.extend(ast.iter_child_nodes(curr))
        return count

    @classmethod
    def _node_depth(cls, node: ast.AST, depth: int) -> int:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return depth
        if isinstance(node, ast.If):
            branch_depth = depth + 1
            max_depth = max([branch_depth] + [cls._node_depth(stmt, branch_depth) for stmt in node.body])
            if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
                # En cadenas elif secuenciales la rama else actúa como selector plano al mismo nivel de abstracción;
                # mantener depth evita penalizar falsamente el anidamiento vertical en _max_nesting_depth.
                return max(max_depth, cls._node_depth(node.orelse[0], depth))
            return max([max_depth] + [cls._node_depth(stmt, branch_depth) for stmt in node.orelse])
        if isinstance(node, _CONTROL_FLOW_TYPES):
            inner_depth = depth + 1
            return max([inner_depth] + [cls._node_depth(child, inner_depth) for child in ast.iter_child_nodes(node)])
        return max([depth] + [cls._node_depth(child, depth) for child in ast.iter_child_nodes(node)])

    @classmethod
    def _max_nesting_depth(cls, func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> int:
        """Calcula la profundidad máxima de control de flujo sin contar cadenas 'elif' como niveles extra."""
        return max([0] + [cls._node_depth(stmt, 0) for stmt in func_node.body])

    def _check_function(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> None:
        # Las cadenas extensas de bifurcaciones condicionales indican violación del principio Abierto/Cerrado (OCP)
        # y sugieren despacho polimórfico o tablas de estrategias extensibles.
        if_count = self._count_local_ifs(node)
        if if_count > MAX_BRANCHES:
            self.findings.append((
                node.lineno,
                "OCP",
                "MEDIO",
                f"La función/método '{node.name}' posee {if_count} bifurcaciones 'if/elif' "
                f"(máximo recomendado: {MAX_BRANCHES}). Evalúa usar el patrón Estrategia o Polimorfismo.",
            ))

        # Limitar el anidamiento máximo de bloques a tres niveles promueve retornos tempranos y lectura plana.
        max_depth = self._max_nesting_depth(node)
        if max_depth > 3:
            self.findings.append((
                node.lineno,
                "GUARD",
                "MEDIO",
                f"La función '{node.name}' alcanza {max_depth} niveles de anidamiento (> 3). "
                "Aplica Cláusulas de Guarda (Guard Clauses) y retornos tempranos para aplanar la lógica.",
            ))

        # En Python las expresiones por defecto se evalúan una única vez al definir la función;
        # colecciones mutables compartidas entre invocaciones provocan corrupción silenciosa de estado.
        defaults = list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]
        if any(_is_mutable_default_expr(d) for d in defaults):
            self.findings.append((
                node.lineno,
                "STATE-SAFETY",
                "ALTO",
                f"Argumento por defecto mutable en '{node.name}'. Usa 'None' como valor por defecto e inicializa dentro de la función.",
            ))

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function(node)

    def visit_Global(self, node: ast.Global) -> None:
        self.findings.append((
            node.lineno,
            "STATE-SAFETY",
            "MEDIO",
            f"Uso de estado mutable global ('global {', '.join(node.names)}'). "
            "Prefiere funciones puras o inyección explícita de estado.",
        ))
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        # Exigir higiene de excepciones: evitar bloques vacíos, retornos silenciosos y pérdida de __cause__.
        is_broad = _is_broad_exception_type(node.type)
        if node.type is None:
            self.findings.append((
                node.lineno,
                "EXCEPTION-HYGIENE",
                "ALTO",
                "Cláusula 'except:' desnuda captura BaseException/SystemExit/KeyboardInterrupt. "
                "Captura excepciones específicas y registra o propaga el fallo.",
            ))
        elif len(node.body) == 1:
            stmt = node.body[0]
            if isinstance(stmt, ast.Pass) or (
                isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis
            ):
                self.findings.append((
                    node.lineno,
                    "EXCEPTION-HYGIENE",
                    "ALTO",
                    "Bloque 'except' silencia la excepción con 'pass'/'...'. Maneja el error explícitamente (Fail Fast).",
                ))
            elif is_broad and isinstance(stmt, ast.Return) and (
                stmt.value is None or (isinstance(stmt.value, ast.Constant) and stmt.value.value is None)
            ):
                self.findings.append((
                    node.lineno,
                    "EXCEPTION-HYGIENE",
                    "ALTO",
                    "Captura amplia retorna None silenciosamente ocultando el fallo. "
                    "Propaga una excepción específica o registra el error.",
                ))

        # Verificar raise NuevaExcepcion() sin 'from exc' dentro del bloque except.
        # No se exige 'from exc' si se relanza la misma variable capturada (raise e)
        # ni si se lanza una excepción de control de salida (SystemExit, etc.).
        _exit_exc_names = {"SystemExit", "KeyboardInterrupt", "GeneratorExit", "Exit"}
        stack: List[ast.AST] = list(node.body)
        while stack:
            curr = stack.pop()
            if isinstance(curr, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.ExceptHandler)):
                continue
            if isinstance(curr, ast.Raise) and curr.exc is not None and curr.cause is None:
                exc_node = curr.exc
                is_same_var = isinstance(exc_node, ast.Name) and node.name and exc_node.id == node.name
                exc_name = None
                if isinstance(exc_node, ast.Name):
                    exc_name = exc_node.id
                elif isinstance(exc_node, ast.Call):
                    if isinstance(exc_node.func, ast.Name):
                        exc_name = exc_node.func.id
                    elif isinstance(exc_node.func, ast.Attribute):
                        exc_name = exc_node.func.attr
                if is_same_var or exc_name in _exit_exc_names:
                    stack.extend(ast.iter_child_nodes(curr))
                    continue
                self.findings.append((
                    curr.lineno,
                    "EXCEPTION-HYGIENE",
                    "ALTO",
                    "Se lanza una nueva excepción dentro de 'except' sin encadenamiento 'from exc'. "
                    "Usa 'raise ... from exc' para conservar el stack trace original.",
                ))
            stack.extend(ast.iter_child_nodes(curr))

        self.generic_visit(node)


class SOLIDChecker:
    """
    Analizador de adherencia a principios de diseño limpio, arquitectura SOLID y fiabilidad.
    """

    @staticmethod
    def audit_file(filepath: str) -> List[Tuple[int, str, str, str]]:
        """
        Audita un archivo Python retornando hallazgos (Línea, Principio, Nivel, Recomendación).
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            tree = ast.parse(content, filename=filepath)
        except FileNotFoundError:
            return [(0, "N/A", "ERROR", f"Archivo '{filepath}' no encontrado.")]
        except (IsADirectoryError, PermissionError, OSError, SyntaxError, UnicodeDecodeError, ValueError, TypeError, RecursionError) as e:
            return [(0, "AST", "ERROR", f"Error en análisis SOLID: {e}")]

        auditor = SOLIDAuditor(filepath)
        auditor.visit(tree)
        return auditor.findings
