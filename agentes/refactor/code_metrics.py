import ast
from typing import Any, Dict, Iterable, List, Set, Tuple

_EXEC_HTTP_METHODS = frozenset({
    "get", "post", "put", "delete", "patch", "head", "options", "request",
})
_DB_RECEIVER_HINTS = ("cur", "cursor", "db", "conn", "connection", "session", "tx", "sql", "engine")


class CyclomaticComplexityVisitor(ast.NodeVisitor):
    """Calculador de Complejidad Ciclomática mediante análisis del árbol AST."""

    def __init__(self) -> None:
        # Toda función parte de complejidad base 1 correspondiente a su ruta de ejecución secuencial mínima.
        self.complexity: int = 1
        self._inside_function: bool = False

    def _visit_func(self, node: ast.AST) -> None:
        if self._inside_function:
            return
        self._inside_function = True
        try:
            self.generic_visit(node)
        finally:
            self._inside_function = False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_func(node)

    def visit_If(self, node: ast.If) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        self.complexity += len(node.values) - 1
        self.generic_visit(node)


class CognitiveComplexityVisitor(ast.NodeVisitor):
    """Calculador de Complejidad Cognitiva (evalúa el esfuerzo de comprensión considerando anidamiento)."""

    def __init__(self) -> None:
        self.cognitive_score: int = 0
        self.nesting_level: int = 0
        self._inside_function: bool = False

    def _visit_func(self, node: ast.AST) -> None:
        if self._inside_function:
            return
        self._inside_function = True
        try:
            self.generic_visit(node)
        finally:
            self._inside_function = False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_func(node)

    def _increment(self, node: ast.AST) -> None:
        self.cognitive_score += (1 + self.nesting_level)
        self.nesting_level += 1
        try:
            self.generic_visit(node)
        finally:
            self.nesting_level -= 1

    def visit_If(self, node: ast.If) -> None:
        self._increment(node)

    def visit_For(self, node: ast.For) -> None:
        self._increment(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._increment(node)

    def visit_While(self, node: ast.While) -> None:
        self._increment(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self._increment(node)


def _attr_chain(node: ast.AST) -> str:
    """Construye la cadena de nombres de un nodo ast.Attribute/ast.Name (p. ej. 'urllib.request.urlopen')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _attr_chain(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _is_zero_int_constant(node: ast.AST) -> bool:
    """Retorna True únicamente si el nodo es el entero literal 0 (excluyendo bool)."""
    return isinstance(node, ast.Constant) and type(node.value) is int and node.value == 0


_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def _bound_names(loop: ast.AST) -> Set[str]:
    """Nombres que un bucle vuelve a ligar en cada vuelta: su variable y toda asignación del cuerpo.

    Las funciones, lambdas y clases anidadas tienen su propio ámbito y no se recorren.
    """
    bound: Set[str] = set()
    pending = list(ast.iter_child_nodes(loop))
    while pending:
        node = pending.pop()
        if isinstance(node, _SCOPES):
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, ast.alias):
            bound.add((node.asname or node.name).split(".")[0])
        pending.extend(ast.iter_child_nodes(node))
    return bound


_MIN_CONST_LOOKUP_LEN = 9


def _is_loop_invariant(exprs: Iterable[ast.AST], bound: Set[str]) -> bool:
    """True si las expresiones valen lo mismo en cada vuelta del bucle que liga `bound`.

    Una llamada dentro de las expresiones (salvo re.escape) puede devolver algo nuevo cada vez,
    así que cuenta como variable: mejor dejar pasar algo elevable que avisar de lo que no lo es.
    """
    for expr in exprs:
        for node in ast.walk(expr):
            if isinstance(node, ast.Name) and node.id in bound:
                return False
            if isinstance(node, ast.Call) and _attr_chain(node.func) != "re.escape":
                return False
    return True


def _is_str_expression(node: ast.AST) -> bool:
    """Heurística segura para detectar literales str, f-strings o conversiones str(...)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "str":
            return True
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("join", "format"):
            return True
    return False


# --- Reglas de llamadas del auditor de rendimiento ---------------------------------
# Cada regla devuelve sus hallazgos (línea, categoría, nivel, recomendación).

_PerfFinding = Tuple[int, str, str, str]
_BIG_O = "IMPACTO ALTO - COMPLEJIDAD BIG-O"
_MEMORY = "IMPACTO MEDIO - HUELLA DE MEMORIA"
_BLOCKING_IO = "IMPACTO ALTO - I/O BLOQUEANTE"
_URLOPEN_CHAINS = ("urlopen", "urllib.request.urlopen")


def _is_requests_call(func: ast.AST) -> bool:
    return (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
            and func.value.id == "requests" and func.attr in _EXEC_HTTP_METHODS)


# Métodos que desplazan toda la lista cuando operan en la posición 0: (argumentos, recomendación).
_FRONT_SHIFTS = {
    "pop": (1, "Uso de '.pop(0)' dentro de un bucle: cada llamada desplaza toda la lista en O(n). "
               "Usa collections.deque.popleft() para operaciones FIFO en O(1)."),
    "insert": (2, "Uso de '.insert(0, ...)' dentro de un bucle: cada llamada desplaza toda la lista en O(n). "
                  "Usa collections.deque.appendleft() en O(1)."),
}


def _list_method_findings(node: ast.Call, in_loop: bool) -> List[_PerfFinding]:
    """pop(0) e insert(0, ...) repetidos en un bucle, y readlines(), que lee el archivo entero."""
    func = node.func
    if not isinstance(func, ast.Attribute):
        return []
    if func.attr in _FRONT_SHIFTS:
        return _front_shift_findings(node, func, in_loop)
    if func.attr == "readlines" and not node.args and not node.keywords:
        return [(node.lineno, _MEMORY, "MEDIO",
                 "Llamada a '.readlines()' carga todas las líneas en RAM de una sola vez. "
                 "Itera directamente sobre el manejador de archivo ('for linea in f:') o usa generadores.")]
    return []


def _front_shift_findings(node: ast.Call, func: ast.Attribute, in_loop: bool) -> List[_PerfFinding]:
    """
    pop(0) e insert(0, ...) desplazan toda la lista: O(n) por llamada. Solo importa repetido en
    un bucle (O(n²) en total); una llamada suelta, como anteponer una ruta a sys.path al arrancar
    o un pop(0) que entrega la siguiente respuesta de un doble de test, no es un cuello de botella.
    """
    arity, message = _FRONT_SHIFTS[func.attr]
    if len(node.args) != arity or not _is_zero_int_constant(node.args[0]):
        return []
    if not in_loop or _attr_chain(func.value) == "sys.path":
        return []
    return [(node.lineno, _BIG_O, "ALTO", message)]


def _regex_in_loop_findings(node: ast.Call, chain: str, bound: Set[str]) -> List[_PerfFinding]:
    """
    re.compile() con el mismo patrón en cada vuelta se puede sacar del bucle. Si el patrón depende
    de lo que el bucle cambia (for pat in patrones: re.compile(pat)), cada vuelta compila uno
    distinto y no hay nada que elevar.
    """
    if chain != "re.compile" or not _is_loop_invariant([*node.args, *(kw.value for kw in node.keywords)], bound):
        return []
    return [(node.lineno, _BIG_O, "ALTO",
             "Compilación repetida de regex 're.compile(...)' dentro de un bucle. "
             "Aplica loop hoisting moviendo re.compile() fuera del bucle o a nivel de módulo.")]


def _blocking_call_name(func: ast.AST, chain: str) -> str:
    """Nombre de la llamada si es E/S o espera síncrona; cadena vacía si no lo es."""
    if chain == "time.sleep":
        return "time.sleep()"
    if _is_requests_call(func) or chain in _URLOPEN_CHAINS:
        return f"{chain}()"
    if isinstance(func, ast.Name) and func.id == "open":
        return "open()"
    return ""


def _blocking_in_async_findings(node: ast.Call, chain: str) -> List[_PerfFinding]:
    """Cualquier E/S o espera síncrona dentro de una corrutina detiene el planificador de asyncio."""
    name = _blocking_call_name(node.func, chain)
    if not name:
        return []
    return [(node.lineno, _BLOCKING_IO, "ALTO",
             f"Llamada síncrona bloqueante '{name}' dentro de 'async def' congela el Event Loop. "
             "Usa asyncio.sleep, httpx.AsyncClient, aiofiles o asyncio.to_thread().")]


def _is_db_execute(func: ast.AST) -> bool:
    return (isinstance(func, ast.Attribute) and func.attr == "execute"
            and any(hint in _attr_chain(func.value).lower() for hint in _DB_RECEIVER_HINTS))


def _n_plus_one_findings(node: ast.Call, chain: str) -> List[_PerfFinding]:
    """
    Peticiones HTTP sin reutilizar sesión y consultas SQL por iteración multiplican la latencia
    (patrón N+1, un handshake TCP/TLS o una ida y vuelta a la base de datos por vuelta).
    """
    if _is_requests_call(node.func) or chain in _URLOPEN_CHAINS:
        return [(node.lineno, _BLOCKING_IO, "ALTO",
                 f"Petición HTTP '{chain}()' dentro de un bucle (patrón N+1 sin Connection Pooling). "
                 "Reutiliza un objeto requests.Session() / httpx.Client o agrupa la operación.")]
    if chain == "sqlite3.connect" or _is_db_execute(node.func):
        return [(node.lineno, _BLOCKING_IO, "ALTO",
                 f"Operación de base de datos '{chain or 'execute'}()' dentro de un bucle (problema N+1). "
                 "Reutiliza la conexión y agrupa consultas mediante batching o executemany().")]
    return []


class PerformanceAuditor(ast.NodeVisitor):
    """
    Auditor estático de rendimiento Big-O, huella de memoria e higiene de Event Loop / I/O.
    Cada hallazgo es una tupla: (línea, categoría, nivel, recomendación).
    """

    def __init__(self, filename: str) -> None:
        self.filename: str = filename
        self.findings: List[Tuple[int, str, str, str]] = []
        self._loop_depth: int = 0
        # Nombres que liga cada bucle envolvente en cada vuelta, el más interno al final (ver _bound_names).
        self._loop_bound: List[Set[str]] = []
        self._in_async_func: bool = False
        self._str_vars: Set[str] = set()

    def _visit_scoped(self, node: ast.AST, *, is_async: bool) -> None:
        prev_loop = self._loop_depth
        prev_bound = self._loop_bound
        prev_async = self._in_async_func
        prev_strs = self._str_vars
        self._loop_depth = 0
        self._loop_bound = []
        self._in_async_func = is_async
        self._str_vars = set()
        try:
            self.generic_visit(node)
        finally:
            self._loop_depth = prev_loop
            self._loop_bound = prev_bound
            self._in_async_func = prev_async
            self._str_vars = prev_strs

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_scoped(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_scoped(node, is_async=True)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_scoped(node, is_async=False)

    def _visit_loop(self, node: ast.AST) -> None:
        self._loop_depth += 1
        self._loop_bound.append(_bound_names(node))
        try:
            self.generic_visit(node)
        finally:
            self._loop_depth -= 1
            self._loop_bound.pop()

    def visit_For(self, node: ast.For) -> None:
        self._visit_loop(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_loop(node)

    def visit_While(self, node: ast.While) -> None:
        self._visit_loop(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if _is_str_expression(node.value):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    self._str_vars.add(tgt.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        is_str_ann = isinstance(node.annotation, ast.Name) and node.annotation.id == "str"
        if isinstance(node.target, ast.Name) and (is_str_ann or (node.value is not None and _is_str_expression(node.value))):
            self._str_vars.add(node.target.id)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if (
            self._loop_depth > 0
            and isinstance(node.op, ast.Add)
            and isinstance(node.target, ast.Name)
            and (_is_str_expression(node.value) or node.target.id in self._str_vars)
        ):
            self.findings.append((
                node.lineno,
                "IMPACTO MEDIO - HUELLA DE MEMORIA",
                "MEDIO",
                f"Concatenación incremental de string '{node.target.id} += ...' dentro de un bucle es O(n²). "
                "Acumula en una lista y une al final con ''.join(...) o usa io.StringIO.",
            ))
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        if self._loop_depth > 0:
            bound = self._loop_bound[-1]
            for op, comp in zip(node.ops, node.comparators):
                if not (isinstance(op, (ast.In, ast.NotIn)) and isinstance(comp, (ast.List, ast.Tuple))):
                    continue
                all_const = all(isinstance(e, ast.Constant) for e in comp.elts)
                min_len = _MIN_CONST_LOOKUP_LEN if all_const else 2
                if len(comp.elts) >= min_len and _is_loop_invariant(comp.elts, bound):
                    self.findings.append((
                        node.lineno,
                        "IMPACTO ALTO - COMPLEJIDAD BIG-O",
                        "ALTO",
                        "Búsqueda secuencial O(n) sobre list/tuple literal dentro de un bucle. "
                        "Precalcula un 'set' o 'dict' fuera del bucle para búsquedas O(1).",
                    ))
                    break
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        chain = _attr_chain(node.func)
        in_loop = self._loop_depth > 0
        # Mismo orden que siempre: métodos de lista, regex, E/S bloqueante en async y N+1.
        self.findings.extend(_list_method_findings(node, in_loop))
        if in_loop:
            self.findings.extend(_regex_in_loop_findings(node, chain, self._loop_bound[-1]))
        if self._in_async_func:
            self.findings.extend(_blocking_in_async_findings(node, chain))
        if in_loop:
            self.findings.extend(_n_plus_one_findings(node, chain))
        self.generic_visit(node)


_DOCSTRING_OWNERS = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)


def _docstring_line_numbers(tree: ast.AST) -> Set[int]:
    """Devuelve los números de línea ocupados por docstrings de módulo, clase o función."""
    lines: Set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, _DOCSTRING_OWNERS) or not node.body:
            continue
        first = node.body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
            end = first.end_lineno or first.lineno
            lines.update(range(first.lineno, end + 1))
    return lines


class CodeMetricsCalculator:
    """
    Calculador de métricas de legibilidad, mantenibilidad, complejidad ciclomática,
    complejidad cognitiva y auditoría de rendimiento Big-O / memoria / I/O.
    """

    @staticmethod
    def _parse_file_ast(filepath: str) -> Tuple[str, ast.Module]:
        """Lee el archivo una sola vez y devuelve su contenido y su árbol AST."""
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        tree = ast.parse(content, filename=filepath)
        return content, tree

    @staticmethod
    def audit_performance(filepath: str) -> List[Tuple[int, str, str, str]]:
        """
        Audita un archivo Python buscando cuellos de botella de Big-O, memoria e I/O bloqueante.
        Retorna lista de tuplas (línea, categoría, nivel, recomendación).
        """
        try:
            _, tree = CodeMetricsCalculator._parse_file_ast(filepath)
        except FileNotFoundError:
            return [(0, "N/A", "ERROR", f"El archivo '{filepath}' no existe.")]
        except (IsADirectoryError, PermissionError, OSError, UnicodeDecodeError, SyntaxError, ValueError, TypeError, RecursionError) as e:
            return [(0, "AST", "ERROR", f"Error en auditoría de rendimiento: {e}")]

        auditor = PerformanceAuditor(filepath)
        auditor.visit(tree)
        return list(dict.fromkeys(auditor.findings))

    @staticmethod
    def calculate_file_metrics(filepath: str) -> Dict[str, Any]:
        """
        Calcula Líneas de Código (LOC), Complejidad Ciclomática, Complejidad Cognitiva
        y hallazgos de rendimiento en una sola pasada de lectura y AST.
        """
        try:
            content, tree = CodeMetricsCalculator._parse_file_ast(filepath)
        except FileNotFoundError:
            return {"error": f"El archivo '{filepath}' no existe."}
        except (IsADirectoryError, PermissionError, OSError) as e:
            return {"error": f"No se pudo leer '{filepath}': {e}"}
        except (SyntaxError, UnicodeDecodeError, ValueError, TypeError, RecursionError) as e:
            return {"error": f"Error parseando AST: {e}"}

        doc_lines = _docstring_line_numbers(tree)
        total_loc = 0
        blank_lines = 0
        comment_lines = 0
        for idx, line in enumerate(content.splitlines(), 1):
            total_loc += 1
            stripped = line.strip()
            if not stripped:
                blank_lines += 1
            elif stripped.startswith("#") or idx in doc_lines:
                comment_lines += 1
        code_loc = total_loc - blank_lines - comment_lines

        func_complexities: List[Tuple[str, int, int, int]] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                cyc_vis = CyclomaticComplexityVisitor()
                cog_vis = CognitiveComplexityVisitor()
                cyc_vis.visit(node)
                cog_vis.visit(node)
                func_complexities.append((node.name, node.lineno, cyc_vis.complexity, cog_vis.cognitive_score))

        perf_auditor = PerformanceAuditor(filepath)
        perf_auditor.visit(tree)

        avg_complexity = (sum(c[2] for c in func_complexities) / len(func_complexities)) if func_complexities else 1.0
        avg_cognitive = (sum(c[3] for c in func_complexities) / len(func_complexities)) if func_complexities else 0.0

        return {
            "filepath": filepath,
            "total_lines": total_loc,
            "code_loc": code_loc,
            "comment_lines": comment_lines,
            "blank_lines": blank_lines,
            "comment_ratio": round((comment_lines / total_loc * 100), 2) if total_loc > 0 else 0,
            "functions_count": len(func_complexities),
            "avg_cyclomatic_complexity": round(avg_complexity, 2),
            "avg_cognitive_complexity": round(avg_cognitive, 2),
            "function_details": func_complexities,
            "performance_findings": list(dict.fromkeys(perf_auditor.findings)),
        }
