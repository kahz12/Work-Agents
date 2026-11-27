import ast
from typing import Any, Dict, Iterable, List, Set, Tuple

_EXEC_HTTP_METHODS = frozenset({
    "get", "post", "put", "delete", "patch", "head", "options", "request",
})
_DB_RECEIVER_HINTS = ("cur", "cursor", "db", "conn", "connection", "session", "tx", "sql", "engine")


class CyclomaticComplexityVisitor(ast.NodeVisitor):
    """
    Cyclomatic complexity of one function: 1 plus one per decision point (if, loop, except
    handler, and each extra operand of a boolean operator). Nested functions are not counted
    towards the enclosing one.
    """

    def __init__(self) -> None:
        # Every function starts at 1: the single path through straight-line code.
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
    """
    Cognitive complexity of one function: like cyclomatic complexity, but each control-flow
    structure costs 1 plus its nesting level, so deeply nested code scores higher than the
    same number of flat branches.
    """

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
    """Dotted name of an ast.Attribute/ast.Name chain (e.g. 'urllib.request.urlopen')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _attr_chain(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _is_zero_int_constant(node: ast.AST) -> bool:
    """True only for the integer literal 0 (False is excluded, even though it equals 0)."""
    return isinstance(node, ast.Constant) and type(node.value) is int and node.value == 0


_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def _bound_names(loop: ast.AST) -> Set[str]:
    """Names a loop rebinds on every iteration: its target and every assignment in its body.

    Nested functions, lambdas and classes have their own scope and are not walked.
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


# A membership test against a small literal of constants is cheap enough (and often the
# clearest code), so only literals of at least this many constants are reported.
_MIN_CONST_LOOKUP_LEN = 9


def _is_loop_invariant(exprs: Iterable[ast.AST], bound: Set[str]) -> bool:
    """True when the expressions evaluate to the same value on every iteration of the loop that binds `bound`.

    A call inside the expressions (other than re.escape) may return something new each time, so
    it counts as variable: missing a hoistable expression is better than flagging one that is not.
    """
    for expr in exprs:
        for node in ast.walk(expr):
            if isinstance(node, ast.Name) and node.id in bound:
                return False
            if isinstance(node, ast.Call) and _attr_chain(node.func) != "re.escape":
                return False
    return True


def _is_str_expression(node: ast.AST) -> bool:
    """Conservative check for str literals, f-strings, str(...) and .join()/.format() results."""
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


# --- Call rules of the performance auditor --------------------------------------
# Each rule returns its findings as (line, category, level, recommendation).

_PerfFinding = Tuple[int, str, str, str]
_BIG_O = "HIGH IMPACT - BIG-O COMPLEXITY"
_MEMORY = "MEDIUM IMPACT - MEMORY FOOTPRINT"
_BLOCKING_IO = "HIGH IMPACT - BLOCKING I/O"
_URLOPEN_CHAINS = ("urlopen", "urllib.request.urlopen")


def _is_requests_call(func: ast.AST) -> bool:
    return (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
            and func.value.id == "requests" and func.attr in _EXEC_HTTP_METHODS)


# List methods that shift every element when they work on index 0: (argument count, recommendation).
_FRONT_SHIFTS = {
    "pop": (1, "'.pop(0)' inside a loop: each call shifts the whole list, O(n). "
               "Use collections.deque.popleft() for O(1) FIFO operations."),
    "insert": (2, "'.insert(0, ...)' inside a loop: each call shifts the whole list, O(n). "
                  "Use collections.deque.appendleft(), which is O(1)."),
}


def _list_method_findings(node: ast.Call, in_loop: bool) -> List[_PerfFinding]:
    """pop(0) and insert(0, ...) repeated in a loop, and readlines(), which reads the whole file at once."""
    func = node.func
    if not isinstance(func, ast.Attribute):
        return []
    if func.attr in _FRONT_SHIFTS:
        return _front_shift_findings(node, func, in_loop)
    if func.attr == "readlines" and not node.args and not node.keywords:
        return [(node.lineno, _MEMORY, "MEDIUM",
                 "'.readlines()' loads every line into memory at once. "
                 "Iterate over the file object directly ('for line in f:') or use a generator.")]
    return []


def _front_shift_findings(node: ast.Call, func: ast.Attribute, in_loop: bool) -> List[_PerfFinding]:
    """
    pop(0) and insert(0, ...) shift the whole list: O(n) per call. That only matters when it is
    repeated in a loop (O(n²) overall); a one-off call, such as prepending a path to sys.path at
    start-up or a pop(0) that hands out a test double's next response, is not a bottleneck.
    """
    arity, message = _FRONT_SHIFTS[func.attr]
    if len(node.args) != arity or not _is_zero_int_constant(node.args[0]):
        return []
    if not in_loop or _attr_chain(func.value) == "sys.path":
        return []
    return [(node.lineno, _BIG_O, "HIGH", message)]


def _regex_in_loop_findings(node: ast.Call, chain: str, bound: Set[str]) -> List[_PerfFinding]:
    """
    re.compile() with the same pattern on every iteration can be hoisted out of the loop. When the
    pattern depends on what the loop rebinds (for pat in patterns: re.compile(pat)), each iteration
    compiles a different one and there is nothing to hoist.
    """
    if chain != "re.compile" or not _is_loop_invariant([*node.args, *(kw.value for kw in node.keywords)], bound):
        return []
    return [(node.lineno, _BIG_O, "HIGH",
             "'re.compile(...)' is called with the same pattern on every iteration of a loop. "
             "Hoist it out of the loop or to module level.")]


def _blocking_call_name(func: ast.AST, chain: str) -> str:
    """Display name of the call when it is synchronous I/O or a blocking wait; "" otherwise."""
    if chain == "time.sleep":
        return "time.sleep()"
    if _is_requests_call(func) or chain in _URLOPEN_CHAINS:
        return f"{chain}()"
    if isinstance(func, ast.Name) and func.id == "open":
        return "open()"
    return ""


def _blocking_in_async_findings(node: ast.Call, chain: str) -> List[_PerfFinding]:
    """Synchronous I/O or waiting inside a coroutine stalls the whole asyncio scheduler."""
    name = _blocking_call_name(node.func, chain)
    if not name:
        return []
    return [(node.lineno, _BLOCKING_IO, "HIGH",
             f"Blocking synchronous call '{name}' inside 'async def' freezes the event loop. "
             "Use asyncio.sleep, httpx.AsyncClient, aiofiles or asyncio.to_thread().")]


def _is_db_execute(func: ast.AST) -> bool:
    return (isinstance(func, ast.Attribute) and func.attr == "execute"
            and any(hint in _attr_chain(func.value).lower() for hint in _DB_RECEIVER_HINTS))


def _n_plus_one_findings(node: ast.Call, chain: str) -> List[_PerfFinding]:
    """
    HTTP requests without a reused session, and SQL queries issued per iteration, multiply latency:
    the N+1 pattern, with one TCP/TLS handshake or one database round trip per iteration.
    """
    if _is_requests_call(node.func) or chain in _URLOPEN_CHAINS:
        return [(node.lineno, _BLOCKING_IO, "HIGH",
                 f"HTTP request '{chain}()' inside a loop (N+1 pattern without connection pooling). "
                 "Reuse a requests.Session() / httpx.Client or batch the operation.")]
    if chain == "sqlite3.connect" or _is_db_execute(node.func):
        return [(node.lineno, _BLOCKING_IO, "HIGH",
                 f"Database operation '{chain or 'execute'}()' inside a loop (N+1 problem). "
                 "Reuse the connection and batch the queries, for example with executemany().")]
    return []


class PerformanceAuditor(ast.NodeVisitor):
    """
    Static performance audit: Big-O pitfalls, memory footprint, and blocking I/O in loops and
    in the event loop. Each finding is a (line, category, level, recommendation) tuple.
    """

    def __init__(self, filename: str) -> None:
        self.filename: str = filename
        self.findings: List[Tuple[int, str, str, str]] = []
        self._loop_depth: int = 0
        # Names each enclosing loop rebinds per iteration, innermost last (see _bound_names).
        self._loop_bound: List[Set[str]] = []
        self._in_async_func: bool = False
        self._str_vars: Set[str] = set()

    def _visit_scoped(self, node: ast.AST, *, is_async: bool) -> None:
        """Visit a new scope with fresh loop and string-variable state, restoring the outer state after."""
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
                _MEMORY,
                "MEDIUM",
                f"Incremental string concatenation '{node.target.id} += ...' inside a loop is O(n²). "
                "Collect the pieces in a list and ''.join(...) them at the end, or use io.StringIO.",
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
                        _BIG_O,
                        "HIGH",
                        "O(n) membership test against a list/tuple literal inside a loop. "
                        "Build a 'set' or 'dict' once, outside the loop, for O(1) lookups.",
                    ))
                    break
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        chain = _attr_chain(node.func)
        in_loop = self._loop_depth > 0
        # Findings for one call are emitted in a fixed order: list methods, regex, blocking I/O in
        # async code, N+1. Callers and tests rely on that order.
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
    """Line numbers covered by module, class or function docstrings (counted as comment lines)."""
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
    Per-file maintainability metrics (lines of code, comment ratio, cyclomatic and cognitive
    complexity) plus the Big-O / memory / I/O performance audit.
    """

    @staticmethod
    def _parse_file_ast(filepath: str) -> Tuple[str, ast.Module]:
        """Read the file once and return its content and its AST."""
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        tree = ast.parse(content, filename=filepath)
        return content, tree

    @staticmethod
    def audit_performance(filepath: str) -> List[Tuple[int, str, str, str]]:
        """
        Look for Big-O, memory and blocking-I/O bottlenecks in a Python file.
        Returns (line, category, level, recommendation) tuples, without duplicates.
        """
        try:
            _, tree = CodeMetricsCalculator._parse_file_ast(filepath)
        except FileNotFoundError:
            return [(0, "N/A", "ERROR", f"File '{filepath}' does not exist.")]
        except (IsADirectoryError, PermissionError, OSError, UnicodeDecodeError, SyntaxError, ValueError, TypeError, RecursionError) as e:
            return [(0, "AST", "ERROR", f"Performance audit error: {e}")]

        auditor = PerformanceAuditor(filepath)
        auditor.visit(tree)
        return list(dict.fromkeys(auditor.findings))

    @staticmethod
    def calculate_file_metrics(filepath: str) -> Dict[str, Any]:
        """
        Lines of code, cyclomatic and cognitive complexity and performance findings, from a
        single read and parse of the file. Returns {"error": ...} when it cannot be analysed.
        """
        try:
            content, tree = CodeMetricsCalculator._parse_file_ast(filepath)
        except FileNotFoundError:
            return {"error": f"File '{filepath}' does not exist."}
        except (IsADirectoryError, PermissionError, OSError) as e:
            return {"error": f"Could not read '{filepath}': {e}"}
        except (SyntaxError, UnicodeDecodeError, ValueError, TypeError, RecursionError) as e:
            return {"error": f"Could not parse the AST: {e}"}

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
