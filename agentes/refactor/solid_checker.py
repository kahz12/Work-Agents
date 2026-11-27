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
    """True when the except clause catches broadly: bare, Exception or BaseException (also inside a tuple)."""
    if exc_node is None:
        return True
    if isinstance(exc_node, ast.Name):
        return exc_node.id in ("Exception", "BaseException")
    if isinstance(exc_node, ast.Tuple):
        return any(_is_broad_exception_type(elt) for elt in exc_node.elts)
    return False


def _is_mutable_default_expr(expr: ast.AST) -> bool:
    """True for mutable literals, comprehensions or list()/dict()/set() calls used as default values."""
    if isinstance(expr, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)):
        return True
    return isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name) and expr.func.id in ("list", "dict", "set")


def _is_dataclass_decorator(dec: ast.AST) -> Tuple[bool, bool]:
    """
    (is_dataclass, has_slots_true) for a decorator: @dataclass, @dataclasses.dataclass or a
    call to either with keyword arguments.
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
    """True when the class body declares `__slots__`."""
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
    """True when any method of the class reassigns or deletes an attribute of `self`."""
    for stmt in node.body:
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(_stmt_mutates_self(sub) for sub in ast.walk(stmt)):
            return True
    return False


# Same limit as ruff (PLR0912) and pylint (too-many-branches): up to 12 branches. A lower
# threshold would mostly flag functions built from guard clauses, which is exactly the style
# this auditor wants to encourage.
MAX_BRANCHES = 12


class SOLIDAuditor(ast.NodeVisitor):
    """
    Static checks for SOLID principles plus Python design and reliability heuristics:
    SRP, DIP, OCP, guard clauses (fail fast), exception hygiene, state safety and data
    contracts (@dataclass with slots). Findings are (line, principle, level, message).
    """

    def __init__(self, filename: str) -> None:
        self.filename: str = filename
        self.findings: List[Tuple[int, str, str, str]] = []
        self._imports = ImportMap("")

    def visit_Module(self, node: ast.Module) -> None:
        self._imports = ImportMap.from_tree(node)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        # Single responsibility (SRP): more than ten methods suggests a class doing too much.
        methods = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        if len(methods) > 10:
            self.findings.append((
                node.lineno,
                "SRP",
                "MEDIUM",
                f"Class '{node.name}' has {len(methods)} methods. Consider splitting it into smaller, focused classes.",
            ))

        # Dependency inversion (DIP): collaborators built inside the constructor cannot be swapped out.
        init_func = next((m for m in methods if m.name == "__init__"), None)
        if init_func:
            self._audit_init_dip(init_func)

        # Dataclasses should use slots=True (or __slots__) to avoid a per-instance __dict__.
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
                advice = "Consider '@dataclass(slots=True)' (Python 3.10+) or '__slots__' for a smaller memory footprint."
            else:
                advice = (
                    "Consider '@dataclass(frozen=True, slots=True)' (Python 3.10+; or '__slots__' on 3.9) "
                    "for an immutable contract and a smaller memory footprint."
                )
            self.findings.append((
                node.lineno,
                "DATA-CONTRACT",
                "LOW",
                f"Dataclass '{node.name}' does not set 'slots=True'. {advice}",
            ))
            return

    def _is_ignored_di_name(self, name: str) -> bool:
        """
        Names whose direct instantiation is fine: anything not CamelCase, builtins, exceptions
        and standard-library value types (Path, Lock, Decimal...), which are values rather than
        collaborators worth injecting.
        """
        if not name or not name[0].isupper():
            return True
        if name in _BUILTIN_NAMES or name in _STDLIB_VALUE_TYPES or name.endswith(_EXCEPTION_SUFFIXES):
            return True
        origin_mod = self._imports.names.get(name, "").split(".")[0]
        return origin_mod in _STDLIB_VALUE_MODULES

    def _audit_init_dip(self, init_func: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> None:
        """
        Flag classes instantiated inside __init__. Raise statements and nested definitions are
        skipped: building the exception you raise is not a hidden dependency.
        """
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
                        "LOW",
                        f"'{name}' is instantiated directly inside __init__. Consider injecting it as a dependency.",
                    ))
            stack.extend(reversed(list(ast.iter_child_nodes(curr))))

    @staticmethod
    def _count_local_ifs(func_node: ast.AST) -> int:
        """Count the ast.If nodes of this function, without descending into nested functions or classes."""
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
        """Deepest control-flow nesting reached inside node, starting from depth."""
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return depth
        if isinstance(node, ast.If):
            branch_depth = depth + 1
            max_depth = max([branch_depth] + [cls._node_depth(stmt, branch_depth) for stmt in node.body])
            if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
                # An elif is parsed as an If nested in the else branch, but it reads as a flat
                # selector at the same level, so it keeps the current depth instead of adding one.
                return max(max_depth, cls._node_depth(node.orelse[0], depth))
            return max([max_depth] + [cls._node_depth(stmt, branch_depth) for stmt in node.orelse])
        if isinstance(node, _CONTROL_FLOW_TYPES):
            inner_depth = depth + 1
            return max([inner_depth] + [cls._node_depth(child, inner_depth) for child in ast.iter_child_nodes(node)])
        return max([depth] + [cls._node_depth(child, depth) for child in ast.iter_child_nodes(node)])

    @classmethod
    def _max_nesting_depth(cls, func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> int:
        """Maximum control-flow nesting depth of the function; elif chains do not add levels."""
        return max([0] + [cls._node_depth(stmt, 0) for stmt in func_node.body])

    def _check_function(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> None:
        # Open/closed (OCP): a long chain of conditionals usually wants polymorphic dispatch or a
        # strategy table, so new cases can be added without editing the function.
        if_count = self._count_local_ifs(node)
        if if_count > MAX_BRANCHES:
            self.findings.append((
                node.lineno,
                "OCP",
                "MEDIUM",
                f"Function '{node.name}' has {if_count} 'if/elif' branches "
                f"(recommended maximum: {MAX_BRANCHES}). Consider the Strategy pattern or polymorphism.",
            ))

        # More than three levels of nesting: guard clauses and early returns would flatten it.
        max_depth = self._max_nesting_depth(node)
        if max_depth > 3:
            self.findings.append((
                node.lineno,
                "GUARD",
                "MEDIUM",
                f"Function '{node.name}' reaches {max_depth} levels of nesting (> 3). "
                "Use guard clauses and early returns to flatten the logic.",
            ))

        # Default expressions are evaluated once, when the function is defined, so a mutable
        # default is shared by every call and silently accumulates state.
        defaults = list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]
        if any(_is_mutable_default_expr(d) for d in defaults):
            self.findings.append((
                node.lineno,
                "STATE-SAFETY",
                "HIGH",
                f"Mutable default argument in '{node.name}'. Use None as the default and create the value inside the function.",
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
            "MEDIUM",
            f"Use of global mutable state ('global {', '.join(node.names)}'). "
            "Prefer pure functions or passing the state explicitly.",
        ))
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        # Exception hygiene: no empty handlers, no silent `return None`, no lost __cause__.
        is_broad = _is_broad_exception_type(node.type)
        if node.type is None:
            self.findings.append((
                node.lineno,
                "EXCEPTION-HYGIENE",
                "HIGH",
                "A bare 'except:' clause catches BaseException, including SystemExit and KeyboardInterrupt. "
                "Catch specific exceptions and log or propagate the failure.",
            ))
        elif len(node.body) == 1:
            stmt = node.body[0]
            if isinstance(stmt, ast.Pass) or (
                isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis
            ):
                self.findings.append((
                    node.lineno,
                    "EXCEPTION-HYGIENE",
                    "HIGH",
                    "The 'except' block silences the exception with 'pass'/'...'. Handle the error explicitly (fail fast).",
                ))
            elif is_broad and isinstance(stmt, ast.Return) and (
                stmt.value is None or (isinstance(stmt.value, ast.Constant) and stmt.value.value is None)
            ):
                self.findings.append((
                    node.lineno,
                    "EXCEPTION-HYGIENE",
                    "HIGH",
                    "A broad catch silently returns None, hiding the failure. "
                    "Raise a specific exception or log the error.",
                ))

        # A new exception raised inside the handler without `from exc` loses the original
        # traceback. Re-raising the caught variable itself (raise e) is fine, and so are
        # exit-control exceptions (SystemExit and friends), which carry no cause worth keeping.
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
                    "HIGH",
                    "A new exception is raised inside 'except' without chaining it with 'from exc'. "
                    "Use 'raise ... from exc' to keep the original traceback.",
                ))
            stack.extend(ast.iter_child_nodes(curr))

        self.generic_visit(node)


class SOLIDChecker:
    """
    Entry point for the SOLID and reliability audit of a single file.
    """

    @staticmethod
    def audit_file(filepath: str) -> List[Tuple[int, str, str, str]]:
        """
        Audit a Python file. Returns (line, principle, level, recommendation) tuples; a file
        that cannot be read or parsed yields a single ERROR entry.
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            tree = ast.parse(content, filename=filepath)
        except FileNotFoundError:
            return [(0, "N/A", "ERROR", f"File '{filepath}' not found.")]
        except (IsADirectoryError, PermissionError, OSError, SyntaxError, UnicodeDecodeError, ValueError, TypeError, RecursionError) as e:
            return [(0, "AST", "ERROR", f"SOLID analysis error: {e}")]

        auditor = SOLIDAuditor(filepath)
        auditor.visit(tree)
        return auditor.findings
