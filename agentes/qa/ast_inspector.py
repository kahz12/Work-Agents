"""
AST inspection of Python modules: signatures, raised exceptions, calls and I/O side effects.
"""
from __future__ import annotations

import ast
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .project import ProjectIndex, module_import
from .side_effects import ImportMap, classify

NON_DET_CALLS = frozenset({
    "time.time", "time.monotonic", "time.perf_counter", "time.sleep",
    "datetime.now", "datetime.utcnow", "date.today", "uuid.uuid4",
    "random.random", "random.randint", "random.randrange", "random.choice",
    "random.uniform", "os.getenv",
})
_NON_DET_CALLS = NON_DET_CALLS


def read_and_parse(source_filepath: str) -> ast.Module:
    """Read a Python source file and return its AST."""
    with open(source_filepath, "r", encoding="utf-8") as f:
        content = f.read()
    return ast.parse(content, filename=source_filepath)


def _regex_literal(msg: str) -> str:
    escaped = re.escape(msg)
    if '"' not in escaped and "\n" not in escaped and "\r" not in escaped:
        return f'r"{escaped}"'
    return repr(escaped)


def _attr_chain(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _attr_chain(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _parameter_names(args: ast.arguments) -> Set[str]:
    """Names of a function's positional, keyword-only, *args and **kwargs parameters."""
    names = {a.arg for a in args.args} | {a.arg for a in args.kwonlyargs}
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return names


def _extract_raise_info(node: ast.Raise) -> Optional[Tuple[str, Optional[str]]]:
    """
    (exception, message) of a raise statement. The message is the literal when there is one, ""
    when the exception is raised without arguments (raise KeyError() or raise KeyError, whose
    message is empty), and None when it is computed at runtime and cannot be known statically.
    """
    if node.exc is None:
        return None
    exc_name = ""
    msg: Optional[str] = None
    if isinstance(node.exc, ast.Call):
        exc_name = _attr_chain(node.exc.func) or getattr(node.exc.func, "id", "")
        if not node.exc.args:
            msg = ""
        elif isinstance(node.exc.args[0], ast.Constant) and isinstance(node.exc.args[0].value, str):
            msg = node.exc.args[0].value
    elif isinstance(node.exc, ast.Name):
        exc_name = node.exc.id
        msg = ""
    return (exc_name, msg) if exc_name else None


def _is_none_comparison(node: ast.Compare) -> bool:
    has_none = any(isinstance(c, ast.Constant) and c.value is None for c in [node.left] + list(node.comparators))
    has_eq_op = any(isinstance(op, (ast.Is, ast.IsNot, ast.Eq, ast.NotEq)) for op in node.ops)
    return has_none and has_eq_op


FuncNode = Union[ast.FunctionDef, ast.AsyncFunctionDef]


def body_nodes(func: FuncNode):
    """Nodes of a function body, without entering functions, lambdas or classes defined inside it."""
    pending: List[ast.AST] = list(func.body)
    while pending:
        node = pending.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            pending.extend(ast.iter_child_nodes(node))


def _name_of(node: ast.AST) -> Optional[str]:
    return node.id if isinstance(node, ast.Name) else None


def decorator_names(node: FuncNode) -> Set[str]:
    """Decorator names without module or call: @functools.cached_property -> cached_property."""
    names = set()
    for dec in node.decorator_list:
        chain = _attr_chain(dec.func if isinstance(dec, ast.Call) else dec)
        if chain:
            names.add(chain.rsplit(".", 1)[-1])
    return names


def method_kind(node: FuncNode) -> str:
    """
    method, static, class, property (cached_property included), setter (a property's setter or
    deleter, which shares the getter's name), abstract or overload (a signature with no real body).
    """
    decorators = decorator_names(node)
    if "overload" in decorators:
        return "overload"
    if decorators & {"setter", "deleter"}:
        return "setter"
    if decorators & {"property", "cached_property"}:
        return "property"
    if "staticmethod" in decorators:
        return "static"
    if "classmethod" in decorators:
        return "class"
    if decorators & {"abstractmethod", "abstractproperty"}:
        return "abstract"
    return "method"


# --- None as input ----------------------------------------------------------------------

# Builtins that fail when given None as their first argument (str(), repr() and bool() do not).
_NONE_FAILING_BUILTINS = frozenset({"len", "iter", "sorted", "sum", "min", "max", "list", "tuple", "set",
                                    "frozenset", "enumerate", "zip", "reversed", "any", "all", "int", "float"})
_CATCHES_TYPE_ERRORS = frozenset({"Exception", "BaseException", "TypeError", "AttributeError"})
_ORDERING = (ast.Lt, ast.LtE, ast.Gt, ast.GtE)


def _catches_type_errors(node: ast.Try) -> bool:
    for handler in node.handlers:
        if handler.type is None:
            return True
        types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
        if {_attr_chain(t).rsplit(".", 1)[-1] for t in types} & _CATCHES_TYPE_ERRORS:
            return True
    return False


def _guarded_names(func: FuncNode) -> Set[str]:
    """Parameters the body checks against None, by type or by truthiness."""
    guarded: Set[str] = set()
    for node in body_nodes(func):
        if isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            if any(isinstance(o, ast.Constant) and o.value is None for o in operands):
                guarded.update(o.id for o in operands if isinstance(o, ast.Name))
        elif isinstance(node, ast.Call) and _attr_chain(node.func) in ("isinstance", "callable", "type", "bool"):
            guarded.update(a.id for a in node.args[:1] if isinstance(a, ast.Name))
        elif isinstance(node, ast.BoolOp):
            guarded.update(v.id for v in node.values if isinstance(v, ast.Name))
        elif isinstance(node, (ast.If, ast.While, ast.IfExp, ast.Assert)):
            test = node.test
            if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
                test = test.operand
            if isinstance(test, ast.Name):
                guarded.add(test.id)
        elif isinstance(node, ast.Try) and _catches_type_errors(node):
            guarded.update(n.id for n in ast.walk(node) if isinstance(n, ast.Name))
    return guarded


def _param_in(node: ast.AST, names: Set[str]) -> Optional[str]:
    """The parameter name when node is one of names; None otherwise."""
    name = _name_of(node)
    return name if name in names else None


def _unsafe_compared(node: ast.Compare, names: Set[str]) -> List[Optional[str]]:
    """Parameters a comparison would use with None: both sides of <, >... and the container of in."""
    found: List[Optional[str]] = []
    operands = [node.left, *node.comparators]
    for op, left, right in zip(node.ops, operands, operands[1:]):
        if isinstance(op, _ORDERING):
            found += [_param_in(left, names), _param_in(right, names)]
        elif isinstance(op, (ast.In, ast.NotIn)):
            found.append(_param_in(right, names))
    return found


def _unsafe_in(expr: ast.AST, names: Set[str]) -> Set[str]:
    """Parameters that expr uses in an operation that fails on None."""
    found: List[Optional[str]] = []
    for node in ast.walk(expr):
        if isinstance(node, ast.BinOp) and not isinstance(node.op, ast.Mod):
            found += [_param_in(node.left, names), _param_in(node.right, names)]
        elif isinstance(node, (ast.Subscript, ast.Attribute, ast.Starred)):
            found.append(_param_in(node.value, names))
        elif isinstance(node, ast.Call) and _attr_chain(node.func) in _NONE_FAILING_BUILTINS and node.args:
            found.append(_param_in(node.args[0], names))
        elif isinstance(node, ast.Compare):
            found += _unsafe_compared(node, names)
        elif isinstance(node, ast.comprehension):
            found.append(_param_in(node.iter, names))
    return {name for name in found if name}


def _may_exit(stmt: ast.stmt) -> bool:
    return any(isinstance(n, (ast.Return, ast.Raise, ast.Break, ast.Continue, ast.Yield, ast.YieldFrom))
               for n in ast.walk(stmt))


# Branch-free statements: whatever they call runs whenever execution reaches them.
_SIMPLE_STATEMENTS = (ast.Expr, ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Return, ast.Raise, ast.Assert,
                      ast.Delete)
# Expressions that may not run even when the statement containing them is reached.
_DEFERRED = (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.FunctionDef,
             ast.AsyncFunctionDef, ast.ClassDef, ast.IfExp, ast.BoolOp)


def _calls_in(node: ast.AST) -> List[ast.Call]:
    """Calls in an expression that certainly run when it is evaluated (not those behind and/or, a conditional or a lambda)."""
    found: List[ast.Call] = []
    pending = [node]
    while pending:
        current = pending.pop()
        if isinstance(current, _DEFERRED):
            continue
        if isinstance(current, ast.Call):
            found.append(current)
        pending.extend(ast.iter_child_nodes(current))
    return found


def _is_guard(stmt: ast.stmt) -> bool:
    """An if without else that ends by raising: a validation that a valid sample value does not trigger."""
    return isinstance(stmt, ast.If) and not stmt.orelse and isinstance(stmt.body[-1], ast.Raise)


def always_reached_calls(func: FuncNode) -> List[ast.Call]:
    """
    The calls the function makes in every execution that accepts its input: those of its body's
    statements, in order, up to the first one that can end the function or skip the rest (a
    return, an if containing a return, a loop with break...). A validation (an if without else
    that ends in raise) does not stop the walk, because a valid sample value does not trigger it;
    the walk carries on into with blocks and try bodies.
    """
    calls: List[ast.Call] = []

    def scan(stmts: List[ast.stmt]) -> bool:
        for stmt in stmts:
            if _is_guard(stmt) or isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    calls.extend(_calls_in(item.context_expr))
                if not scan(stmt.body):
                    return False
            elif isinstance(stmt, ast.Try):
                if not scan(stmt.body):
                    return False
            elif isinstance(stmt, _SIMPLE_STATEMENTS):
                calls.extend(_calls_in(stmt))
                if _may_exit(stmt):
                    return False
            else:
                # if, loops, match: only the condition or the iterable is certain to be evaluated.
                head = getattr(stmt, "test", None) or getattr(stmt, "iter", None) or getattr(stmt, "subject", None)
                calls.extend(_calls_in(head) if head is not None else [])
                if _may_exit(stmt):
                    return False
        return True

    scan(func.body)
    return calls


def _is_forever(loop: ast.While) -> bool:
    """while True (or while 1) with no break, return, raise or sys.exit of its own: only an outside exception stops it."""
    if not (isinstance(loop.test, ast.Constant) and loop.test.value in (True, 1)):
        return False
    pending: List[Tuple[ast.AST, bool]] = [(stmt, False) for stmt in loop.body]
    while pending:
        node, nested_loop = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, (ast.Return, ast.Raise)) or (isinstance(node, ast.Break) and not nested_loop):
            return False
        if isinstance(node, ast.Call) and _attr_chain(node.func) in ("sys.exit", "exit", "quit", "os._exit"):
            return False
        inner = nested_loop or isinstance(node, (ast.For, ast.AsyncFor, ast.While))
        pending.extend((child, inner) for child in ast.iter_child_nodes(node))
    return True


def has_endless_loop(func: FuncNode) -> bool:
    """
    True when the function always enters an endless loop (a monitor, a server): a while True with
    no way out, in a statement that runs on every call, including inside a with or a try. A
    generator does not count, because calling it executes nothing.
    """
    if any(isinstance(n, (ast.Yield, ast.YieldFrom)) for n in body_nodes(func)):
        return False

    def scan(stmts: List[ast.stmt]) -> bool:
        for stmt in stmts:
            if isinstance(stmt, ast.While) and _is_forever(stmt):
                return True
            if isinstance(stmt, (ast.With, ast.AsyncWith, ast.Try)) and scan(stmt.body):
                return True
            if _may_exit(stmt) and not _is_guard(stmt):
                return False
        return False

    return scan(func.body)


# Parameter names that denote a duration: a huge boundary value would leave the test waiting.
_DURATION_NAME = re.compile(r"^(seconds|secs|delay|timeout|interval|wait|duration|sleep)(_|$)"
                            r"|_(seconds|secs|minutes|hours|ms|timeout|delay|interval)$")
# Calls that wait for the time they are given (not join: that is also str.join).
_WAITING_CALL = re.compile(r"(^|\.)(sleep|wait|wait_for)$")


def duration_params(func: FuncNode) -> Set[str]:
    """
    Parameters that are a duration: by name, or because the function passes them (possibly inside
    an expression such as minutes * 60) to sleep or wait, or as timeout=.
    """
    names = {a.arg for a in [*func.args.posonlyargs, *func.args.args, *func.args.kwonlyargs]}
    found = {n for n in names if _DURATION_NAME.search(n.lower())}
    for node in body_nodes(func):
        if not isinstance(node, ast.Call):
            continue
        values = [kw.value for kw in node.keywords if kw.arg == "timeout"]
        if _WAITING_CALL.search(_attr_chain(node.func)):
            values += node.args[:1]
        for value in values:
            found |= {n.id for n in ast.walk(value) if isinstance(n, ast.Name) and n.id in names}
    return found


def none_unsafe_params(func: FuncNode) -> Set[str]:
    """
    Parameters for which None certainly makes the function fail: they are used in an operation
    that rejects None (arithmetic, indexing, attribute access, iteration, len, ordering
    comparison...) in a statement that always runs, and the body never checks them. The body is
    walked in order and the walk stops at the first statement that can end the function or skip
    the rest: past that point, whether an operation is reached depends on the other arguments.
    """
    if any(isinstance(n, (ast.Yield, ast.YieldFrom)) for n in body_nodes(func)):
        return set()  # a generator runs nothing until it is iterated
    names = {a.arg for a in [*func.args.posonlyargs, *func.args.args, *func.args.kwonlyargs]}
    unsafe: Set[str] = set()
    for stmt in func.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(stmt, (ast.If, ast.While)):
            unsafe |= _unsafe_in(stmt.test, names)
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            unsafe |= _unsafe_in(stmt.iter, names)
            iterated = _param_in(stmt.iter, names)
            if iterated:
                unsafe.add(iterated)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                unsafe |= _unsafe_in(item.context_expr, names)
        elif isinstance(stmt, ast.Try):
            break
        else:
            unsafe |= _unsafe_in(stmt, names)
        if _may_exit(stmt):
            break
    return unsafe - _guarded_names(func)


def is_cli_entrypoint(func: FuncNode) -> bool:
    """The function reads sys.argv or ends the process (sys.exit, SystemExit): it is tested through its command line."""
    for node in body_nodes(func):
        if isinstance(node, ast.Attribute) and _attr_chain(node) in ("sys.argv", "sys.exit"):
            return True
        if isinstance(node, ast.Raise) and node.exc is not None:
            exc = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
            if _attr_chain(exc) == "SystemExit":
                return True
        if isinstance(node, ast.Call) and _attr_chain(node.func) in ("exit", "quit"):
            return True
    return False


def _mentions(expr: ast.AST, name: str) -> bool:
    return any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(expr))


def validating_raises(func: Optional[ast.AST], name: str) -> List[Tuple[str, Optional[str]]]:
    """
    Exceptions the function uses to validate parameter name, in source order: a raise inside an
    if whose condition mentions it, or an assert on it. Those are what an invalid value of name
    can trigger; a raise in another branch depends on something else, and expecting it would make
    the test fail against a correct function.
    """
    if func is None:
        return []
    found: List[Tuple[int, str, Optional[str]]] = []
    for node in body_nodes(func):  # type: ignore[arg-type]
        if isinstance(node, ast.If) and _mentions(node.test, name):
            for stmt in node.body:
                info = _extract_raise_info(stmt) if isinstance(stmt, ast.Raise) else None
                if info:
                    found.append((stmt.lineno, *info))
        elif isinstance(node, ast.Assert) and _mentions(node.test, name):
            msg = node.msg.value if isinstance(node.msg, ast.Constant) and isinstance(node.msg.value, str) else None
            found.append((node.lineno, "AssertionError", "" if node.msg is None else msg))
    return [(exc, msg) for _, exc, msg in sorted(found, key=lambda item: item[0])]


def has_bare_assert(func: Optional[ast.AST]) -> bool:
    """True when the body validates with a message-less assert: the AssertionError it raises has empty text."""
    return func is not None and any(isinstance(n, ast.Assert) and n.msg is None for n in body_nodes(func))  # type: ignore[arg-type]


def accepts_none(param: ast.arg, default: Optional[ast.AST]) -> bool:
    """The parameter accepts None by contract: it defaults to None or its annotation includes it."""
    if isinstance(default, ast.Constant) and default.value is None:
        return True
    if param.annotation is None:
        return False
    names = {_attr_chain(n).rsplit(".", 1)[-1] for n in ast.walk(param.annotation)}
    nones = any(isinstance(n, ast.Constant) and n.value is None for n in ast.walk(param.annotation))
    return nones or bool(names & {"Optional", "Any", "None", "object"})


def _extract_raises_and_flags(
    func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
    imports: Optional[ImportMap] = None,
) -> Tuple[List[Tuple[str, Optional[str]]], bool, List[str]]:
    """
    Extract from a function body (without crossing into nested functions or classes):
    - Exceptions raised explicitly: [(ExcName, literal_msg_or_None)]
    - Whether None could make it fail (arithmetic/comparison operators, raise, method calls)
    - Patch targets for the calls with side effects (I/O, filesystem, processes, network)
    """
    imports = imports or ImportMap("")
    raises: List[Tuple[str, Optional[str]]] = []
    may_fail_on_none = False
    handles_none = False
    io_calls: List[str] = []

    stack: List[ast.AST] = list(func_node.body)
    while stack:
        curr = stack.pop()
        if isinstance(curr, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(curr, ast.Raise) and curr.exc is not None:
            may_fail_on_none = True
            info = _extract_raise_info(curr)
            if info:
                raises.append(info)
        elif isinstance(curr, ast.Compare):
            if _is_none_comparison(curr):
                handles_none = True
            else:
                may_fail_on_none = True
        elif isinstance(curr, (ast.BinOp, ast.Subscript)):
            may_fail_on_none = True
        elif isinstance(curr, ast.Call):
            hit = classify(curr, imports)
            if hit:
                io_calls.append(hit[1])
                may_fail_on_none = True
        stack.extend(ast.iter_child_nodes(curr))

    return raises, (may_fail_on_none and not handles_none), sorted(set(io_calls))


def _called_names(func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> Tuple[Set[str], Set[str]]:
    """(functions called by name, methods called on self/cls), without entering nested functions."""
    plain: Set[str] = set()
    on_self: Set[str] = set()
    stack: List[ast.AST] = list(func_node.body)
    while stack:
        curr = stack.pop()
        if isinstance(curr, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(curr, ast.Call):
            if isinstance(curr.func, ast.Name):
                plain.add(curr.func.id)
            elif (
                isinstance(curr.func, ast.Attribute)
                and isinstance(curr.func.value, ast.Name)
                and curr.func.value.id in ("self", "cls")
            ):
                on_self.add(curr.func.attr)
        stack.extend(ast.iter_child_nodes(curr))
    return plain, on_self


def _propagate_step(direct: Dict[str, Set[Any]], edges: Dict[str, Set[str]]) -> bool:
    changed = False
    for key, callees in edges.items():
        for callee in callees:
            extra = direct[callee] - direct[key]
            if extra:
                direct[key] |= extra
                changed = True
    return changed


class UnitTestGenerator(ast.NodeVisitor):
    """
    Collects, from a module's AST, the metadata the test emitters need: public functions and
    classes, their signatures, sync/async kind, exception contracts and I/O to patch.
    """

    def __init__(self, filename: str, project: Optional[ProjectIndex] = None) -> None:
        self.filename: str = filename
        # The fully qualified name inside the package, which is what patch("<module>.rmtree") needs.
        self.module = module_import(filename)[0]
        self.imports = ImportMap(self.module)
        # The project's other modules: their helpers can perform I/O too.
        self.project = project or ProjectIndex(filename)
        # I/O of every function in the module, private ones included, for callers in other modules.
        self.io_by_function: Dict[str, Set[str]] = {}
        self.io_always_by_function: Dict[str, bool] = {}
        # Every function in the module, private ones included: needed to propagate a helper's
        # I/O (`_delete`) to the public function that calls it.
        self._all_nodes: Dict[str, Union[ast.FunctionDef, ast.AsyncFunctionDef]] = {}
        self.functions: List[Tuple[str, List[str], Optional[ast.arguments]]] = []
        self.classes: List[Tuple[str, Optional[ast.arguments], List[Tuple[str, List[str], Optional[ast.arguments]]]]] = []
        self.function_meta: Dict[str, Dict[str, Any]] = {}
        self.function_nodes: Dict[str, Union[ast.FunctionDef, ast.AsyncFunctionDef]] = {}
        # The module AST: the emitters use it to resolve aliases, classes and parameter types.
        self.tree: Optional[ast.Module] = None

    def visit_Module(self, node: ast.Module) -> None:
        self.tree = node
        self.imports = ImportMap.from_tree(node, self.imports.module)
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._all_nodes[item.name] = item
            elif isinstance(item, ast.ClassDef):
                for sub in item.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self._all_nodes[f"{item.name}.{sub.name}"] = sub
        with self.project.loading(self.module):
            self.generic_visit(node)
            self._propagate()

    def _propagate(self) -> None:
        """
        A function that calls another function of the module inherits its I/O (and test doubles)
        and the exceptions it can raise: raises_reachable includes its helpers' exceptions, raises
        only its own. bare_assert says whether it or a helper validates with a message-less assert.
        """
        extracted = {key: _extract_raises_and_flags(fn, self.imports) for key, fn in self._all_nodes.items()}
        io_direct = {key: set(info[2]) | self._project_io(self._all_nodes[key]) for key, info in extracted.items()}
        raises_direct = {key: set(info[0]) for key, info in extracted.items()}
        asserts: Dict[str, Set[Any]] = {key: {True} if has_bare_assert(fn) else set() for key, fn in self._all_nodes.items()}
        edges: Dict[str, Set[str]] = {}
        for key, fn in self._all_nodes.items():
            plain, on_self = _called_names(fn)
            cls = key.split(".")[0] + "." if "." in key else None
            callees = {name for name in plain if name in self._all_nodes}
            if cls:
                callees |= {cls + name for name in on_self if cls + name in self._all_nodes}
            edges[key] = callees
        while _propagate_step(io_direct, edges):
            pass
        while _propagate_step(raises_direct, edges):
            pass
        while _propagate_step(asserts, edges):
            pass
        always = self._always_io(io_direct)
        self.io_by_function, self.io_always_by_function = io_direct, always
        for key, meta in self.function_meta.items():
            meta["io_calls"] = sorted(io_direct.get(key, set(meta.get("io_calls", []))))
            meta["io_always"] = always.get(key, False)
            reachable = raises_direct.get(key, set()) - set(meta.get("raises", []))
            meta["raises_reachable"] = [*meta.get("raises", []), *sorted(reachable, key=lambda r: (r[0], r[1] or ""))]
            meta["bare_assert"] = bool(asserts.get(key))

    def _always_io(self, io: Dict[str, Set[str]]) -> Dict[str, bool]:
        """
        Which functions perform I/O in every execution that accepts their input: an I/O call that
        is always reached, or an always-reached call to a module helper that itself always does
        I/O (doing it in some branch is not enough: send_telegram only posts when credentials are
        set). Iterates to a fixed point so chains of helpers are followed.
        """
        reached = {key: always_reached_calls(fn) for key, fn in self._all_nodes.items() if io.get(key)}
        always: Dict[str, bool] = {key: False for key in self._all_nodes}
        changed = True
        while changed:
            changed = False
            for key, calls in reached.items():
                if not always[key] and any(self._does_io(key, call, always) for call in calls):
                    always[key] = changed = True
        return always

    def _project_callee(self, call: ast.Call) -> Optional[Tuple[str, str]]:
        """(module, function) when the call targets a function in another project module."""
        names, modules = self.project.imports_of(self.module)
        func = call.func
        if isinstance(func, ast.Name) and func.id in names:
            return names[func.id]
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id in modules:
            return modules[func.value.id], func.attr
        return None

    def _project_io(self, fn: FuncNode) -> Set[str]:
        """I/O performed by helpers in other project modules that the function calls (export_rows writes a file)."""
        targets: Set[str] = set()
        for node in body_nodes(fn):
            callee = self._project_callee(node) if isinstance(node, ast.Call) else None
            if callee is not None:
                targets |= self.project.function_io(*callee)[0]
        return targets

    def _does_io(self, key: str, call: ast.Call, always: Dict[str, bool]) -> bool:
        if classify(call, self.imports):
            return True
        external = self._project_callee(call)
        if external is not None:
            return self.project.function_io(*external)[1]
        func = call.func
        callee = func.id if isinstance(func, ast.Name) else None
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id in ("self", "cls"):
            callee = key.split(".")[0] + "." + func.attr if "." in key else None
        return bool(callee and always.get(callee))

    def _build_meta(
        self,
        node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
        *,
        is_async: bool,
    ) -> Dict[str, Any]:
        raises, may_fail_on_none, io_calls = _extract_raises_and_flags(node, self.imports)
        param_types: Dict[str, Optional[str]] = {}
        for arg in node.args.args:
            if arg.arg in ("self", "cls"):
                continue
            ann = _attr_chain(arg.annotation) if arg.annotation is not None else None
            param_types[arg.arg] = ann
        return {
            "is_async": is_async,
            "raises": raises,
            "may_fail_on_none": may_fail_on_none,
            "none_unsafe": sorted(none_unsafe_params(node)),
            "cli_entrypoint": is_cli_entrypoint(node),
            "endless_loop": has_endless_loop(node),
            "durations": sorted(duration_params(node)),
            "io_calls": io_calls,
            "param_types": param_types,
            "lineno": node.lineno,
        }

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if not node.name.startswith("_") and method_kind(node) != "overload":
            args = [a.arg for a in node.args.args if a.arg not in ("self", "cls")]
            self.functions.append((node.name, args, node.args))
            self.function_meta[node.name] = self._build_meta(node, is_async=False)
            self.function_nodes[node.name] = node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if not node.name.startswith("_") and method_kind(node) != "overload":
            args = [a.arg for a in node.args.args if a.arg not in ("self", "cls")]
            self.functions.append((node.name, args, node.args))
            self.function_meta[node.name] = self._build_meta(node, is_async=True)
            self.function_nodes[node.name] = node

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Public classes and their public methods. Property setters and @overload signatures are not test targets."""
        if node.name.startswith("_"):
            return
        init_args: Optional[ast.arguments] = None
        methods: List[Tuple[str, List[str], Optional[ast.arguments]]] = []
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if item.name == "__init__":
                    init_args = item.args
                elif not item.name.startswith("_") and method_kind(item) not in ("setter", "overload"):
                    m_args = [a.arg for a in item.args.args if a.arg not in ("self", "cls")]
                    methods.append((item.name, m_args, item.args))
                    self.function_meta[f"{node.name}.{item.name}"] = self._build_meta(
                        item, is_async=isinstance(item, ast.AsyncFunctionDef),
                    )
                    self.function_nodes[f"{node.name}.{item.name}"] = item
        self.classes.append((node.name, init_args, methods))
