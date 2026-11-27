"""
AST audit of architectural testability: hardcoded dependencies, global state, I/O and determinism.
"""
from __future__ import annotations

import ast
import os
import re
from typing import List, Set, Tuple, Union

from .ast_inspector import NON_DET_CALLS, _attr_chain, _parameter_names, read_and_parse
from .side_effects import ImportMap, classify

_STD_TYPES_OR_EXCS = frozenset({
    "str", "int", "float", "bool", "list", "dict", "set", "tuple", "bytes",
    "frozenset", "bytearray", "object", "super", "Exception", "BaseException",
    "SystemExit", "KeyboardInterrupt", "GeneratorExit",
    "ValueError", "TypeError", "KeyError", "IndexError", "RuntimeError",
    "AssertionError", "AttributeError", "LookupError", "OSError", "IOError",
    "FileNotFoundError", "TimeoutError", "ZeroDivisionError", "NotImplementedError",
    "Path", "PurePath", "Decimal", "UUID", "re", "json", "math", "datetime",
})

_COLLABORATOR_WORD_HINTS = frozenset({
    "Client", "Service", "Repo", "Repository", "Provider", "Session", "Engine",
    "Connection", "Pool", "Database", "DB", "Cache", "Mailer", "Gateway",
    "Adapter", "Broker", "Server", "Transport", "Anthropic", "Gemini",
    "Redis", "Mongo", "Bot",
})

_COLLABORATOR_BRAND_HINTS = ("OpenAI", "Anthropic", "Gemini")


def _is_collaborator_class(cls_name: str) -> bool:
    """True only when the class name suggests an external client, service or repository."""
    # Split CamelCase into words, keeping acronyms together: "HTTPClient" -> ["HTTP", "Client"].
    if any(brand in cls_name for brand in _COLLABORATOR_BRAND_HINTS):
        return True
    words = re.findall(r"[A-Z]+(?=[A-Z][a-z0-9]|$)|[A-Z][a-z0-9]*", cls_name)
    return any(w in _COLLABORATOR_WORD_HINTS for w in words)


def _is_hardcoded_collaborator(cls_name: str, local_names: Set[str]) -> bool:
    """A collaborator class (client, repository...) instantiated inside the function instead of being passed in."""
    return (
        cls_name[0:1].isupper()
        and cls_name not in _STD_TYPES_OR_EXCS
        and not cls_name.endswith(("Error", "Exception", "Warning"))
        and cls_name not in local_names
        and _is_collaborator_class(cls_name)
    )


class TestabilityAuditor(ast.NodeVisitor):
    """
    AST testability audit: direct coupling to external collaborators, mutable global state,
    I/O mixed with business logic, and non-determinism. Findings are (line, code, level, message).
    """

    def __init__(self, tree: ast.Module, module: str = "") -> None:
        self.findings: List[Tuple[int, str, str, str]] = []
        self.imports = ImportMap.from_tree(tree, module)
        self._module_vars: Set[str] = set()
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self._module_vars.add(t.id)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                self._module_vars.add(node.target.id)

    # Nodes that signal business logic (decisions, loops, computation) as opposed to plain delegation.
    _LOGIC_NODES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.BinOp, ast.Compare, ast.Raise)
    _MUTATING_METHODS = frozenset({"append", "extend", "update", "pop", "clear", "add", "remove"})

    def _audit_func(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> None:
        local_names = _parameter_names(node.args)
        has_logic = False
        io_hits: List[Tuple[int, str]] = []
        stack: List[ast.AST] = list(node.body)

        # Walk the body without entering nested functions or classes; they are audited on their own.
        while stack:
            curr = stack.pop()
            if isinstance(curr, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            has_logic = has_logic or isinstance(curr, self._LOGIC_NODES)
            self._audit_node(curr, node.name, local_names, io_hits)
            stack.extend(ast.iter_child_nodes(curr))

        if io_hits and has_logic:
            lineno, chain = io_hits[0]
            self._add(
                lineno, "MIXED-IO", "HIGH",
                f"Function '{node.name}' mixes business logic with direct I/O ('{chain}'). "
                "Separate the pure logic from the I/O adapter.",
            )

        self.generic_visit(node)

    def _add(self, line: int, code: str, level: str, message: str) -> None:
        self.findings.append((line, code, level, message))

    def _audit_node(self, curr: ast.AST, func_name: str, local_names: Set[str], io_hits: List[Tuple[int, str]]) -> None:
        if isinstance(curr, ast.Global):
            self._add(
                curr.lineno, "GLOBAL-STATE", "HIGH",
                f"Function '{func_name}' uses 'global {', '.join(curr.names)}', which couples tests to execution order.",
            )
        elif isinstance(curr, ast.Assign):
            self._audit_global_item_assignment(curr, func_name, local_names)
        elif isinstance(curr, ast.Call):
            self._audit_call(curr, func_name, local_names, io_hits)
        elif isinstance(curr, ast.Subscript) and _attr_chain(curr.value) == "os.environ":
            self._add(
                curr.lineno, "NON-DETERMINISTIC", "MEDIUM",
                f"Direct read of os.environ in '{func_name}'. Use monkeypatch in tests or inject the configuration.",
            )

    def _is_module_var(self, name: str, local_names: Set[str]) -> bool:
        """A module-level variable that the function neither receives nor shadows with a parameter."""
        return name in self._module_vars and name not in local_names

    def _audit_global_item_assignment(self, curr: ast.Assign, func_name: str, local_names: Set[str]) -> None:
        """CACHE[k] = v on a module-level variable."""
        for tgt in curr.targets:
            if (
                isinstance(tgt, ast.Subscript)
                and isinstance(tgt.value, ast.Name)
                and self._is_module_var(tgt.value.id, local_names)
            ):
                self._add(
                    curr.lineno, "GLOBAL-STATE", "HIGH",
                    f"Global state mutation '{tgt.value.id}[...]' inside '{func_name}'. Pass the state in explicitly.",
                )

    def _audit_call(self, curr: ast.Call, func_name: str, local_names: Set[str], io_hits: List[Tuple[int, str]]) -> None:
        func = curr.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in self._MUTATING_METHODS
            and isinstance(func.value, ast.Name)
            and self._is_module_var(func.value.id, local_names)
        ):
            self._add(
                curr.lineno, "GLOBAL-STATE", "HIGH",
                f"Global collection mutation '{func.value.id}.{func.attr}()' inside '{func_name}'.",
            )
        chain = _attr_chain(func)
        hit = classify(curr, self.imports)
        if hit:
            io_hits.append((curr.lineno, hit[0]))
        elif chain in NON_DET_CALLS:
            self._add(
                curr.lineno, "NON-DETERMINISTIC", "MEDIUM",
                f"Non-deterministic call '{chain}()' in '{func_name}'. Inject the clock/generator or make it a parameter.",
            )
        elif isinstance(func, ast.Name) and _is_hardcoded_collaborator(func.id, local_names):
            self._add(
                curr.lineno, "HARDCODED-DEP", "MEDIUM",
                f"Hardcoded dependency '{func.id}()' inside '{func_name}'. "
                "Use dependency injection so tests can mock it with spec/autospec.",
            )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._audit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._audit_func(node)


def audit_testability(source_filepath: str) -> List[Tuple[int, str, str, str]]:
    """
    Look for testability blockers in a source file through its AST: concrete coupling, mutable
    global state, direct I/O and non-determinism.
    Returns a list of (line, code, level, message) tuples.
    """
    try:
        tree = read_and_parse(source_filepath)
    except FileNotFoundError:
        return [(0, "N/A", "ERROR", f"File '{source_filepath}' not found.")]
    except (IsADirectoryError, PermissionError, OSError, SyntaxError, UnicodeDecodeError) as e:
        return [(0, "AST", "ERROR", f"Testability analysis error: {e}")]

    auditor = TestabilityAuditor(tree, os.path.splitext(os.path.basename(source_filepath))[0])
    auditor.visit(tree)
    return auditor.findings
