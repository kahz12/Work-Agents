"""
The project modules imported by the analysed module.

The generator analyses one file, but its functions call helpers and use classes from other
modules of the same project: export_rows, from core/report.py, writes a file; ProviderSpec,
from ai/base.py, is a dataclass that has to be constructed; a screen inherits from another
screen defined elsewhere, which in turn inherits from Textual. ProjectIndex finds those modules
(the ones under the same root as the analysed file) and reads them without executing them,
with a shared cache so each one is read only once.
"""
from __future__ import annotations

import ast
import os
from contextlib import contextmanager
from typing import TYPE_CHECKING, Dict, Iterator, Optional, Set, Tuple

if TYPE_CHECKING:
    from .ast_inspector import UnitTestGenerator


def module_import(source_filepath: str) -> Tuple[str, str]:
    """
    (name the module is imported under, directory that must be on sys.path). Inside a package
    the name is the full dotted path (agentes.common.findings) and the root is the directory that
    contains the top-level package, which is what makes the module's relative imports work.
    """
    path = os.path.abspath(source_filepath)
    directory, filename = os.path.split(path)
    stem = os.path.splitext(filename)[0]
    parts = [] if stem == "__init__" else [stem]
    # Climb while the directory is a package; names are collected innermost first.
    while os.path.isfile(os.path.join(directory, "__init__.py")):
        parts.append(os.path.basename(directory))
        directory = os.path.dirname(directory)
    return ".".join(reversed(parts)) or stem, directory


# What a module imports from the project: local name -> (module, original name), and module
# alias -> module (from pkg import report, import pkg.report as report).
ProjectImports = Tuple[Dict[str, Tuple[str, str]], Dict[str, str]]


class ProjectIndex:
    """The modules under the analysed module's root, read on demand and never executed."""

    def __init__(self, source_filepath: str) -> None:
        self.module, self.root = module_import(source_filepath)
        self._trees: Dict[str, Optional[ast.Module]] = {}
        self._imports: Dict[str, ProjectImports] = {}
        self._visitors: Dict[str, Optional["UnitTestGenerator"]] = {}
        self._loading: Set[str] = set()

    def path_of(self, module: str) -> Optional[str]:
        """The module's file inside the project, or None when it is not a project module."""
        base = os.path.join(self.root, *module.split("."))
        for candidate in (base + ".py", os.path.join(base, "__init__.py")):
            if os.path.isfile(candidate):
                return candidate
        return None

    def tree(self, module: str) -> Optional[ast.Module]:
        """The module's AST, or None when it is not a project module or cannot be read."""
        if module not in self._trees:
            path = self.path_of(module)
            tree = None
            if path is not None:
                try:
                    with open(path, encoding="utf-8") as handle:
                        tree = ast.parse(handle.read(), filename=path)
                except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
                    tree = None
            self._trees[module] = tree
        return self._trees[module]

    def resolve(self, module: str, node: ast.ImportFrom) -> Optional[str]:
        """The project module a `from ... import` written in module refers to (relative imports included), or None."""
        if node.level:
            parts = module.split(".")
            is_package = (self.path_of(module) or "").endswith("__init__.py")
            base = parts if is_package else parts[:-1]
            base = base[:len(base) - (node.level - 1)]
            target = ".".join([*base, *([node.module] if node.module else [])])
        else:
            target = node.module or ""
        return target if target and self.path_of(target) else None

    def imports_of(self, module: str) -> ProjectImports:
        """What module imports from the project at module level, including inside try and if blocks."""
        if module not in self._imports:
            names: Dict[str, Tuple[str, str]] = {}
            modules: Dict[str, str] = {}
            tree = self.tree(module)
            for node in _module_level(tree.body if tree is not None else []):
                if isinstance(node, ast.ImportFrom):
                    target = self.resolve(module, node)
                    for alias in node.names if target else []:
                        local = alias.asname or alias.name
                        if self.path_of(f"{target}.{alias.name}"):
                            modules[local] = f"{target}.{alias.name}"
                        elif alias.name != "*":
                            names[local] = (str(target), alias.name)
                elif isinstance(node, ast.Import):
                    # Without an alias, `import pkg.mod` is used as pkg.mod.f(); only aliased imports are followed.
                    modules.update({a.asname: a.name for a in node.names if a.asname and self.path_of(a.name)})
            self._imports[module] = (names, modules)
        return self._imports[module]

    @contextmanager
    def loading(self, module: str) -> Iterator[None]:
        """Mark a module as being analysed, so a circular import back into it does not recurse forever."""
        self._loading.add(module)
        try:
            yield
        finally:
            self._loading.discard(module)

    def visitor(self, module: str) -> Optional["UnitTestGenerator"]:
        """The module's analysis (its functions and their I/O), or None when it is not a project module or is already being analysed."""
        if module in self._visitors:
            return self._visitors[module]
        if module in self._loading:
            return None
        from .ast_inspector import UnitTestGenerator

        tree, path = self.tree(module), self.path_of(module)
        visitor = None
        if tree is not None and path is not None:
            visitor = UnitTestGenerator(path, project=self)
            visitor.visit(tree)
        self._visitors[module] = visitor
        return visitor

    def function_io(self, module: str, name: str) -> Tuple[Set[str], bool]:
        """(patch targets for the function's I/O, whether it always performs it) for a function in another module."""
        visitor = self.visitor(module)
        if visitor is None:
            return set(), False
        return set(visitor.io_by_function.get(name, set())), visitor.io_always_by_function.get(name, False)


def _module_level(stmts: list) -> Iterator[ast.stmt]:
    """Module-level statements, descending into if and try blocks (optional or TYPE_CHECKING imports)."""
    for stmt in stmts:
        yield stmt
        if isinstance(stmt, ast.If):
            yield from _module_level([*stmt.body, *stmt.orelse])
        elif isinstance(stmt, ast.Try):
            yield from _module_level([*stmt.body, *stmt.orelse, *[s for h in stmt.handlers for s in h.body]])
