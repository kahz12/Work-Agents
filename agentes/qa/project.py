"""
Los módulos del proyecto que importa el módulo analizado.

El generador analiza un archivo, pero sus funciones llaman a helpers y usan clases de otros
módulos del mismo proyecto: export_rows, de core/report.py, escribe un archivo; ProviderSpec, de
ai/base.py, es una dataclass que hace falta construir; una pantalla hereda de otra definida en
otro módulo, que a su vez hereda de Textual. ProjectIndex localiza esos módulos (los que están
bajo la misma raíz que el analizado) y los lee sin ejecutarlos, con una caché compartida para
que cada uno se lea una sola vez.
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
    (nombre con el que se importa el módulo, directorio que tiene que estar en sys.path). En un
    paquete el nombre lleva la ruta completa (agentes.common.findings) y la raíz es el directorio
    que contiene el paquete de más arriba: así funcionan los imports relativos del módulo.
    """
    path = os.path.abspath(source_filepath)
    directory, filename = os.path.split(path)
    stem = os.path.splitext(filename)[0]
    parts = [] if stem == "__init__" else [stem]
    # Se sube mientras haya paquete: los nombres salen de dentro hacia fuera.
    while os.path.isfile(os.path.join(directory, "__init__.py")):
        parts.append(os.path.basename(directory))
        directory = os.path.dirname(directory)
    return ".".join(reversed(parts)) or stem, directory


# Lo que un módulo importa del proyecto: nombre local -> (módulo, nombre original), y alias de
# módulo -> módulo (from pkg import report, import pkg.report as report).
ProjectImports = Tuple[Dict[str, Tuple[str, str]], Dict[str, str]]


class ProjectIndex:
    """Los módulos bajo la raíz del módulo analizado, leídos bajo demanda y sin ejecutarlos."""

    def __init__(self, source_filepath: str) -> None:
        self.module, self.root = module_import(source_filepath)
        self._trees: Dict[str, Optional[ast.Module]] = {}
        self._imports: Dict[str, ProjectImports] = {}
        self._visitors: Dict[str, Optional["UnitTestGenerator"]] = {}
        self._loading: Set[str] = set()

    def path_of(self, module: str) -> Optional[str]:
        """El archivo del módulo dentro del proyecto, o None si no es del proyecto."""
        base = os.path.join(self.root, *module.split("."))
        for candidate in (base + ".py", os.path.join(base, "__init__.py")):
            if os.path.isfile(candidate):
                return candidate
        return None

    def tree(self, module: str) -> Optional[ast.Module]:
        """El árbol del módulo, o None si no es del proyecto o no se puede leer."""
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
        """El módulo del proyecto al que se refiere un from ... import escrito en module, o None."""
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
        """Lo que module importa del proyecto a nivel de módulo, también dentro de un try o un if."""
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
                    # import pkg.mod sin alias se usa como pkg.mod.f(): solo se sigue con alias.
                    modules.update({a.asname: a.name for a in node.names if a.asname and self.path_of(a.name)})
            self._imports[module] = (names, modules)
        return self._imports[module]

    @contextmanager
    def loading(self, module: str) -> Iterator[None]:
        """Marca un módulo mientras se analiza: si otro lo importa de vuelta, no se entra en bucle."""
        self._loading.add(module)
        try:
            yield
        finally:
            self._loading.discard(module)

    def visitor(self, module: str) -> Optional["UnitTestGenerator"]:
        """El análisis del módulo (sus funciones, su E/S), o None si no es del proyecto o ya se está analizando."""
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
        """(objetivos de patch de la E/S de la función, si la hace siempre) para una función de otro módulo."""
        visitor = self.visitor(module)
        if visitor is None:
            return set(), False
        return set(visitor.io_by_function.get(name, set())), visitor.io_always_by_function.get(name, False)


def _module_level(stmts: list) -> Iterator[ast.stmt]:
    """Las sentencias de nivel de módulo, entrando en if y try (imports opcionales o de TYPE_CHECKING)."""
    for stmt in stmts:
        yield stmt
        if isinstance(stmt, ast.If):
            yield from _module_level([*stmt.body, *stmt.orelse])
        elif isinstance(stmt, ast.Try):
            yield from _module_level([*stmt.body, *stmt.orelse, *[s for h in stmt.handlers for s in h.body]])
