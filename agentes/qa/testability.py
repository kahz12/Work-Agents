"""
Auditoría AST de testabilidad arquitectónica: dependencias, estado global, E/S y determinismo.
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


def _es_clase_colaborador(cls_name: str) -> bool:
    """Devuelve True solo si el nombre sugiere un cliente/servicio/repositorio externo."""
    if any(brand in cls_name for brand in _COLLABORATOR_BRAND_HINTS):
        return True
    words = re.findall(r"[A-Z]+(?=[A-Z][a-z0-9]|$)|[A-Z][a-z0-9]*", cls_name)
    return any(w in _COLLABORATOR_WORD_HINTS for w in words)


def _is_hardcoded_collaborator(cls_name: str, local_names: Set[str]) -> bool:
    """Una clase colaboradora (cliente, repositorio...) instanciada dentro en vez de recibida."""
    return (
        cls_name[0:1].isupper()
        and cls_name not in _STD_TYPES_OR_EXCS
        and not cls_name.endswith(("Error", "Exception", "Warning"))
        and cls_name not in local_names
        and _es_clase_colaborador(cls_name)
    )


class TestabilityAuditor(ast.NodeVisitor):
    """
    Auditor AST de testabilidad arquitectónica: identifica acoplamiento directo
    a colaboradores externos, estado global mutable, I/O mezclado con lógica y no-determinismo.
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

    # Nodos que indican lógica de negocio (decisiones, bucles, operaciones) frente a mera delegación.
    _LOGIC_NODES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.BinOp, ast.Compare, ast.Raise)
    _MUTATING_METHODS = frozenset({"append", "extend", "update", "pop", "clear", "add", "remove"})

    def _audit_func(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> None:
        local_names = _parameter_names(node.args)
        has_logic = False
        io_hits: List[Tuple[int, str]] = []
        stack: List[ast.AST] = list(node.body)

        # Recorre el cuerpo sin entrar en funciones ni clases anidadas: tienen su propia auditoría.
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
                lineno, "MIXED-IO", "ALTO",
                f"La funcion '{node.name}' mezcla logica de negocio con I/O directo ('{chain}'). "
                "Separa la logica pura del adaptador de I/O.",
            )

        self.generic_visit(node)

    def _add(self, line: int, code: str, level: str, message: str) -> None:
        self.findings.append((line, code, level, message))

    def _audit_node(self, curr: ast.AST, func_name: str, local_names: Set[str], io_hits: List[Tuple[int, str]]) -> None:
        if isinstance(curr, ast.Global):
            self._add(
                curr.lineno, "GLOBAL-STATE", "ALTO",
                f"La funcion '{func_name}' usa 'global {', '.join(curr.names)}', acoplando pruebas al orden de ejecucion.",
            )
        elif isinstance(curr, ast.Assign):
            self._audit_global_item_assignment(curr, func_name, local_names)
        elif isinstance(curr, ast.Call):
            self._audit_call(curr, func_name, local_names, io_hits)
        elif isinstance(curr, ast.Subscript) and _attr_chain(curr.value) == "os.environ":
            self._add(
                curr.lineno, "NON-DETERMINISTIC", "MEDIO",
                f"Lectura directa de os.environ en '{func_name}'. Usa monkeypatch en tests o inyecta configuracion.",
            )

    def _is_module_var(self, name: str, local_names: Set[str]) -> bool:
        """Variable del módulo que la función no recibe ni ensombrece con un parámetro."""
        return name in self._module_vars and name not in local_names

    def _audit_global_item_assignment(self, curr: ast.Assign, func_name: str, local_names: Set[str]) -> None:
        """CACHE[k] = v sobre una variable del módulo."""
        for tgt in curr.targets:
            if (
                isinstance(tgt, ast.Subscript)
                and isinstance(tgt.value, ast.Name)
                and self._is_module_var(tgt.value.id, local_names)
            ):
                self._add(
                    curr.lineno, "GLOBAL-STATE", "ALTO",
                    f"Mutacion de estado global '{tgt.value.id}[...]' dentro de '{func_name}'. Inyecta estado explicito.",
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
                curr.lineno, "GLOBAL-STATE", "ALTO",
                f"Mutacion de coleccion global '{func.value.id}.{func.attr}()' dentro de '{func_name}'.",
            )
        chain = _attr_chain(func)
        hit = classify(curr, self.imports)
        if hit:
            io_hits.append((curr.lineno, hit[0]))
        elif chain in NON_DET_CALLS:
            self._add(
                curr.lineno, "NON-DETERMINISTIC", "MEDIO",
                f"Llamada no determinista '{chain}()' en '{func_name}'. Inyecta reloj/generador o parametrizalo.",
            )
        elif isinstance(func, ast.Name) and _is_hardcoded_collaborator(func.id, local_names):
            self._add(
                curr.lineno, "HARDCODED-DEP", "MEDIO",
                f"Dependencia hardcodeada '{func.id}()' dentro de '{func_name}'. "
                "Usa inyeccion de dependencias para mockear con spec/autospec.",
            )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._audit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._audit_func(node)


def audit_testability(source_filepath: str) -> List[Tuple[int, str, str, str]]:
    """
    Audita el código fuente mediante AST en busca de impedimentos de testabilidad
    (acoplamiento concreto, estado global mutable, I/O directo y no-determinismo).
    Retorna una lista de tuplas (línea, código, nivel, mensaje).
    """
    try:
        tree = read_and_parse(source_filepath)
    except FileNotFoundError:
        return [(0, "N/A", "ERROR", f"Archivo '{source_filepath}' no encontrado.")]
    except (IsADirectoryError, PermissionError, OSError, SyntaxError, UnicodeDecodeError) as e:
        return [(0, "AST", "ERROR", f"Error analizando testabilidad: {e}")]

    auditor = TestabilityAuditor(tree, os.path.splitext(os.path.basename(source_filepath))[0])
    auditor.visit(tree)
    return auditor.findings
