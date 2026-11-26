"""
Resolución de nombres importados en un módulo analizado.

Sirve para saber a qué apunta de verdad una llamada: `sh.rmtree` con `import shutil as sh`
es `shutil.rmtree`, y `ydl.urlopen` sobre un objeto de yt-dlp no es `urllib.request.urlopen`.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, Set


@dataclass
class ImportMap:
    """Cómo se llaman en el módulo los nombres importados."""

    module: str
    modules: Dict[str, str] = field(default_factory=dict)   # alias -> módulo   (import shutil as sh)
    names: Dict[str, str] = field(default_factory=dict)     # nombre -> origen  (from shutil import rmtree)
    star: Set[str] = field(default_factory=set)             # módulos con `from x import *`

    @classmethod
    def from_tree(cls, tree: ast.AST, module: str = "") -> "ImportMap":
        imports = cls(module)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    imports.modules[local] = alias.name if alias.asname else alias.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                for alias in node.names:
                    if alias.name == "*":
                        imports.star.add(node.module)
                    else:
                        imports.names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        return imports

    def resolve(self, chain: str) -> str:
        """Nombre completo de una cadena como `ur.urlopen`; la deja igual si no viene de un import."""
        head, dot, rest = chain.partition(".")
        if head in self.names:
            base = self.names[head]
        elif head in self.modules:
            base = self.modules[head]
        else:
            return chain
        return f"{base}{dot}{rest}"


def attr_chain(node: ast.AST) -> str:
    """`a.b.c` para Name/Attribute; "" si la base no es un nombre (una llamada, un subíndice...)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = attr_chain(node.value)
        return f"{prefix}.{node.attr}" if prefix else ""
    return ""
