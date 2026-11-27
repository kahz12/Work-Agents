"""
Resolution of imported names in an analysed module.

It tells what a call really targets: with `import shutil as sh`, `sh.rmtree` is
`shutil.rmtree`, while `ydl.urlopen` on a yt-dlp object is not `urllib.request.urlopen`.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, Set


@dataclass
class ImportMap:
    """The local names under which a module refers to what it imports."""

    module: str
    modules: Dict[str, str] = field(default_factory=dict)   # alias -> module  (import shutil as sh)
    names: Dict[str, str] = field(default_factory=dict)     # name -> origin   (from shutil import rmtree)
    star: Set[str] = field(default_factory=set)             # modules pulled in with `from x import *`

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
        """Fully qualified name of a chain such as `ur.urlopen`; unchanged when it does not come from an import."""
        head, dot, rest = chain.partition(".")
        if head in self.names:
            base = self.names[head]
        elif head in self.modules:
            base = self.modules[head]
        else:
            return chain
        return f"{base}{dot}{rest}"


def attr_chain(node: ast.AST) -> str:
    """`a.b.c` for a Name/Attribute chain; "" when the base is not a name (a call, a subscript...)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = attr_chain(node.value)
        return f"{prefix}.{node.attr}" if prefix else ""
    return ""
