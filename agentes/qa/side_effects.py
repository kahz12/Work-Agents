"""
Detección de efectos secundarios en el código analizado.

El generador de tests sustituye por dobles todo lo que escribe, borra, mueve, ejecuta
procesos o abre conexiones. Si una de esas llamadas se le escapa, el test generado la haría
de verdad: `delete_items(...)` con un `shutil.rmtree` sin sustituir borra archivos reales.

Por eso la detección es amplia a propósito: es preferible sustituir de más que de menos.
Cada llamada detectada da un objetivo de `unittest.mock.patch` que funciona con la forma
en que el módulo la importa:

  import shutil; shutil.rmtree(p)        -> patch("shutil.rmtree")
  import shutil as sh; sh.rmtree(p)      -> patch("shutil.rmtree")
  from shutil import rmtree; rmtree(p)   -> patch("<modulo>.rmtree")
  Path(p).unlink()                       -> patch("pathlib.Path.unlink")
"""
from __future__ import annotations

import ast
import re
from typing import Optional, Tuple

from ..common.imports import ImportMap, attr_chain  # noqa: F401 - ImportMap se reexporta

# Llamadas con efectos, por nombre completo. Las de os son solo las que escriben, borran,
# cambian permisos o lanzan procesos: os.path.exists o os.listdir no hacen falta sustituirlas.
IO_NAMES = frozenset({
    "open", "urllib.request.urlopen",
    "os.system", "os.popen", "os.remove", "os.unlink", "os.rmdir", "os.removedirs",
    "os.rename", "os.renames", "os.replace", "os.mkdir", "os.makedirs", "os.chmod",
    "os.chown", "os.symlink", "os.link", "os.truncate", "os.startfile", "os.kill",
    "os.execv", "os.execve", "os.execvp", "os.spawnv", "os.spawnl", "os.fork",
})
# Módulos en los que cualquier llamada se considera E/S.
IO_PREFIXES = (
    "requests.", "httpx.", "aiohttp.", "urllib.request.", "http.client.", "socket.",
    "ftplib.", "smtplib.", "paramiko.", "subprocess.", "sqlite3.", "shutil.",
)
# Métodos de pathlib.Path con efectos. Se detectan aunque el objeto no sea un Path
# (no se puede saber sin ejecutar): sustituir un método que no se usa no hace daño.
PATH_METHODS = frozenset({
    "unlink", "rmdir", "rename", "write_text", "write_bytes", "mkdir", "touch",
    "chmod", "symlink_to", "hardlink_to",
})


# En esos módulos, crear una excepción o un resultado no es E/S: subprocess.TimeoutExpired(...) o
# subprocess.CompletedProcess(...) solo construyen un objeto. Sustituirlos por un doble rompería
# además los except que los capturan ("catching classes that do not inherit from BaseException").
_NOT_IO = re.compile(r"(Error|Exception|Expired|Warning|Exit)$|^CompletedProcess$")


def is_io(name: str) -> bool:
    if _NOT_IO.search(name.rsplit(".", 1)[-1]):
        return False
    return name in IO_NAMES or name.startswith(IO_PREFIXES)


def classify(call: ast.Call, imports: ImportMap) -> Optional[Tuple[str, str]]:
    """
    (nombre completo, objetivo de patch) si la llamada tiene efectos; None si no.
    """
    func = call.func
    if isinstance(func, ast.Name):
        if func.id in imports.names:
            full = imports.names[func.id]
            return (full, f"{imports.module}.{func.id}") if is_io(full) else None
        return ("open", "builtins.open") if func.id == "open" else None

    chain = attr_chain(func)
    if chain:
        full = imports.resolve(chain)
        if is_io(full):
            return full, full
    if isinstance(func, ast.Attribute) and func.attr in PATH_METHODS:
        head = chain.split(".")[0] if chain else ""
        # os.rename y similares ya se han resuelto arriba; aquí solo métodos de objetos.
        if head not in imports.modules:
            target = f"pathlib.Path.{func.attr}"
            return target, target
    return None
