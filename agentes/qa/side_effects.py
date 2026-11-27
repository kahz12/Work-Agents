"""
Side-effect detection in the analysed code.

The test generator replaces with test doubles everything that writes, deletes, moves, starts
processes or opens connections. If one of those calls slipped through, the generated test
would perform it for real: `delete_items(...)` with an unpatched `shutil.rmtree` deletes real
files.

That is why detection is deliberately broad: patching too much is better than too little.
Every detected call yields a `unittest.mock.patch` target that works with the way the module
imports it:

  import shutil; shutil.rmtree(p)        -> patch("shutil.rmtree")
  import shutil as sh; sh.rmtree(p)      -> patch("shutil.rmtree")
  from shutil import rmtree; rmtree(p)   -> patch("<module>.rmtree")
  Path(p).unlink()                       -> patch("pathlib.Path.unlink")
"""
from __future__ import annotations

import ast
import re
from typing import Optional, Tuple

from ..common.imports import ImportMap, attr_chain  # noqa: F401 - ImportMap is re-exported

# Calls with side effects, by fully qualified name. The os entries are only those that write,
# delete, change permissions or start processes: os.path.exists or os.listdir need no patching.
IO_NAMES = frozenset({
    "open", "urllib.request.urlopen",
    "os.system", "os.popen", "os.remove", "os.unlink", "os.rmdir", "os.removedirs",
    "os.rename", "os.renames", "os.replace", "os.mkdir", "os.makedirs", "os.chmod",
    "os.chown", "os.symlink", "os.link", "os.truncate", "os.startfile", "os.kill",
    "os.execv", "os.execve", "os.execvp", "os.spawnv", "os.spawnl", "os.fork",
})
# Modules where any call counts as I/O.
IO_PREFIXES = (
    "requests.", "httpx.", "aiohttp.", "urllib.request.", "http.client.", "socket.",
    "ftplib.", "smtplib.", "paramiko.", "subprocess.", "sqlite3.", "shutil.",
)
# pathlib.Path methods with side effects. They are matched even when the receiver may not be a
# Path (that cannot be known without running the code): patching an unused method is harmless.
PATH_METHODS = frozenset({
    "unlink", "rmdir", "rename", "write_text", "write_bytes", "mkdir", "touch",
    "chmod", "symlink_to", "hardlink_to",
})


# Within those modules, building an exception or a result object is not I/O:
# subprocess.TimeoutExpired(...) or subprocess.CompletedProcess(...) only construct a value.
# Replacing them with a double would also break the except clauses that catch them ("catching
# classes that do not inherit from BaseException is not allowed").
_NOT_IO = re.compile(r"(Error|Exception|Expired|Warning|Exit)$|^CompletedProcess$")


def is_io(name: str) -> bool:
    """True when a fully qualified call name has side effects that a generated test must patch."""
    if _NOT_IO.search(name.rsplit(".", 1)[-1]):
        return False
    return name in IO_NAMES or name.startswith(IO_PREFIXES)


def classify(call: ast.Call, imports: ImportMap) -> Optional[Tuple[str, str]]:
    """
    (fully qualified name, patch target) when the call has side effects, otherwise None.
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
        # os.rename and friends were resolved above; only methods on objects reach this point.
        if head not in imports.modules:
            target = f"pathlib.Path.{func.attr}"
            return target, target
    return None
