import ast
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from ..common.imports import ImportMap, attr_chain


def _is_test_file(filepath: str) -> bool:
    """Recognise test files by their base name only; parent directories do not count."""
    name = os.path.basename(filepath.replace("\\", "/")).lower()
    return name == "conftest.py" or (
        name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))
    )


def _has_keyword(call: ast.Call, name: str) -> bool:
    return any(kw.arg == name for kw in call.keywords)


def _keyword_is(call: ast.Call, name: str, value: bool) -> bool:
    """True when the call passes `name=value` as a literal (verify=False, shell=True...)."""
    return any(
        kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is value
        for kw in call.keywords
    )


def _is_built_string(node: ast.AST) -> bool:
    """Text built at runtime: an f-string, a `+` concatenation or `%` formatting."""
    return isinstance(node, ast.JoinedStr) or (
        isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod))
    )


def _open_mode(call: ast.Call) -> Optional[str]:
    """Mode of an open() call: 'r' when omitted, None when it is not a literal."""
    mode = call.args[1] if len(call.args) >= 2 else next((kw.value for kw in call.keywords if kw.arg == "mode"), None)
    if mode is None:
        return "r"
    return mode.value if isinstance(mode, ast.Constant) and isinstance(mode.value, str) else None


def _handler_nodes(body: List[ast.stmt]):
    """Nodes in an except body, without descending into functions or classes defined there."""
    pending: List[ast.AST] = list(body)
    while pending:
        node = pending.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            pending.extend(ast.iter_child_nodes(node))


def _propagates_or_logs(body: List[ast.stmt]) -> bool:
    """
    True when the handler re-raises (raise, raise X from e) or logs the traceback
    (logger.exception, exc_info=True). Ruff's BLE001 does not flag those handlers either.
    """
    for node in _handler_nodes(body):
        if isinstance(node, ast.Raise):
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "exception":
                return True
            if any(kw.arg == "exc_info" and not (isinstance(kw.value, ast.Constant) and not kw.value.value)
                   for kw in node.keywords):
                return True
    return False


def _uses_name(body: List[ast.stmt], name: Optional[str]) -> bool:
    """True when the handler body reads the caught exception: it reports, stores or inspects it."""
    return bool(name) and any(
        isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Load)
        for node in _handler_nodes(body)
    )


def _sql_construction(node: ast.AST) -> Optional[str]:
    """How a SQL statement was assembled by hand, or None for a literal or a plain variable."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return "string concatenation"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return "dynamic formatting (%)"
    if isinstance(node, ast.JoinedStr):
        return "f-string"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return "dynamic formatting (.format)"
    return None


# --- Rule constants -------------------------------------------------------------------------

DANGEROUS_FUNCTIONS = frozenset({"eval", "exec"})
HTTP_CLIENT_LIBS = frozenset({"requests", "httpx"})
HTTP_METHODS = frozenset({"get", "post", "put", "delete", "patch", "head", "request"})
RANDOM_GENERATORS = frozenset({"choice", "choices", "randint", "random", "randrange", "getrandbits", "sample"})
SENSITIVE_RANDOM_HINTS = ("nonce", "salt", "otp")

# Fully qualified names of the standard-library urlopen. A `.urlopen` method on some other
# object (yt-dlp's YoutubeDL, a custom opener) applies its own timeout, so it is not flagged.
URLLIB_URLOPEN = frozenset({"urllib.request.urlopen", "urllib2.urlopen", "six.moves.urllib.request.urlopen"})
_URLOPEN_MODULES = frozenset(name.rsplit(".", 1)[0] for name in URLLIB_URLOPEN)

# Base classes whose visit_* methods implement the visitor protocol and are documented there.
_VISITOR_BASES = frozenset({"NodeVisitor", "NodeTransformer"})

# Name fragments that suggest a credential, and metadata suffixes that only name a column or a
# UI label ("password_field" holds the name of a field, not a password).
SECRET_NAME_HINTS = (
    "password", "passwd", "passphrase", "secret", "api_key", "apikey",
    "token", "credential", "access_key", "client_secret", "private_key",
)
FIELD_NAME_SUFFIXES = ("_name", "_names", "_field", "_fields", "_label", "_column", "_header", "_param", "_attr")
# Placeholder values used in docs and templates, in English and Spanish. They are not secrets
# even when the key name looks like one.
_PLACEHOLDERS = ("changeme", "change_me", "your", "tu-", "tu_", "placeholder", "example",
                 "ejemplo", "todo", "tbd", "dummy", "sample", "fake", "redacted", "aqui", "here")

# Messages shared by several rules. Other modules recognise findings by their text
# (audits._TOPICS, rules._MESSAGE_RULES, reporting._SAST_SARIF_RULES), so rewording a message
# here means updating the regular expressions in those tables as well.
BLOCKING_IN_ASYNC = "Blocking synchronous call inside an 'async def' function (it blocks the event loop)."
URLOPEN_WITHOUT_TIMEOUT = "Call to 'urlopen()' without an explicit 'timeout' (DoS risk)."
BROAD_EXCEPT = "Use of 'except Exception:'. Catch more specific exceptions instead."
BROAD_EXCEPT_REPORTED = (
    "Use of 'except Exception:' that reports the error. Acceptable at a boundary (CLI, SDK, thread); "
    "elsewhere, catch more specific exceptions."
)
TOCTOU = (
    "Possible TOCTOU race condition: 'os.path.exists' followed by 'open()' for writing. "
    "The file can change between the check and the open (for example, it can be swapped for a "
    "symlink); use open(..., 'x') to create it only if it does not exist yet."
)

Issue = Tuple[int, str, str]


# --- Traversal state ------------------------------------------------------------------------

def _nothing() -> None:
    return None


class AnalysisState:
    """
    Per-file traversal state: what the rules need to know about the node being visited, plus
    the list where they record their findings.

    CodeQualityChecker updates it through enter() before visiting each node's children. Rules
    read it and report through issue(); the only rule that mutates it is the one that records,
    in checked_paths, the paths tested with os.path.exists(), which the TOCTOU rule reads later.
    """

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.is_test = _is_test_file(filename)
        self.issues: List[Issue] = []
        # Empty until enter() visits the module. It is traversal data, not an injected collaborator.
        self.imports = ImportMap("")  # agentes: ignore[SOLID-DIP]
        # Classes and functions enclosing the current node, outermost first.
        self.scopes: List[ast.AST] = []
        # True inside the body of an `async def`, but not inside a plain function nested in it.
        self.in_async = False
        # id() of the open() calls whose file is closed for us: inside a `with`, registered on an
        # ExitStack, or closed by a try statement. They are collected when the enclosing scope is
        # entered, so the set is complete before the call itself is visited.
        self.managed_opens: Set[int] = set()
        # Variables tested with os.path.exists() or isfile() in the current function.
        self.checked_paths: Set[str] = set()

    def issue(self, line: int, level: str, message: str) -> None:
        self.issues.append((line, level, message))

    def enter(self, node: ast.AST) -> Callable[[], object]:
        """
        Prepare the state for visiting node's children and return the callback that restores
        it afterwards. Only modules (their imports), `with` blocks (their open() calls), classes
        and functions (which open a new scope) change the state.
        """
        if isinstance(node, ast.Module):
            self.imports = ImportMap.from_tree(node)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            self.managed_opens.update(id(item.context_expr) for item in node.items if _is_open_call(item.context_expr))
        elif isinstance(node, ast.ClassDef):
            self.scopes.append(node)
            return self.scopes.pop
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return self._enter_function(node)
        return _nothing

    def _enter_function(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> Callable[[], object]:
        """A function starts with no checked paths and records whether its body is asynchronous."""
        self.managed_opens |= _managed_opens(node)
        saved = (self.checked_paths, self.in_async)
        self.checked_paths, self.in_async = set(), isinstance(node, ast.AsyncFunctionDef)
        self.scopes.append(node)

        def restore() -> None:
            self.scopes.pop()
            self.checked_paths, self.in_async = saved

        return restore


def _is_open_call(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open"


def _closed_names(stmts: List[ast.stmt]) -> Set[str]:
    """Names X for which these statements contain an X.close() call."""
    names = set()
    for stmt in stmts:
        for sub in ast.walk(stmt):
            if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr == "close"
                    and isinstance(sub.func.value, ast.Name)):
                names.add(sub.func.value.id)
    return names


def _managed_opens(func: ast.AST) -> Set[int]:
    """
    id() of the open() calls in func that do not need a `with` because the file is closed anyway:

    - `f = open(...)` followed by a try whose finally calls `f.close()`;
    - or a try whose except handlers and else branch all call `f.close()` (closing before a
      rename, for instance);
    - `stack.enter_context(open(...))` inside an ExitStack.
    """
    managed: Set[int] = set()
    assigned: Dict[str, List[ast.Call]] = {}
    try_types = tuple(t for t in (getattr(ast, "Try", None), getattr(ast, "TryStar", None)) if t)
    closed: Set[str] = set()
    for sub in ast.walk(func):
        if isinstance(sub, (ast.Assign, ast.AnnAssign)):
            targets = sub.targets if isinstance(sub, ast.Assign) else [sub.target]
            if len(targets) == 1 and isinstance(targets[0], ast.Name) and isinstance(sub.value, ast.Call) \
                    and _is_open_call(sub.value):
                assigned.setdefault(targets[0].id, []).append(sub.value)
        elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr == "enter_context":
            managed.update(id(arg) for arg in sub.args if _is_open_call(arg))
        elif isinstance(sub, try_types):
            if sub.finalbody:
                closed |= _closed_names(sub.finalbody)
            if sub.handlers and sub.orelse:
                every_handler = set.intersection(*(_closed_names(h.body) for h in sub.handlers))
                closed |= every_handler & _closed_names(sub.orelse)
    for name in closed & assigned.keys():
        managed.update(id(call) for call in assigned[name])
    return managed


# --- Function rules -------------------------------------------------------------------------

def _needs_docstring(state: AnalysisState, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> bool:
    """
    True for a public-API function that documents nothing itself. Exempt: private functions
    and tests; functions nested in another function; overrides of a method documented
    elsewhere (@override, visit_* on an ast.NodeVisitor); and property setters and deleters,
    which are documented on the getter.
    """
    if state.is_test or node.name.startswith(("_", "test_")) or ast.get_docstring(node):
        return False
    if any(isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) for scope in state.scopes):
        return False
    decorators = {attr_chain(d).rsplit(".", 1)[-1] for d in node.decorator_list if attr_chain(d)}
    if decorators & {"override", "setter", "deleter"}:
        return False
    parent = state.scopes[-1] if state.scopes else None
    if isinstance(parent, ast.ClassDef) and (node.name.startswith("visit_") or node.name == "generic_visit"):
        bases = {attr_chain(b).rsplit(".", 1)[-1] for b in parent.bases if attr_chain(b)}
        return not bases & _VISITOR_BASES
    return True


def _rule_missing_docstring(state: AnalysisState, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> None:
    if _needs_docstring(state, node):
        state.issue(node.lineno, "LOW", f"Public function '{node.name}' has no docstring.")


def _rule_too_many_args(state: AnalysisState, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> None:
    """Count positional parameters, excluding self and cls."""
    count = sum(1 for a in node.args.args if a.arg not in ("self", "cls"))
    if count > 5:
        state.issue(node.lineno, "MEDIUM", f"Function '{node.name}' takes {count} arguments (recommended maximum: 5).")


def _rule_mutable_default(state: AnalysisState, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> None:
    """A list, dict or set default is created once and shared by every call."""
    defaults = [*node.args.defaults, *(d for d in node.args.kw_defaults if d is not None)]
    if any(isinstance(d, (ast.List, ast.Dict, ast.Set)) for d in defaults):
        state.issue(node.lineno, "MEDIUM",
                    f"Function '{node.name}' uses a mutable default argument (list/dict/set); use None instead.")


# --- Exception rules ------------------------------------------------------------------------

def _is_silencing_body(body: List[ast.stmt]) -> bool:
    """True when the body is just `pass` or `...`."""
    if len(body) != 1:
        return False
    stmt = body[0]
    if isinstance(stmt, ast.Pass):
        return True
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis


def _rule_bare_except(state: AnalysisState, node: ast.ExceptHandler) -> None:
    if node.type is None:
        state.issue(node.lineno, "HIGH",
                    "Use of a bare 'except:'. It catches every exception, including ones nobody meant to handle.")


def _rule_broad_except(state: AnalysisState, node: ast.ExceptHandler) -> None:
    """
    Grade `except Exception` by what the handler does with the error: silencing it is the
    serious case; reporting it is normal at a boundary; re-raising it or logging the traceback
    hides nothing, so it is not flagged.
    """
    if not (isinstance(node.type, ast.Name) and node.type.id == "Exception"):
        return
    if _is_silencing_body(node.body):
        state.issue(node.lineno, "HIGH", "Use of 'except Exception: pass', which silences errors.")
    elif _propagates_or_logs(node.body):
        return
    elif _uses_name(node.body, node.name):
        state.issue(node.lineno, "LOW", BROAD_EXCEPT_REPORTED)
    else:
        state.issue(node.lineno, "MEDIUM", BROAD_EXCEPT)


# --- Call rules -----------------------------------------------------------------------------

def _rule_call(state: AnalysisState, node: ast.Call) -> None:
    """
    Run the rule chain that matches the callee: a bare name (eval(), open()...) or an attribute
    (os.system(), requests.get()...). Within a chain, the first rule whose condition matches
    owns the call even if it reports nothing: yaml.load with SafeLoader, for example, must not
    fall through to the remaining rules.
    """
    func = node.func
    if isinstance(func, ast.Name):
        for name_rule in NAME_CALL_RULES:
            if name_rule(state, node, func.id):
                return
    elif isinstance(func, ast.Attribute):
        owner = func.value.id if isinstance(func.value, ast.Name) else None
        for attribute_rule in ATTRIBUTE_CALL_RULES:
            if attribute_rule(state, node, func.attr, owner):
                return


def _is_urllib_urlopen(state: AnalysisState, func: ast.AST) -> bool:
    """True when the callee is urllib's urlopen, resolved through the module's own imports."""
    if isinstance(func, ast.Name):
        if func.id in state.imports.names:
            return state.imports.names[func.id] in URLLIB_URLOPEN
        # Without an explicit import, the bare name can only come from `from urllib.request import *`.
        return func.id == "urlopen" and bool(state.imports.star & _URLOPEN_MODULES)
    chain = attr_chain(func)
    return bool(chain) and state.imports.resolve(chain) in URLLIB_URLOPEN


def _check_blocking_in_async(state: AnalysisState, node: ast.Call) -> None:
    if state.in_async:
        state.issue(node.lineno, "MEDIUM", BLOCKING_IN_ASYNC)


def _check_urlopen(state: AnalysisState, node: ast.Call) -> None:
    # urlopen takes the timeout as its third positional argument.
    if not (len(node.args) >= 3 or _has_keyword(node, "timeout")):
        state.issue(node.lineno, "MEDIUM", URLOPEN_WITHOUT_TIMEOUT)
    _check_blocking_in_async(state, node)


def _writes(node: ast.Call) -> bool:
    """
    True when open() writes or creates the file, or when its mode is not a literal. Reading
    after an existence check only risks a FileNotFoundError, not an exploitable race.
    """
    mode = _open_mode(node)
    return mode is None or any(flag in mode for flag in "wax+")


# Rules for calls to a bare name: (state, call, name) -> True when the rule owns the call.

def _call_dynamic_exec(state: AnalysisState, node: ast.Call, name: str) -> bool:
    if name not in DANGEROUS_FUNCTIONS:
        return False
    state.issue(node.lineno, "CRITICAL", f"Use of the dynamic code execution function '{name}()'.")
    return True


def _call_open(state: AnalysisState, node: ast.Call, name: str) -> bool:
    """open() outside a `with`, with a hand-built path, or right after an existence check."""
    if name != "open":
        return False
    if id(node) not in state.managed_opens:
        state.issue(node.lineno, "MEDIUM",
                    "Call to 'open()' outside a 'with' context manager (risk of leaking file descriptors).")
    if not node.args:
        return True
    path = node.args[0]
    if _is_built_string(path):
        state.issue(node.lineno, "MEDIUM",
                    "File opened with a dynamically built path; validate it with Path.resolve() "
                    "to prevent path traversal.")
    elif isinstance(path, ast.Name) and path.id in state.checked_paths and _writes(node):
        state.issue(node.lineno, "MEDIUM", TOCTOU)
    return True


def _call_urlopen(state: AnalysisState, node: ast.Call, name: str) -> bool:
    """urlopen imported from urllib under its own name or an alias (from urllib.request import urlopen as uo)."""
    if not _is_urllib_urlopen(state, node.func):
        return False
    _check_urlopen(state, node)
    return True


# Rules for calls to an attribute: (state, call, attribute, owner name or None) -> True when the
# rule owns the call.

def _attr_path_check(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    """os.path.exists(x) / isfile(x): remember x so that a later open(x) can be flagged (TOCTOU)."""
    if not (_is_os_path_check(node.func) and node.args and isinstance(node.args[0], ast.Name)):
        return False
    state.checked_paths.add(node.args[0].id)
    return True


def _attr_pickle(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    if not (attr == "loads" and owner == "pickle"):
        return False
    state.issue(node.lineno, "CRITICAL", "Unsafe use of 'pickle.loads()' (deserialising untrusted data).")
    return True


def _attr_os_command(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    if not (owner == "os" and attr in ("system", "popen")):
        return False
    state.issue(node.lineno, "CRITICAL", f"Unsafe command execution with 'os.{attr}()' (command injection risk).")
    return True


def _attr_yaml_load(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    if not (owner == "yaml" and attr == "load"):
        return False
    if not _has_safe_yaml_loader(node):
        state.issue(node.lineno, "HIGH", "Unsafe use of 'yaml.load()' without SafeLoader (use yaml.safe_load).")
    return True


def _attr_weak_hash(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    if not (owner == "hashlib" and attr in ("md5", "sha1")):
        return False
    if not _keyword_is(node, "usedforsecurity", False):
        state.issue(node.lineno, "MEDIUM", f"Weak cryptographic hash 'hashlib.{attr}()' (use SHA-256 or stronger).")
    return True


def _attr_http_client(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    """requests or httpx: unverified TLS, a missing timeout, or a blocking call inside a coroutine."""
    if not (owner in HTTP_CLIENT_LIBS and attr in HTTP_METHODS):
        return False
    if _keyword_is(node, "verify", False):
        state.issue(node.lineno, "HIGH", "TLS verification disabled ('verify=False') in an HTTP request.")
    if not _has_keyword(node, "timeout"):
        state.issue(node.lineno, "MEDIUM", "HTTP request without an explicit 'timeout' (DoS risk).")
    _check_blocking_in_async(state, node)
    return True


def _attr_urlopen(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    if not (attr == "urlopen" and _is_urllib_urlopen(state, node.func)):
        return False
    _check_urlopen(state, node)
    return True


def _attr_sleep_in_async(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    if not (owner == "time" and attr == "sleep" and state.in_async):
        return False
    state.issue(node.lineno, "MEDIUM", BLOCKING_IN_ASYNC)
    return True


def _attr_shell(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    if not (attr in ("Popen", "run", "call") and owner == "subprocess"):
        return False
    if _keyword_is(node, "shell", True):
        state.issue(node.lineno, "HIGH", "Subprocess started with 'shell=True' (command injection risk).")
    return True


def _attr_sql(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    """Hand-built SQL passed to execute(): concatenation, %, an f-string or .format."""
    if not (attr in ("execute", "executemany") and node.args):
        return False
    how = _sql_construction(node.args[0])
    if how:
        state.issue(node.lineno, "HIGH", f"Possible SQL injection: {how} in execute().")
    return True


def _attr_jinja(state: AnalysisState, node: ast.Call, attr: str, owner: Optional[str]) -> bool:
    """Jinja templates rendered without a guarantee that autoescape is on."""
    if not (attr in ("render", "from_string") and owner and "jinja" in owner.lower()):
        return False
    state.issue(node.lineno, "MEDIUM", "Jinja render/from_string call: make sure autoescape is enabled.")
    return True


def _is_os_path_check(func_node: ast.AST) -> bool:
    return (
        isinstance(func_node, ast.Attribute)
        and func_node.attr in ("exists", "isfile")
        and isinstance(func_node.value, ast.Attribute)
        and func_node.value.attr == "path"
        and isinstance(func_node.value.value, ast.Name)
        and func_node.value.value.id == "os"
    )


def _is_safe_yaml_loader(loader_node: ast.AST) -> bool:
    if isinstance(loader_node, ast.Name):
        return loader_node.id in ("SafeLoader", "CSafeLoader")
    if isinstance(loader_node, ast.Attribute):
        return loader_node.attr in ("SafeLoader", "CSafeLoader")
    return False


def _has_safe_yaml_loader(node: ast.Call) -> bool:
    """yaml.load with Loader=SafeLoader (or CSafeLoader), as a keyword or as the second argument."""
    if any(kw.arg == "Loader" and _is_safe_yaml_loader(kw.value) for kw in node.keywords):
        return True
    return len(node.args) >= 2 and _is_safe_yaml_loader(node.args[1])


# --- Secret and assert rules ----------------------------------------------------------------

def _names_a_secret(name: str) -> bool:
    low = name.lower()
    if low.endswith(FIELD_NAME_SUFFIXES):
        return False
    return any(k in low for k in SECRET_NAME_HINTS)


def _is_real_secret_value(node: Optional[ast.AST]) -> bool:
    """A string constant long enough to be a credential that is not an obvious placeholder."""
    if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
        return False
    val = node.value.strip()
    if len(val) < 8:
        return False
    low = val.lower()
    if any(low.startswith(r) or low == r for r in _PLACEHOLDERS):
        return False
    if val.startswith("<") and val.endswith(">"):
        return False
    if val.startswith("$") or (val.startswith("{") and val.endswith("}")):
        return False
    return set(val) - set("xX*-_.") != set()


def _uses_insecure_random(value: ast.AST) -> bool:
    """True when the expression calls one of the random.* generators."""
    for sub in ast.walk(value):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and isinstance(sub.func.value, ast.Name)
            and sub.func.value.id == "random"
            and sub.func.attr in RANDOM_GENERATORS
        ):
            return True
    return False


def _names_sensitive_random(name: str) -> bool:
    """A secret-like name, or one for material that must also be unpredictable (nonce, salt, otp)."""
    if _names_a_secret(name):
        return True
    low = name.lower()
    return not low.endswith(FIELD_NAME_SUFFIXES) and any(k in low for k in SENSITIVE_RANDOM_HINTS)


def _check_secret_target(state: AnalysisState, target: ast.AST, value: Optional[ast.AST], lineno: int) -> None:
    """
    Check an assignment to a secret-looking variable or attribute: a real literal value is an
    embedded secret (except in tests), and a value produced by random.* is predictable material.
    """
    if value is None:
        return
    name = target.id if isinstance(target, ast.Name) else target.attr if isinstance(target, ast.Attribute) else None
    if not name:
        return
    if not state.is_test and _names_a_secret(name) and _is_real_secret_value(value):
        state.issue(lineno, "HIGH", f"Possible hardcoded secret in '{name}'.")
    elif _names_sensitive_random(name) and _uses_insecure_random(value):
        state.issue(lineno, "HIGH", "The 'random' module is used to generate sensitive material; use 'secrets' instead.")


def _rule_secret_in_assign(state: AnalysisState, node: ast.Assign) -> None:
    """Plain and chained assignments: PASSWORD = "..." or a = b = "..."."""
    for target in node.targets:
        _check_secret_target(state, target, node.value, node.lineno)


def _rule_secret_in_annassign(state: AnalysisState, node: ast.AnnAssign) -> None:
    """Annotated assignments (API_KEY: str = "..."); a bare annotation has no value to check."""
    _check_secret_target(state, node.target, node.value, node.lineno)


def _rule_secret_in_dict(state: AnalysisState, node: ast.Dict) -> None:
    """Keys of a dict literal ({"token": "..."}), which never go through an assignment."""
    if state.is_test:
        return
    for key, value in zip(node.keys, node.values):
        if isinstance(key, ast.Constant) and isinstance(key.value, str) \
                and _names_a_secret(key.value) and _is_real_secret_value(value):
            state.issue(node.lineno, "HIGH", f"Possible hardcoded secret in key '{key.value}'.")


def _rule_secret_in_keyword(state: AnalysisState, node: ast.keyword) -> None:
    """Keyword arguments (connect(password="...")): the secret goes straight into the call."""
    if not state.is_test and node.arg and _names_a_secret(node.arg) and _is_real_secret_value(node.value):
        state.issue(getattr(node.value, "lineno", 0), "HIGH", f"Possible hardcoded secret in argument '{node.arg}'.")


def _rule_assert(state: AnalysisState, node: ast.Assert) -> None:
    if not state.is_test:
        state.issue(node.lineno, "LOW",
                    "Use of assert (stripped under python -O); do not rely on it for validation in production code.")


# --- Rule tables ----------------------------------------------------------------------------

Rule = Callable[[AnalysisState, Any], None]
NameCallRule = Callable[[AnalysisState, ast.Call, str], bool]
AttributeCallRule = Callable[[AnalysisState, ast.Call, str, Optional[str]], bool]

_FUNCTION_RULES: Tuple[Rule, ...] = (_rule_missing_docstring, _rule_too_many_args, _rule_mutable_default)

# Rules per node type. Findings for one node are reported in the order of its tuple.
RULES: Dict[type, Tuple[Rule, ...]] = {
    ast.FunctionDef: _FUNCTION_RULES,
    ast.AsyncFunctionDef: _FUNCTION_RULES,
    ast.ExceptHandler: (_rule_bare_except, _rule_broad_except),
    ast.Call: (_rule_call,),
    ast.Assert: (_rule_assert,),
    ast.Assign: (_rule_secret_in_assign,),
    ast.AnnAssign: (_rule_secret_in_annassign,),
    ast.Dict: (_rule_secret_in_dict,),
    ast.keyword: (_rule_secret_in_keyword,),
}

# Chains used by _rule_call: tried in order, and the first rule that returns True owns the call.
NAME_CALL_RULES: Tuple[NameCallRule, ...] = (_call_dynamic_exec, _call_open, _call_urlopen)
ATTRIBUTE_CALL_RULES: Tuple[AttributeCallRule, ...] = (
    _attr_path_check, _attr_pickle, _attr_os_command, _attr_yaml_load, _attr_weak_hash,
    _attr_http_client, _attr_urlopen, _attr_sleep_in_async, _attr_shell, _attr_sql, _attr_jinja,
)


class CodeQualityChecker(ast.NodeVisitor):
    """
    AST-based static analysis: Bandit-style security checks plus code-quality checks.

    Walks the tree in pre-order. At each node it runs the rules registered in RULES for that
    node type, updates the state through AnalysisState.enter() and visits the children. Adding
    a rule means adding a function to the tables; the traversal itself never changes. Findings
    are (line, level, message) tuples.
    """

    def __init__(self, filename: str) -> None:
        self.filename = filename
        # Each traversal owns its state; there is nothing to inject or swap out.
        self.state = AnalysisState(filename)  # agentes: ignore[SOLID-DIP]

    @property
    def issues(self) -> List[Issue]:
        """Findings in the order they were found."""
        return self.state.issues

    def visit(self, node: ast.AST) -> None:
        for rule in RULES.get(type(node), ()):
            rule(self.state, node)
        restore = self.state.enter(node)
        try:
            self.generic_visit(node)
        finally:
            restore()


# In tests, assert (B101) and sample passwords (B105 to B107) are expected, and the AST engine
# does not flag them in test files either.
_BANDIT_SKIPPED_IN_TESTS = frozenset({"B101", "B105", "B106", "B107"})


def _run_bandit(command: List[str], chunk: List[str]) -> Optional[Dict[str, Any]]:
    """
    Bandit's JSON report for a chunk of files, or None when it could not be obtained: Bandit
    did not finish within 60 seconds, could not be started, or printed nothing or something
    other than a JSON object. Files in that chunk are then covered by the AST engine alone.
    """
    try:
        proc = subprocess.run(
            [*command, "-f", "json", "-q", *chunk],
            capture_output=True,
            text=True,
            timeout=60,
        )
        raw = proc.stdout.strip()
        data = json.loads(raw) if raw else None
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _bandit_issues_by_file(data: Dict[str, Any], chunk: List[str]) -> Dict[str, List[Issue]]:
    """
    Group a Bandit report by file, keyed by each path exactly as the caller passed it. Bandit
    may spell paths differently, so they are matched by their real path. Every file in the
    chunk gets an entry, even with no findings, so that "no findings" can be told apart from
    "Bandit did not analyse this file".
    """
    real_to_orig = {os.path.realpath(fp): fp for fp in chunk}
    grouped: Dict[str, List[Issue]] = {fp: [] for fp in chunk}
    for item in data.get("results", []):
        fname = item.get("filename")
        orig_fp = real_to_orig.get(os.path.realpath(fname)) if fname else None
        if orig_fp is None or (_is_test_file(orig_fp) and item.get("test_id") in _BANDIT_SKIPPED_IN_TESTS):
            continue
        grouped[orig_fp].append(StaticCodeAnalyzer._bandit_item_to_issue(item))
    return grouped


class StaticCodeAnalyzer:
    """
    Static analysis front end: runs Bandit when it is installed and always runs the AST engine.
    Also exports findings as SARIF 2.1.0.
    """

    _SEVERITY_MAP = {
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "UNDEFINED": "LOW",
    }

    @staticmethod
    def _bandit_item_to_issue(item: dict) -> Tuple[int, str, str]:
        sev = StaticCodeAnalyzer._SEVERITY_MAP.get(str(item.get("issue_severity", "LOW")).upper(), "MEDIUM")
        # Bandit reports severity and confidence separately; HIGH severity with HIGH confidence
        # is promoted to CRITICAL so it sorts above the merely likely issues.
        if str(item.get("issue_confidence", "")).upper() == "HIGH" and sev == "HIGH":
            sev = "CRITICAL"
        line = int(item.get("line_number") or 0)
        text = item.get("issue_text") or item.get("test_name") or "Bandit finding"
        return (line, sev, f"[bandit] {text}")

    @staticmethod
    def bandit_command() -> Optional[List[str]]:
        """
        Command line that runs Bandit, or None when it is not installed.

        The interpreter running agentes is tried first (`python -m bandit`), so Bandit is found
        even when its virtual environment is not activated (pipx, an absolute path, CI running
        `python -m agentes`). The PATH is searched next.
        """
        if importlib.util.find_spec("bandit") is not None:
            return [sys.executable, "-m", "bandit"]
        exe = shutil.which("bandit")
        return [exe] if exe else None

    @staticmethod
    def _analyze_batch_with_bandit(
        filepaths: List[str],
        chunk_size: int = 100,
    ) -> Optional[Dict[str, List[Tuple[int, str, str]]]]:
        """
        Bandit findings per file, running one subprocess per chunk of chunk_size files. A chunk
        Bandit fails on is left out of the result, so its files fall back to the AST engine.
        Returns None when Bandit is not installed or failed on every chunk.
        """
        command = StaticCodeAnalyzer.bandit_command()
        if not command or not filepaths:
            return None
        grouped: Dict[str, List[Tuple[int, str, str]]] = {}
        any_chunk_ok = False
        for start in range(0, len(filepaths), chunk_size):
            chunk = filepaths[start:start + chunk_size]
            data = _run_bandit(command, chunk)
            if data is None:
                continue
            any_chunk_ok = True
            grouped.update(_bandit_issues_by_file(data, chunk))
        return grouped if any_chunk_ok else None

    @staticmethod
    def _analyze_with_bandit(filepath: str) -> Optional[List[Tuple[int, str, str]]]:
        batch = StaticCodeAnalyzer._analyze_batch_with_bandit([filepath])
        if batch is None:
            return None
        return batch.get(filepath)

    @staticmethod
    def _merge_issues(
        bandit_issues: Optional[List[Tuple[int, str, str]]],
        ast_issues: List[Tuple[int, str, str]],
    ) -> List[Tuple[int, str, str]]:
        if bandit_issues is None:
            return ast_issues
        merged = list(bandit_issues)
        seen = {(ln, msg) for ln, _, msg in bandit_issues}
        for item in ast_issues:
            key = (item[0], item[2])
            if key not in seen:
                merged.append(item)
                seen.add(key)
        return merged

    @staticmethod
    def _analyze_with_ast(filepath: str) -> List[Tuple[int, str, str]]:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                code_content = f.read()
            tree = ast.parse(code_content, filename=filepath)
            checker = CodeQualityChecker(filepath)
            checker.visit(tree)
            return checker.issues
        except SyntaxError as e:
            return [(e.lineno or 0, "HIGH", f"Syntax error: {e.msg}")]
        except Exception as e:
            return [(0, "ERROR", f"Error during analysis: {str(e)}")]

    @staticmethod
    def analyze_python_files(
        filepaths: List[str],
        *,
        prefer_bandit: bool = True,
    ) -> Dict[str, List[Tuple[int, str, str]]]:
        """
        Analyse several Python files in one batch: one Bandit subprocess per chunk plus the AST
        engine on every file. Maps each path to its merged findings.
        """
        existing = [fp for fp in filepaths if os.path.exists(fp)]
        batch_map = (
            StaticCodeAnalyzer._analyze_batch_with_bandit(existing)
            if (prefer_bandit and existing) else None
        )
        results: Dict[str, List[Tuple[int, str, str]]] = {}
        for fp in filepaths:
            if not os.path.exists(fp):
                results[fp] = [(0, "ERROR", f"File {fp} does not exist.")]
                continue
            b_issues = batch_map.get(fp) if batch_map is not None else None
            ast_issues = StaticCodeAnalyzer._analyze_with_ast(fp)
            results[fp] = StaticCodeAnalyzer._merge_issues(b_issues, ast_issues)
        return results

    @staticmethod
    def analyze_python_file(filepath: str, *, prefer_bandit: bool = True) -> List[Tuple[int, str, str]]:
        """
        Analyse a single Python file with Bandit (when available) and the AST engine.
        """
        return StaticCodeAnalyzer.analyze_python_files([filepath], prefer_bandit=prefer_bandit)[filepath]

    @staticmethod
    def export_to_sarif(filepath: str, issues: List[Tuple[int, str, str]], output_sarif_path: str) -> str:
        """
        Write the findings as a SARIF 2.1.0 log that GitHub Code Scanning can ingest.
        """
        from ..common.reporting import findings_to_sarif

        abs_file = os.path.abspath(filepath)
        findings = [
            {
                "file": abs_file,
                "line": line,
                "level": level,
                "message": desc,
                "rule_id": f"SAST-{level}",
            }
            for line, level, desc in issues
        ]
        return findings_to_sarif(
            "DefensiveCodeQualityChecker",
            findings,
            output_sarif_path,
            base_dir=os.path.dirname(abs_file),
        )
