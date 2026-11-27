"""
How the generated tests call each function or method.

For every target it decides which arguments to pass, where each sample value comes from, how
to obtain the object a method is called on, and how to import the module. Sample values come
from, most reliable first:

1. the parameter's default value: the argument is omitted and the function uses its own;
2. its type annotation, including the module's aliases, classes, enums and Literals;
3. how the function body uses it (iterates it, calls .lower() on it, compares it with 5...);
4. its name (SAMPLE_BY_NAME and the rules in sample_for_arg).

Values from 3 and 4 are assumptions unless they match a name in the table. A test built on
assumed values says so and, when they do not fit the function (TypeError or AttributeError), it
is skipped rather than failed: not knowing how to build a good sample is not a defect of the
analysed code.
"""
from __future__ import annotations

import ast
import builtins
import os
from typing import Dict, FrozenSet, List, NamedTuple, Optional, Sequence, Set, Tuple

from .ast_inspector import FuncNode, _attr_chain, _name_of, body_nodes, method_kind
from .project import ProjectIndex, module_import
from .sample_values import SAMPLE_BY_NAME, boundary_samples_for_param, sample_for_arg

# --- Types and sample values ------------------------------------------------------------------

# Sample expression for each value kind the generator knows how to build.
KIND_SAMPLES: Dict[str, str] = {
    "int": "1", "float": "1.0", "number": "1", "str": '"sample"', "bytes": 'b"sample"',
    "bool": "True", "list": "[]", "dict": "{}", "set": "set()", "tuple": "()",
    "callable": "lambda *args, **kwargs: None", "none": "None",
}
_BUILTIN_TYPES: Dict[str, str] = {
    "int": "int", "float": "float", "complex": "number", "str": "str", "bytes": "bytes",
    "bytearray": "bytes", "bool": "bool", "list": "list", "dict": "dict", "set": "set",
    "frozenset": "set", "tuple": "tuple", "None": "none", "NoneType": "none",
}
# Generic types from typing and collections.abc, by their bare name.
_GENERIC_TYPES: Dict[str, str] = {
    "List": "list", "Sequence": "list", "MutableSequence": "list", "Iterable": "list",
    "Collection": "list", "Reversible": "list", "Dict": "dict", "Mapping": "dict",
    "MutableMapping": "dict", "OrderedDict": "dict", "DefaultDict": "dict", "Set": "set",
    "FrozenSet": "set", "AbstractSet": "set", "MutableSet": "set", "Tuple": "tuple",
    "Callable": "callable", "Text": "str", "AnyStr": "str", "ByteString": "bytes",
}
# Standard-library types with a fixed sample: (module to import, expression).
_STDLIB_TYPES: Dict[str, Tuple[str, str]] = {
    "Path": ("pathlib", 'pathlib.Path("sample.txt")'),
    "PurePath": ("pathlib", 'pathlib.PurePath("sample.txt")'),
    "PurePosixPath": ("pathlib", 'pathlib.PurePosixPath("sample.txt")'),
    "Decimal": ("decimal", 'decimal.Decimal("1.5")'),
    "Fraction": ("fractions", "fractions.Fraction(1, 2)"),
    "datetime": ("datetime", "datetime.datetime(2024, 1, 1, 12, 0)"),
    "date": ("datetime", "datetime.date(2024, 1, 1)"),
    "time": ("datetime", "datetime.time(12, 0)"),
    "timedelta": ("datetime", "datetime.timedelta(seconds=1)"),
    "Pattern": ("re", 're.compile("sample")'),
}
# Wrappers that do not change the type of the value.
_TRANSPARENT = frozenset({"Optional", "Annotated", "Final", "ClassVar", "Required", "NotRequired", "ReadOnly"})
_ANY_TYPES = frozenset({"Any", "object"})
_ENUM_BASES = frozenset({"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag", "ReprEnum"})
# UI frameworks: methods of their components need the application running (Textual's
# query_one fails without a mounted screen; a Tk widget fails without a window).
_UI_FRAMEWORKS: Dict[str, str] = {
    "textual": "Textual", "tkinter": "Tkinter", "customtkinter": "CustomTkinter", "PyQt5": "Qt",
    "PyQt6": "Qt", "PySide2": "Qt", "PySide6": "Qt", "wx": "wxPython", "kivy": "Kivy", "kivymd": "KivyMD",
    "toga": "Toga",
}
# Value kinds that have boundary values.
_BOUNDARY_KINDS = frozenset({"int", "float", "number", "str", "bytes", "bool", "list", "dict"})


class Sample(NamedTuple):
    """
    A sample value expression, its value kind and whether it is an assumption. For a typed
    container, item is its sample element (k: v for a dict), used to build its boundary values.
    """

    expr: str
    kind: str
    assumed: bool
    item: Optional[str] = None


class ClassModel(NamedTuple):
    """
    What the generator needs to know about a module class to construct it and call its methods.
    params are the constructor parameters (from __init__, or the fields of a dataclass or
    NamedTuple); abstract_methods, the abstract methods neither it nor its bases implement; ui,
    the UI framework it inherits from (Textual, Qt...), or "" when it is not a UI component.
    """

    name: str
    bases: List[str]
    init: Optional[FuncNode]
    params: List[ast.arg]
    defaults: Dict[str, ast.AST]
    kwonly: List[str]
    enum: bool
    protocol: bool
    abstract_methods: FrozenSet[str]
    method_kinds: Dict[str, str]
    ui: str = ""

    @property
    def abstract(self) -> bool:
        """It cannot be instantiated: it is a Protocol or still has unimplemented abstract methods."""
        return self.protocol or bool(self.abstract_methods)


class SampleContext:
    """
    What the generator knows about a module: its classes and its type aliases. The analysed
    module's context is the root; with a ProjectIndex, classes it imports from other project
    modules are looked up in their own module's context (child), where their annotations make
    sense. While tests are generated, the root records which names from the analysed module,
    other project modules and the standard library the expressions use, so the suite imports them.
    """

    def __init__(self, tree: Optional[ast.Module], project: Optional[ProjectIndex] = None, *,
                 module: Optional[str] = None, root: Optional["SampleContext"] = None) -> None:
        self.project = project
        self.module = module if module is not None else (project.module if project else "")
        self.root: SampleContext = root or self
        if root is None:
            self._used_names: Set[str] = set()
            self._used_modules: Set[str] = set()
            self.foreign_imports: Dict[str, Set[str]] = {}
            self._children: Dict[str, Optional[SampleContext]] = {}
        self.imported: Dict[str, Tuple[str, str]] = project.imports_of(self.module)[0] if project else {}
        self.classes: Dict[str, ClassModel] = {}
        self.aliases: Dict[str, ast.AST] = {}
        self.module_names: Set[str] = module_bindings(tree.body) if tree is not None else set()
        ui_names = _ui_bindings(tree.body) if tree is not None else {}
        for node in tree.body if tree is not None else []:
            if isinstance(node, ast.ClassDef):
                heads = [_attr_chain(_base_node(b)).split(".", 1)[0] for b in node.bases]
                ui = next((ui_names[h] for h in heads if h in ui_names), "")
                self.classes[node.name] = _class_model(node)._replace(ui=ui)
            elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                self.aliases[node.targets[0].id] = node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
                self.aliases[node.target.id] = node.value
        self._inherit()

    @property
    def used_names(self) -> Set[str]:
        """Names the suite imports from the analysed module."""
        return self.root._used_names

    @used_names.setter
    def used_names(self, value: Set[str]) -> None:
        self.root._used_names = value

    @property
    def used_modules(self) -> Set[str]:
        """Standard-library modules the sample values use (pathlib, datetime...)."""
        return self.root._used_modules

    @used_modules.setter
    def used_modules(self, value: Set[str]) -> None:
        self.root._used_modules = value

    def snapshot(self) -> Tuple[Set[str], Set[str], Dict[str, Set[str]]]:
        """Snapshot of what has been recorded so far, to undo the names of a target that ends up skipped."""
        root = self.root
        return set(root._used_names), set(root._used_modules), {m: set(n) for m, n in root.foreign_imports.items()}

    def restore(self, snapshot: Tuple[Set[str], Set[str], Dict[str, Set[str]]]) -> None:
        root = self.root
        root._used_names, root._used_modules, root.foreign_imports = snapshot

    def child(self, module: str) -> Optional["SampleContext"]:
        """Context of another project module, created once; None when it cannot be read or is being created."""
        root = self.root
        if module == root.module:
            return root
        if module not in root._children:
            root._children[module] = None  # placeholder while it is built, so a circular import cannot recurse
            tree = root.project.tree(module) if root.project else None
            if tree is not None:
                root._children[module] = SampleContext(tree, root.project, module=module, root=root)
        return root._children[module]

    def lookup(self, name: str, depth: int = 0) -> Optional[Tuple["SampleContext", ClassModel]]:
        """The class name refers to in this module, with its own module's context; None when unknown."""
        if name in self.classes:
            return self, self.classes[name]
        if name not in self.imported or depth > 4:
            return None
        module, original = self.imported[name]
        owner = self.child(module)
        return owner.lookup(original, depth + 1) if owner is not None and owner is not self else None

    def require(self, name: str) -> bool:
        """
        Record that the suite uses name, a class of this module: imported from the analysed module
        when this is the root or the analysed module imports it under that name, otherwise from
        this module. False when it would clash with a name the suite already uses (a class with
        the same name from another module).
        """
        root = self.root
        if self is root or root.imported.get(name) == (self.module, name):
            root.used_names.add(name)
            return True
        if name in root.module_names or any(name in names for module, names in root.foreign_imports.items()
                                             if module != self.module):
            return False
        root.foreign_imports.setdefault(self.module, set()).add(name)
        return True

    def exception_import(self, name: str) -> Optional[str]:
        """
        What the suite must import from the module to name an exception the code raises: its
        first name ("binascii" for binascii.Error), "" for a builtin that needs no import, or None
        when it does not exist at module level (a local variable, self.error) and the test cannot
        refer to it. A module-level name shadows the builtin of the same name.
        """
        head = name.split(".", 1)[0]
        if head in self.module_names:
            return "" if head in _HEADER_MODULES else head
        builtin = getattr(builtins, name, None)
        if "." not in name and isinstance(builtin, type) and issubclass(builtin, BaseException):
            return ""
        return None

    def use_exception(self, name: str) -> bool:
        """Record the import needed to name the exception; False when the suite cannot name it."""
        head = self.exception_import(name)
        if head is None:
            return False
        if head:
            self.used_names.add(head)
        return True

    def _inherit(self) -> None:
        """
        Propagate what classes take from their module bases: the constructor, enum-ness and
        outstanding abstract methods. Repeats until nothing changes, so it flows down the whole
        inheritance chain.
        """
        for _ in range(len(self.classes)):
            if not self._inherit_step():
                return

    def _inherit_step(self) -> bool:
        """One inheritance pass over every class; True when any class changed."""
        changed = False
        for name, model in list(self.classes.items()):
            updated = model
            for base in model.bases:
                parent = self.classes.get(base)
                if parent is not None and parent.name != name:
                    updated = _inherit_from(updated, parent)
                elif parent is None and not updated.ui:
                    # From a base defined in another project module only the UI framework is
                    # inherited. Its constructor is not copied: its annotations use names from
                    # that other module, which do not resolve here.
                    found = self.lookup(base)
                    updated = updated._replace(ui=found[1].ui) if found is not None else updated
            if updated != model:
                self.classes[name] = updated
                changed = True
        return changed


def _inherit_from(model: ClassModel, parent: ClassModel) -> ClassModel:
    """model plus what it inherits from parent: the constructor when it has none, enum-ness and the abstract methods it leaves unimplemented."""
    own_init = model.init is not None or bool(model.params)
    implemented = {m for m, kind in model.method_kinds.items() if kind != "abstract"}
    return model._replace(
        init=model.init or parent.init,
        params=model.params if own_init else parent.params,
        defaults=model.defaults if own_init else parent.defaults,
        kwonly=model.kwonly if own_init else parent.kwonly,
        enum=model.enum or parent.enum,
        abstract_methods=model.abstract_methods | (parent.abstract_methods - implemented),
        ui=model.ui or parent.ui,
    )


# Modules the suite header already imports; they never need importing from the analysed module.
_HEADER_MODULES = frozenset({"os", "sys"})


def _assigned_names(node: ast.stmt) -> Set[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [getattr(node, "target", None)]
    return {n.id for t in targets if t is not None for n in ast.walk(t) if isinstance(n, ast.Name)}


def module_bindings(stmts: Sequence[ast.stmt]) -> Set[str]:
    """
    Names certainly bound at module level once the module is imported. From an if, only names
    bound by both branches count (if TYPE_CHECKING: binds nothing at runtime); from a try, only
    those bound whether it completes normally or any of its except handlers runs.
    """
    names: Set[str] = set()
    for node in stmts:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Import):
            names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.update(alias.asname or alias.name for alias in node.names if alias.name != "*")
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            names |= _assigned_names(node)
        elif isinstance(node, ast.If):
            names |= module_bindings(node.body) & module_bindings(node.orelse)
        elif isinstance(node, ast.Try) or type(node).__name__ == "TryStar":
            completed = module_bindings(node.body) | module_bindings(node.orelse)  # type: ignore[attr-defined]
            for handler in node.handlers:  # type: ignore[attr-defined]
                completed &= module_bindings(handler.body)
            names |= completed | module_bindings(node.finalbody)  # type: ignore[attr-defined]
    return names


def _is_dataclass(node: ast.ClassDef) -> bool:
    return any(_attr_chain(d.func if isinstance(d, ast.Call) else d).rsplit(".", 1)[-1] == "dataclass"
               for d in node.decorator_list)


def _field_params(node: ast.ClassDef) -> Tuple[List[ast.arg], Dict[str, ast.AST]]:
    """Fields of a dataclass or NamedTuple, in order, with their default values."""
    params: List[ast.arg] = []
    defaults: Dict[str, ast.AST] = {}
    for item in node.body:
        if not (isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name)):
            continue
        root = item.annotation.value if isinstance(item.annotation, ast.Subscript) else item.annotation
        if _attr_chain(root).rsplit(".", 1)[-1] == "ClassVar":
            continue
        value = item.value
        if isinstance(value, ast.Call) and _attr_chain(value.func).rsplit(".", 1)[-1] == "field":
            keywords = {kw.arg: kw.value for kw in value.keywords}
            init = keywords.get("init")
            if isinstance(init, ast.Constant) and init.value is False:
                continue
            value = keywords.get("default") or keywords.get("default_factory")
        params.append(ast.arg(arg=item.target.id, annotation=item.annotation))
        if value is not None:
            defaults[item.target.id] = value
    return params, defaults


def _base_node(base: ast.AST) -> ast.AST:
    """The class behind a generic base: ModalScreen[bool] is ModalScreen."""
    return base.value if isinstance(base, ast.Subscript) else base


def _ui_bindings(stmts: Sequence[ast.stmt]) -> Dict[str, str]:
    """Module names that come from a UI framework: from textual.screen import Screen, import tkinter as tk."""
    found: Dict[str, str] = {}
    for node in stmts:
        if isinstance(node, ast.ImportFrom) and not node.level and node.module:
            framework = _UI_FRAMEWORKS.get(node.module.split(".", 1)[0])
            found.update({a.asname or a.name: framework for a in node.names if framework})
        elif isinstance(node, ast.Import):
            for alias in node.names:
                framework = _UI_FRAMEWORKS.get(alias.name.split(".", 1)[0])
                if framework:
                    found[alias.asname or alias.name.split(".", 1)[0]] = framework
        elif isinstance(node, (ast.If, ast.Try)):
            nested = [*node.body, *node.orelse, *[s for h in getattr(node, "handlers", []) for s in h.body]]
            found.update(_ui_bindings(nested))
    return found


def _class_model(node: ast.ClassDef) -> ClassModel:
    bases = [_attr_chain(_base_node(b)).rsplit(".", 1)[-1] for b in node.bases if _attr_chain(_base_node(b))]
    methods = {item.name: item for item in node.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))}
    kinds = {name: method_kind(fn) for name, fn in methods.items()}
    init = methods.get("__init__")
    params: List[ast.arg] = []
    defaults: Dict[str, ast.AST] = {}
    kwonly: List[str] = []
    if init is not None:
        args = init.args
        positional = [*args.posonlyargs, *args.args][1:]
        offset = len(positional) - len(args.defaults)
        params = positional + list(args.kwonlyargs)
        defaults = {a.arg: d for a, d in zip(positional[max(offset, 0):], args.defaults[max(-offset, 0):])}
        defaults.update({a.arg: d for a, d in zip(args.kwonlyargs, args.kw_defaults) if d is not None})
        kwonly = [a.arg for a in args.kwonlyargs]
    elif _is_dataclass(node) or "NamedTuple" in bases:
        params, defaults = _field_params(node)
    abstract = frozenset(name for name, kind in kinds.items() if kind == "abstract")
    return ClassModel(node.name, bases, init, params, defaults, kwonly, bool(set(bases) & _ENUM_BASES),
                      "Protocol" in bases, abstract, kinds)


def _root_name(annotation: ast.AST) -> str:
    return _attr_chain(annotation).rsplit(".", 1)[-1]


def annotation_sample(annotation: Optional[ast.AST], ctx: SampleContext, depth: int = 0) -> Optional[Sample]:
    """Sample value for an annotation, or None when no value of that type can be built."""
    if annotation is None or depth > 4:
        return None
    if isinstance(annotation, ast.Constant):
        if annotation.value is None:
            return Sample("None", "none", False)
        if isinstance(annotation.value, str):
            try:
                return annotation_sample(ast.parse(annotation.value, mode="eval").body, ctx, depth + 1)
            except SyntaxError:
                return None
        return None
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        return _first_branch([annotation.left, annotation.right], ctx, depth)
    if isinstance(annotation, ast.Subscript):
        return _subscript_sample(annotation, ctx, depth)
    name = _root_name(annotation)
    return _named_sample(name, ctx, depth) if name else None


def _first_branch(branches: Sequence[ast.AST], ctx: SampleContext, depth: int) -> Optional[Sample]:
    """Union or X | Y: the first member type that can be built, trying None last."""
    ordered = sorted(branches, key=lambda b: isinstance(b, ast.Constant) and b.value is None)
    for branch in ordered:
        sample = annotation_sample(branch, ctx, depth + 1)
        if sample is not None:
            return sample
    return None


def _element_sample(annotation: ast.AST, ctx: SampleContext, depth: int) -> Optional[Sample]:
    """Element of a container. Any or object as the element type accepts any value."""
    if _root_name(annotation) in _ANY_TYPES:
        return Sample('"sample"', "str", False)
    return annotation_sample(annotation, ctx, depth + 1)


def _container_sample(kind: str, args: Sequence[ast.AST], ctx: SampleContext, depth: int) -> Optional[Sample]:
    """
    A container holding one element of the given type. When the element cannot be built, an empty
    list, set or dict is still valid; a fixed-arity tuple is not.
    """
    items = [_element_sample(a, ctx, depth) for a in args if not isinstance(a, ast.Constant)]
    if not items or any(item is None for item in items):
        return None if kind == "tuple" and items else Sample(KIND_SAMPLES[kind], kind, False)
    exprs = [item.expr for item in items if item is not None]
    if kind == "dict" and len(exprs) == 2:
        pair = f"{exprs[0]}: {exprs[1]}"
        return Sample(f"{{{pair}}}", kind, False, pair)
    if kind == "list":
        return Sample(f"[{exprs[0]}]", kind, False, exprs[0])
    if kind == "set":
        return Sample(f"{{{exprs[0]}}}", kind, False, exprs[0])
    if kind == "tuple":
        return Sample(f"({', '.join(exprs)},)", kind, False)
    return Sample(KIND_SAMPLES[kind], kind, False)


def _subscript_sample(annotation: ast.Subscript, ctx: SampleContext, depth: int) -> Optional[Sample]:
    root = _root_name(annotation.value)
    args = list(annotation.slice.elts) if isinstance(annotation.slice, ast.Tuple) else [annotation.slice]
    if root in _TRANSPARENT and args:
        return annotation_sample(args[0], ctx, depth + 1)
    if root == "Union":
        return _first_branch(args, ctx, depth)
    if root == "Literal" and args and isinstance(args[0], ast.Constant):
        value = args[0].value
        return Sample(repr(value), _BUILTIN_TYPES.get(type(value).__name__, "str"), False)
    if root in ("Type", "type") and args:
        name = _root_name(args[0])
        if name in _BUILTIN_TYPES:
            return Sample(name, "callable", False)
        found = ctx.lookup(name)
        if found is not None and found[0].require(found[1].name):
            return Sample(found[1].name, "callable", False)
        return None
    if root == "Iterator":
        return Sample("iter([])", "list", False)
    kind = _BUILTIN_TYPES.get(root) or _GENERIC_TYPES.get(root)
    if kind in ("list", "dict", "set", "tuple"):
        return _container_sample(kind, args, ctx, depth)
    return Sample(KIND_SAMPLES[kind], kind, False) if kind else None


def _named_sample(name: str, ctx: SampleContext, depth: int) -> Optional[Sample]:
    kind = _BUILTIN_TYPES.get(name) or _GENERIC_TYPES.get(name)
    if kind:
        return Sample(KIND_SAMPLES[kind], kind, False)
    if name in _STDLIB_TYPES:
        module, expr = _STDLIB_TYPES[name]
        ctx.used_modules.add(module)
        return Sample(expr, "object", False)
    if ctx.lookup(name) is not None:
        constructed = construct_expr(name, ctx, depth + 1)
        return Sample(constructed, "object", False) if constructed else None
    if name in ctx.aliases:
        return annotation_sample(ctx.aliases[name], ctx, depth + 1)
    return None


def construct_expr(class_name: str, ctx: SampleContext, depth: int = 0) -> Optional[str]:
    """
    Expression that creates an instance of a class from this module or another project module, or
    None when that is not possible (abstract, unknown parameter types, a clashing name). The
    parameters of a class from another module are resolved in that module's context.
    """
    found = ctx.lookup(class_name)
    if found is None or found[1].abstract or depth > 4:
        return None
    owner, model = found
    if model.enum:
        return f"list({model.name})[0]" if owner.require(model.name) else None
    votes = usage_kinds(model.init) if model.init is not None else {}
    args: List[str] = []
    for param in model.params:
        if param.arg in model.defaults:
            continue
        sample = param_sample(param, owner, votes.get(param.arg, set()), depth=depth + 1)
        if sample is None:
            return None
        args.append(f"{param.arg}={sample.expr}" if param.arg in model.kwonly else sample.expr)
    return f"{model.name}({', '.join(args)})" if owner.require(model.name) else None


# --- How the body uses each parameter ------------------------------------------------------------

_STR_METHODS = frozenset({
    "lower", "upper", "strip", "lstrip", "rstrip", "split", "rsplit", "splitlines", "startswith",
    "endswith", "replace", "find", "rfind", "encode", "isdigit", "isalpha", "isalnum", "isspace",
    "zfill", "center", "ljust", "rjust", "casefold", "title", "capitalize", "partition", "rpartition",
    "expandtabs", "removeprefix", "removesuffix", "format", "islower", "isupper",
})
_METHOD_KINDS = (
    (_STR_METHODS, "str"),
    (frozenset({"items", "keys", "values", "get", "setdefault", "popitem"}), "dict"),
    (frozenset({"append", "extend", "insert", "remove", "sort", "reverse"}), "list"),
    (frozenset({"add", "discard", "union", "intersection", "difference", "issubset", "issuperset"}), "set"),
    (frozenset({"decode"}), "bytes"),
)
_ITERATING_BUILTINS = frozenset({"len", "sorted", "list", "tuple", "set", "frozenset", "sum", "min", "max",
                                 "any", "all", "enumerate", "zip", "reversed", "iter", "dict"})
_NUMERIC_OPS = (ast.Sub, ast.Div, ast.FloorDiv, ast.Pow, ast.LShift, ast.RShift, ast.BitAnd, ast.BitXor)
_ORDERING = (ast.Lt, ast.LtE, ast.Gt, ast.GtE)


def _constant_kind(node: ast.AST) -> Optional[str]:
    """Value kind of a literal, or of a tuple or list of literals of the same kind."""
    if isinstance(node, ast.Constant) and not isinstance(node.value, bool) and node.value is not None:
        return {"int": "number", "float": "number", "str": "str", "bytes": "bytes"}.get(type(node.value).__name__)
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)) and node.elts:
        kinds = {_constant_kind(e) for e in node.elts}
        return kinds.pop() if len(kinds) == 1 else None
    return None


def _vote(votes: Dict[str, Set[str]], node: ast.AST, kind: Optional[str]) -> None:
    name = _name_of(node)
    if name is not None and name in votes and kind:
        votes[name].add(kind)


def _votes_from_call(node: ast.Call, votes: Dict[str, Set[str]]) -> None:
    func = node.func
    _vote(votes, func, "callable")
    if isinstance(func, ast.Name) and func.id in _ITERATING_BUILTINS and node.args:
        _vote(votes, node.args[0], "iterable")
    if isinstance(func, ast.Attribute):
        for methods, kind in _METHOD_KINDS:
            if func.attr in methods:
                _vote(votes, func.value, kind)
        if func.attr == "join" and node.args:
            _vote(votes, node.args[0], "iterable")


def _votes_from_compare(node: ast.Compare, votes: Dict[str, Set[str]]) -> None:
    operands = [node.left, *node.comparators]
    for op, left, right in zip(node.ops, operands, operands[1:]):
        if isinstance(op, (ast.In, ast.NotIn)):
            _vote(votes, right, "iterable")
            _vote(votes, left, _constant_kind(right))
        elif isinstance(op, _ORDERING + (ast.Eq, ast.NotEq)):
            _vote(votes, left, _constant_kind(right))
            _vote(votes, right, _constant_kind(left))


def _votes_from_binop(node: ast.BinOp, votes: Dict[str, Set[str]]) -> None:
    for this, other in ((node.left, node.right), (node.right, node.left)):
        if isinstance(node.op, _NUMERIC_OPS) or _constant_kind(other) == "number":
            _vote(votes, this, "number")
        elif _constant_kind(other) == "str" and isinstance(node.op, ast.Add):
            _vote(votes, this, "str")


def usage_kinds(func: FuncNode) -> Dict[str, Set[str]]:
    """
    Value kinds suggested by how the body uses each parameter: iterable, indexed (subscripted with
    an integer), str, dict, list, set, bytes, number or callable.
    """
    args = func.args
    votes: Dict[str, Set[str]] = {a.arg: set() for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]}
    for node in body_nodes(func):
        if isinstance(node, ast.Call):
            _votes_from_call(node, votes)
        elif isinstance(node, ast.Compare):
            _votes_from_compare(node, votes)
        elif isinstance(node, ast.BinOp):
            _votes_from_binop(node, votes)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            _vote(votes, node.iter, "iterable")
        elif isinstance(node, ast.AugAssign):
            _vote(votes, node.target, _constant_kind(node.value))
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            _vote(votes, node.operand, "number")
        elif isinstance(node, ast.Subscript):
            _vote(votes, node.value, "dict" if _constant_kind(node.slice) == "str" else "indexed")
    return votes


def _usage_sample(votes: Set[str]) -> Optional[Tuple[str, str]]:
    """(value kind, sample) compatible with every usage, or None when there are no hints or they conflict."""
    for kind in ("dict", "str", "bytes", "list", "set", "callable"):
        if kind in votes and votes <= {kind, "iterable", "indexed"}:
            return kind, KIND_SAMPLES[kind]
    if votes and votes <= {"iterable", "indexed"}:
        # Indexing needs at least one element; when it is only iterated, an empty list is safest.
        return "list", "[1, 2, 3]" if "indexed" in votes else "[]"
    if votes == {"number"}:
        return "number", "1"
    return None


def _fits(expr: str, kind: str) -> bool:
    """True when expr (a literal) is of value kind kind."""
    try:
        value = ast.literal_eval(expr)
    except (ValueError, SyntaxError):
        return False
    if isinstance(value, bool):
        return kind == "bool"
    if kind == "int":
        return isinstance(value, int)
    if kind in ("float", "number"):
        return isinstance(value, (int, float))
    return type(value).__name__ == kind


def param_sample(param: ast.arg, ctx: SampleContext, votes: Set[str], *, depth: int = 0) -> Optional[Sample]:
    """
    Sample value for a required parameter. None when it is annotated with a type that cannot be
    built: the test must not call the function with a made-up value of another type.
    """
    by_name = sample_for_arg(param.arg)
    known_name = param.arg.lower() in SAMPLE_BY_NAME
    if param.annotation is not None and _root_name(param.annotation) not in _ANY_TYPES:
        typed = annotation_sample(param.annotation, ctx, depth)
        if typed is None:
            return None
        if typed.kind in ("int", "float", "number", "str", "bytes") and _fits(by_name, typed.kind):
            return Sample(by_name, typed.kind, False)
        return typed
    usage = _usage_sample(votes)
    if usage is None:
        return Sample(by_name, "number" if _fits(by_name, "number") else "str", True)
    kind, expr = usage
    if _fits(by_name, kind):
        return Sample(by_name, kind, not known_name)
    return Sample(expr, kind, True)


def boundary_values(sample: Sample, name: str) -> List[Tuple[str, str]]:
    """
    Boundary values for the first parameter according to its value kind; empty when varying it
    makes no sense. A typed container is tried empty, with one element and with two, always of
    its element type.
    """
    if sample.kind not in _BOUNDARY_KINDS:
        return []
    if sample.item is not None and sample.kind == "list":
        return [("empty_list", "[]"), ("single_elem", f"[{sample.item}]"),
                ("two_elems", f"[{sample.item}, {sample.item}]")]
    if sample.item is not None and sample.kind == "dict":
        return [("empty_dict", "{}"), ("single_kv", f"{{{sample.item}}}")]
    if sample.kind == "bool":
        return [("false", "False"), ("true", "True")]
    if sample.kind == "bytes":
        return [("empty_bytes", 'b""'), ("null_byte", 'b"\\x00"'), ("giant_bytes", 'b"A" * 2048')]
    annotation = {"str": "str", "list": "list", "dict": "dict"}.get(sample.kind)
    return boundary_samples_for_param(name, annotation, sample.expr)


# --- Call plan ---------------------------------------------------------------------------------

class CallPlan(NamedTuple):
    """
    How to call a target. positional and names are the positional arguments and their parameter
    names; keywords, the keyword-only ones (name=value). static_names and static_values are the
    parameters and values used to evaluate the body statically (including those left at a literal
    default). assumed lists parameters with an assumed value; missing, those that cannot be built.
    first is the first required positional parameter: the one boundary and None-input tests vary.
    """

    positional: List[str]
    names: List[str]
    keywords: List[str]
    static_names: List[str]
    static_values: List[str]
    assumed: List[str]
    missing: List[str]
    first: Optional[Tuple[ast.arg, Sample]]

    @property
    def arg_str(self) -> str:
        """The call's arguments, as written between the parentheses."""
        return ", ".join([*self.positional, *self.keywords])

    def with_first(self, expr: str) -> str:
        """The arguments with the first positional one replaced by expr."""
        return ", ".join([expr, *self.positional[1:], *self.keywords])


def _literal_default(node: ast.AST) -> Optional[str]:
    try:
        ast.literal_eval(node)
    except (ValueError, SyntaxError, TypeError):
        return None
    return ast.unparse(node)


def function_params(func: FuncNode, skip_first: bool) -> Tuple[List[ast.arg], Dict[str, ast.AST], Set[str]]:
    """(parameters excluding *args and **kwargs, their default values, the keyword-only ones)."""
    args = func.args
    positional = [*args.posonlyargs, *args.args]
    if skip_first and positional:
        positional = positional[1:]
    offset = len(positional) - len(args.defaults)
    defaults: Dict[str, ast.AST] = {a.arg: d for a, d in zip(positional[max(offset, 0):], args.defaults[max(-offset, 0):])}
    defaults.update({a.arg: d for a, d in zip(args.kwonlyargs, args.kw_defaults) if d is not None})
    return [*positional, *args.kwonlyargs], defaults, {a.arg for a in args.kwonlyargs}


def plan_call(func: Optional[FuncNode], ctx: SampleContext, *, skip_first: bool = False) -> CallPlan:
    """Call plan for a function; skip_first drops self or cls for methods."""
    plan = CallPlan([], [], [], [], [], [], [], None)
    if func is None:
        return plan
    params, defaults, kwonly = function_params(func, skip_first)
    votes = usage_kinds(func)
    for param in params:
        name = param.arg
        if name in defaults:
            literal = _literal_default(defaults[name])
            if literal is not None:
                plan.static_names.append(name)
                plan.static_values.append(literal)
            continue
        sample = param_sample(param, ctx, votes.get(name, set()))
        if sample is None:
            plan.missing.append(f"{name} ({ast.unparse(param.annotation) if param.annotation else 'untyped'})")
            continue
        if sample.assumed:
            plan.assumed.append(name)
        plan.static_names.append(name)
        plan.static_values.append(sample.expr)
        if name in kwonly:
            plan.keywords.append(f"{name}={sample.expr}")
            continue
        plan.positional.append(sample.expr)
        plan.names.append(name)
        if plan.first is None:
            plan = plan._replace(first=(param, sample))
    return plan


# --- The object a method is called on ----------------------------------------------------------

class Receiver(NamedTuple):
    """
    How to reach a method: target is what gets called (obj.m or Class.m) and setup, the
    expression that creates obj. assumed means it is built from assumed values or with a
    constructor inherited from outside the module; skip, why it cannot be tested (abstract, a
    constructor that cannot be completed). kind is the method kind: method, static, class or property.
    """

    target: str
    setup: Optional[str]
    assumed: bool
    skip: Optional[str]
    kind: str


def _construction_assumed(model: ClassModel, ctx: SampleContext) -> bool:
    if model.enum:
        return False
    if model.init is None and not model.params:
        return any(base not in ctx.classes and base not in ("object", "Exception") for base in model.bases)
    votes = usage_kinds(model.init) if model.init is not None else {}
    for param in model.params:
        if param.arg not in model.defaults:
            sample = param_sample(param, ctx, votes.get(param.arg, set()))
            if sample is not None and sample.assumed:
                return True
    return False


def receiver_for(class_name: str, method: str, ctx: SampleContext) -> Receiver:
    """How to reach the method: on the class for static and class methods, otherwise on a freshly built object."""
    model = ctx.classes[class_name]
    kind = model.method_kinds.get(method, "method")
    if model.ui:
        reason = (f"It is a {model.ui} UI component: it needs the application running. "
                  "Test it with the framework's own tools (in Textual, App.run_test()).")
        return Receiver(f"obj.{method}", None, False, reason, kind)
    if kind in ("static", "class"):
        ctx.used_names.add(class_name)
        return Receiver(f"{class_name}.{method}", None, False, None, kind)
    expr, skip = instantiation_for(class_name, ctx)
    if expr is None:
        return Receiver(f"obj.{method}", None, False, skip, kind)
    return Receiver(f"obj.{method}", expr, _construction_assumed(model, ctx), None, kind)


def instantiation_for(class_name: str, ctx: SampleContext) -> Tuple[Optional[str], Optional[str]]:
    """(expression that creates the instance, reason not to test it)."""
    model = ctx.classes[class_name]
    if model.abstract:
        return None, f"{class_name} is abstract: it cannot be instantiated."
    expr = construct_expr(class_name, ctx)
    if expr is None:
        return None, f"Cannot work out how to construct {class_name}: fill it in by hand with valid values."
    return expr, None


def construction_assumed(class_name: str, ctx: SampleContext) -> bool:
    """True when the class is built from assumed values or with a constructor that is not known."""
    return _construction_assumed(ctx.classes[class_name], ctx)


# --- Importing the analysed module --------------------------------------------------------------

def _from_import(module: str, names: Set[str]) -> str:
    """A `from module import ...` line, wrapped in parentheses when it would be too long."""
    statement = f"from {module} import {', '.join(sorted(names))}  # noqa: E402"
    if len(statement) > 110:
        body = "".join(f"    {n},\n" for n in sorted(names))
        statement = f"from {module} import (  # noqa: E402\n{body})"
    return statement


def import_header(source_filepath: str, output_test_filepath: str, names: Set[str], modules: Set[str],
                  foreign: Optional[Dict[str, Set[str]]] = None) -> List[str]:
    """
    Lines that import the analysed module from the suite. Its root, relative to the suite, is put
    on sys.path, and targets are imported by name (import * would miss whatever __all__ excludes).
    foreign maps other project modules to the classes the suite needs from them.
    """
    dotted, root = module_import(source_filepath)
    rel = os.path.relpath(root, os.path.dirname(os.path.abspath(output_test_filepath))).replace(os.sep, "/")
    lines = [
        "import os",
        "import sys",
        *(f"import {m}" for m in sorted(modules)),
        "",
        f"# Root that {dotted} is imported from, relative to this file.",
        f'_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "{rel}"))',
        "if _ROOT not in sys.path:",
        "    sys.path.insert(0, _ROOT)",
        "",
    ]
    lines.append(_from_import(dotted, names) if names else f"import {dotted}  # noqa: E402,F401")
    lines.extend(_from_import(module, extra) for module, extra in sorted((foreign or {}).items()) if extra)
    return lines
