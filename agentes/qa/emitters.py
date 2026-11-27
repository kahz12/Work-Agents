"""
Emitters for unittest suites and adversarial pytest suites.

Each target (function, method or property) is described by a TargetSpec built from call_plan's
call plan: which arguments to pass, how to create a method's object, which values are assumed
and what cannot be built. The emitters only write the tests; every decision is made upstream.
"""
from __future__ import annotations

import ast
import os
import re
from typing import Any, Dict, List, NamedTuple, Optional, Set, Tuple

from .ast_inspector import NON_DET_CALLS, UnitTestGenerator, _regex_literal, accepts_none, validating_raises
from .call_plan import (
    KIND_SAMPLES,
    CallPlan,
    SampleContext,
    boundary_values,
    construction_assumed,
    import_header,
    instantiation_for,
    module_import,
    plan_call,
    receiver_for,
)
from .expected_values import Outcome, fallback_assertion, is_pure_binop, static_outcome, uses_nondeterminism
from .sample_values import first_invalid_argument

SOURCE_COMMENT = {
    "static": "Value computed from the function body.",
    "recorded": "Value recorded when the suite was generated: pins the current behaviour (characterisation test).",
}
RAISES_COMMENT = {
    "static": "exception derived from the function body for these values.",
    "recorded": "exception recorded when the suite was generated (characterisation test).",
}
RECORDED_HEADER = [
    "# Values marked as recorded were obtained by running the code when the suite was generated.",
    "# They pin down the current behaviour: if there is a bug today, the test accepts it. Review them.",
]
# What Python raises when an assumed sample value is not of the type the function expects.
_MISFIT = "(TypeError, AttributeError)"
# What it raises when it processes the data of an I/O double (a MagicMock, an empty file) as if
# it were real: json.loads(MagicMock) raises TypeError; json.load on an empty file, ValueError.
_FAKE_IO_MISFIT = "(TypeError, AttributeError, ValueError)"


class TargetSpec(NamedTuple):
    """
    A test target. name identifies it in the test name (func or Class_method); call_target is
    what gets called (func, obj.method or Class.method); setup, the expression that creates obj,
    and setup_assumed, whether it is built from assumed values; skip, why it cannot be tested;
    access, "call" or "property" (read, not called).
    """

    name: str
    call_target: str
    label: str
    meta: Dict[str, Any]
    func_node: Optional[ast.AST]
    plan: CallPlan
    setup: Optional[str]
    setup_assumed: bool
    skip: Optional[str]
    access: str
    ctx: SampleContext

    @property
    def is_async(self) -> bool:
        """The target is a coroutine function, so it is called through asyncio.run."""
        return bool(self.meta.get("is_async"))

    def call(self, args: Optional[str] = None) -> str:
        """Expression that invokes the target (with args, or the plan's); coroutines go through asyncio.run."""
        if self.access == "property":
            return self.call_target
        expr = f"{self.call_target}({self.plan.arg_str if args is None else args})"
        return f"asyncio.run({expr})" if self.is_async else expr


_CLI_REASON = "It reads sys.argv or ends the process: test it through its command line (subprocess or CliRunner)."
_ENDLESS_REASON = ("It enters an endless loop (while True with no break, return or raise): test it with a "
                   "stop event or an iteration limit.")


def _skip_reason(plan: CallPlan, meta: Dict[str, Any]) -> Optional[str]:
    """Why the target cannot be called from a unit test; None when it can."""
    if meta.get("cli_entrypoint"):
        return _CLI_REASON
    if meta.get("endless_loop"):
        return _ENDLESS_REASON
    if not plan.missing:
        return None
    return f"No sample value for {', '.join(plan.missing)}: fill it in by hand."


def build_targets(visitor: UnitTestGenerator, ctx: SampleContext) -> List[TargetSpec]:
    """One TargetSpec per public function and per public method or property of each public class."""
    specs: List[TargetSpec] = []
    for func_name, _, _ in visitor.functions:
        snapshot = ctx.snapshot()
        node = visitor.function_nodes.get(func_name)
        plan = plan_call(node, ctx)
        meta = visitor.function_meta.get(func_name, {})
        ctx.used_names.add(func_name)
        specs.append(TargetSpec(func_name, func_name, func_name, meta, node, plan, None, False,
                                _skip_reason(plan, meta), "call", ctx))
        _forget_if_skipped(specs[-1], ctx, snapshot)
    for cls_name, _, methods in visitor.classes:
        for m_name, _, _ in methods:
            snapshot = ctx.snapshot()
            key = f"{cls_name}.{m_name}"
            node = visitor.function_nodes.get(key)
            receiver = receiver_for(cls_name, m_name, ctx)
            plan = plan_call(node, ctx, skip_first=receiver.kind != "static")
            meta = visitor.function_meta.get(key, {})
            specs.append(TargetSpec(
                f"{cls_name}_{m_name}", receiver.target, key, meta, node, plan,
                receiver.setup, receiver.assumed, receiver.skip or _skip_reason(plan, meta),
                "property" if receiver.kind == "property" else "call", ctx,
            ))
            _forget_if_skipped(specs[-1], ctx, snapshot)
    return specs


def _forget_if_skipped(spec: TargetSpec, ctx: SampleContext,
                       snapshot: Tuple[Set[str], Set[str], Dict[str, Set[str]]]) -> None:
    """A skipped target uses nothing from the module, so whatever its planning recorded is not imported."""
    if spec.skip:
        ctx.restore(snapshot)


def io_targets(io_calls: List[str]) -> List[str]:
    """Patch targets for every detected I/O call, without duplicates."""
    targets: List[str] = []
    for target in io_calls:
        if target and target not in targets:
            targets.append(target)
    return targets


def absorb_blocked(outcome: Optional[Outcome], targets: List[str]) -> Tuple[Optional[Outcome], List[str]]:
    """
    While recording, the function tried to write, delete, start a process or connect (perhaps
    through another module) and was blocked. There is no reliable value to assert, but the test
    must still patch those calls so it never performs them for real.
    """
    if outcome is None or outcome[0] != "blocked":
        return outcome, targets
    extra = [t for t in outcome[1].split(",") if t and t not in targets]
    return None, targets + extra


# Doubles for open(): a MagicMock would return another MagicMock from read(), and code reading
# the file (a parser, a read() loop) would never finish. An empty file is simulated instead.
_OPEN_TARGETS = frozenset({"builtins.open", "io.open"})


def patch_clause(targets: List[str], *, named: bool = False) -> str:
    """
    Build the patch(...) clause for the I/O doubles: autospec, or an empty file for open(). With
    named, each double is bound to io_0, io_1... for tests that check whether it was called.
    """
    return ", ".join(
        (f'patch("{t}", new=mock_open(read_data=""))' if t in _OPEN_TARGETS else f'patch("{t}", autospec=True)')
        + (f" as io_{i}" if named else "")
        for i, t in enumerate(targets)
    )


def _uses_open_double(specs: List["TargetSpec"]) -> bool:
    return any(set(spec.meta.get("io_calls") or []) & _OPEN_TARGETS for spec in specs if not spec.skip)


def declared_raises(spec: TargetSpec, *, reachable: bool = False) -> List[Tuple[str, Optional[str]]]:
    """
    The exceptions the target raises that the suite can name, with their messages; with
    reachable, also those of the module helpers it calls. Exceptions defined or imported by the
    module are recorded so the suite imports them.
    """
    raises = spec.meta.get("raises_reachable" if reachable else "raises") or spec.meta.get("raises") or []
    found = [(name, msg) for name, msg in raises if spec.ctx.exception_import(name) is not None]
    for name, _ in found:
        spec.ctx.use_exception(name)
    return found


class Rejection(NamedTuple):
    """
    An invalid-input test: the argument at position receives value and the function must raise
    exceptions (a name or a tuple), with a message matching pattern when it is known.
    """

    position: int
    value: str
    exceptions: str
    pattern: Optional[str]


def expected_rejection(spec: TargetSpec) -> Optional[Rejection]:
    """
    The invalid-input test, only when the function validates the parameter that receives the
    hostile value (a raise under an if that mentions it, or an assert on it). Without that
    validation, demanding an exception would fail the test against a correct function:
    walk_files("../../etc/passwd") walks a relative path without complaint, as it should.
    """
    invalid = first_invalid_argument(spec.plan.names)
    if invalid is None or spec.access == "property":
        return None
    index, value = invalid
    raises = [(name, msg) for name, msg in validating_raises(spec.func_node, spec.plan.names[index])
              if spec.ctx.exception_import(name) is not None]
    if not raises:
        return None
    names = list(dict.fromkeys(name for name, _ in raises))
    for name in names:
        spec.ctx.use_exception(name)
    # Only use a pattern when every message is known and none is empty: any of them may be the one raised.
    messages = list(dict.fromkeys(msg for _, msg in raises if msg))
    pattern = None
    if len(messages) == 1 and all(msg for _, msg in raises):
        pattern = _regex_literal(messages[0])
    elif messages and all(msg for _, msg in raises):
        pattern = repr("|".join(re.escape(m) for m in messages))
    return Rejection(index, value, names[0] if len(names) == 1 else f"({', '.join(names)})", pattern)


def fallback_kind(spec: TargetSpec) -> Tuple[str, str]:
    """
    What can be asserted about the value without knowing it (fallback_assertion). When one of the
    arguments is the sample callable, which returns None, the target may return whatever it
    returns (interruptible(call) returns call()), so neither the annotated type nor "not None"
    is safe any more.
    """
    kind, type_name = fallback_assertion(spec.func_node)  # type: ignore[arg-type]
    callable_sample = KIND_SAMPLES["callable"]
    if kind in ("isinstance", "not_none") and any(callable_sample in arg for arg in [*spec.plan.positional,
                                                                                      *spec.plan.keywords]):
        return "none", ""
    return kind, type_name


def io_assertion(spec: TargetSpec) -> str:
    """
    What can be asserted about a target with its I/O patched and no known value: "called" when it
    performs the I/O in every execution that accepts its input (the test checks it delegates to
    the doubles), "none" when it never returns anything, and "" when nothing is safe (the I/O sits
    in a branch, or the value depends on the doubles).
    """
    if spec.meta.get("io_always"):
        return "called"
    if fallback_kind(spec)[0] == "is_none":
        return "none"
    return ""


def io_called_expr(targets: List[str]) -> str:
    """Boolean expression that checks whether any of the I/O doubles was called."""
    return " or ".join(f"io_{i}.called" for i in range(len(targets)))


def recording_calls(visitor: UnitTestGenerator) -> Dict[str, str]:
    """Expressions to record: functions and methods with no I/O and no non-deterministic results."""
    calls: Dict[str, str] = {}
    for spec in build_targets(visitor, SampleContext(visitor.tree, visitor.project)):
        if spec.skip or spec.meta.get("io_calls") or uses_nondeterminism(spec.func_node, NON_DET_CALLS):  # type: ignore[arg-type]
            continue
        target = spec.call_target
        if spec.setup and target.startswith("obj."):
            target = f"({spec.setup}).{target[4:]}"
        calls[spec.name] = target if spec.access == "property" else f"{target}({spec.plan.arg_str})"
    return calls


def outcome_for(
    key: str,
    func_node: Optional[ast.AST],
    kept_args: List[str],
    samples: List[str],
    recorded: Optional[Dict[str, Outcome]],
) -> Tuple[Optional[Outcome], str]:
    """Expected outcome, taken from the recording first and from static evaluation otherwise."""
    if recorded and key in recorded:
        return recorded[key], "recorded"
    outcome = static_outcome(func_node, kept_args, samples)  # type: ignore[arg-type]
    return (outcome, "static") if outcome else (None, "")


def _spec_outcome(spec: TargetSpec, recorded: Optional[Dict[str, Outcome]]) -> Tuple[Optional[Outcome], str]:
    """
    Expected outcome for the target. With assumed values, a TypeError or AttributeError only
    shows that the assumption does not fit the function, not how it behaves, so it is not asserted.
    """
    if spec.access == "property":
        outcome, source = (recorded[spec.name], "recorded") if recorded and spec.name in recorded else (None, "")
    else:
        outcome, source = outcome_for(spec.name, spec.func_node, spec.plan.static_names, spec.plan.static_values,
                                      recorded)
    if outcome is None or outcome[0] != "raises":
        return outcome, source
    if (spec.plan.assumed or spec.setup_assumed) and outcome[1] in ("TypeError", "AttributeError"):
        return None, ""
    return (outcome, source) if spec.ctx.use_exception(outcome[1]) else (None, "")


def is_float_literal(text: str) -> bool:
    """True when the literal expression evaluates to a float."""
    try:
        return isinstance(ast.literal_eval(text), float)
    except (ValueError, SyntaxError):
        return False


# --- Building blocks shared by both emitters ----------------------------------------------------

# Suite isolation: a generated test never reaches the network or waits on standard input.
# Network calls the analysis cannot see (made by another module) fail with OSError, as they
# would offline, and anything reading standard input finds it empty. Local connections keep
# working, because asyncio on Windows uses them for its event loop.
_ISOLATION_HELPERS = [
    '_QA_LOCAL_HOSTS = (None, "localhost", "127.0.0.1", "::1")',
    "_qa_real_connect = socket.socket.connect",
    "_qa_real_getaddrinfo = socket.getaddrinfo",
    "",
    "",
    "def _qa_local_connect(sock, address):",
    '    """Local connections only: a generated test never reaches the network."""',
    "    host = address[0] if isinstance(address, tuple) else None",
    "    if host not in _QA_LOCAL_HOSTS:",
    '        raise OSError(f"Network blocked in generated tests: {address!r}")',
    "    return _qa_real_connect(sock, address)",
    "",
    "",
    "def _qa_local_getaddrinfo(host, *args, **kwargs):",
    '    """Local names only: without network access nothing else resolves."""',
    "    if host not in _QA_LOCAL_HOSTS:",
    '        raise socket.gaierror(f"Network blocked in generated tests: {host!r}")',
    "    return _qa_real_getaddrinfo(host, *args, **kwargs)",
    "",
    "",
    "def _qa_empty_stdin():",
    "    return io.TextIOWrapper(io.BytesIO())",
    "",
    "",
    "# Seconds each test may run; 0 removes the limit.",
    "_QA_TIMEOUT = 10",
    "",
    "",
    "class _QaTimeout(BaseException):",
    '    """The test kept running after being skipped: stop it with something except Exception cannot catch."""',
    "",
    "",
    "def _qa_time_limit(skip):",
    '    """',
    "    Arm the test's time limit and return the callable that disarms it. When it expires, skip",
    "    skips the test; if the code swallows that exception and carries on, _QaTimeout stops it two",
    "    seconds later. Without SIGALRM (Windows) or outside the main thread there is no limit.",
    '    """',
    '    if not _QA_TIMEOUT or not hasattr(signal, "SIGALRM") or threading.current_thread() is not threading.main_thread():',
    "        return lambda: None",
    "    fired = []",
    "",
    "    def _on_alarm(signum, frame):",
    "        fired.append(signum)",
    "        if len(fired) == 1:",
    '            skip(f"Did not finish within {_QA_TIMEOUT} s with the sample values: an endless loop, a wait "',
    '                 "or an interactive interface.")',
    '        raise _QaTimeout(f"Did not finish within {_QA_TIMEOUT} s and the code swallowed the skip.")',
    "",
    "    previous = signal.signal(signal.SIGALRM, _on_alarm)",
    "    signal.setitimer(signal.ITIMER_REAL, _QA_TIMEOUT, 2)",
    "",
    "    def disarm():",
    "        signal.setitimer(signal.ITIMER_REAL, 0)",
    "        signal.signal(signal.SIGALRM, previous)",
    "",
    "    return disarm",
]

def _setup_lines(spec: TargetSpec, ind: str, skip_call: str) -> List[str]:
    """The lines that create obj. When it is built from assumed values that do not fit, the test is skipped."""
    if not spec.setup:
        return []
    if not spec.setup_assumed:
        return [f"{ind}obj = {spec.setup}"]
    return [
        f"{ind}# The object is built from assumed values: if they do not fit the class, the test is skipped.",
        f"{ind}try:",
        f"{ind}    obj = {spec.setup}",
        f"{ind}except {_MISFIT} as exc:",
        f'{ind}    {skip_call}(f"Could not create the object from assumed values: {{exc}}")',
    ]


def _call_lines(spec: TargetSpec, ind: str, statement: str, skip_call: str, fake_io: bool = False) -> List[str]:
    """
    The statement that calls the target (result = f(...)). When it uses assumed values that do
    not fit the function, or (with fake_io) it chokes on the data the I/O doubles return, the test
    is skipped: that says nothing about how it behaves with real data.
    """
    if fake_io:
        return [
            f"{ind}# The I/O doubles return simulated data: if the function cannot process it, the test is skipped.",
            f"{ind}try:",
            f"{ind}    {statement}",
            f"{ind}except {_FAKE_IO_MISFIT} as exc:",
            f'{ind}    {skip_call}(f"The sample values or the simulated I/O data do not fit: {{exc}}")',
        ]
    if not spec.plan.assumed:
        return [f"{ind}{statement}"]
    names = ", ".join(spec.plan.assumed)
    return [
        f"{ind}# Assumed sample values for {names}: if they do not fit the function, the test is skipped.",
        f"{ind}try:",
        f"{ind}    {statement}",
        f"{ind}except {_MISFIT} as exc:",
        f'{ind}    {skip_call}(f"The assumed values for {names} do not fit the function: {{exc}}")',
    ]


def _with_doubles(targets: List[str]) -> str:
    """
    The I/O doubles as the first context managers of a with statement, or "" when there is no
    I/O. Every test that calls the target needs them; otherwise the call would do the I/O for real.
    """
    return f"{patch_clause(targets)}, " if targets else ""


def _with_arg(plan: CallPlan, index: int, expr: str) -> str:
    """The plan's arguments with the positional one at index replaced by expr."""
    positional = list(plan.positional)
    positional[index] = expr
    return ", ".join([*positional, *plan.keywords])


# ---------------------------------------------------------------------------
# unittest emitter
# ---------------------------------------------------------------------------

def _emit_unittest_fallback_assert(test_code: List[str], ind: str, spec: TargetSpec) -> None:
    kind, type_name = fallback_kind(spec)
    if kind == "isinstance":
        test_code.append(f"{ind}self.assertIsInstance(result, {type_name})")
    elif kind == "is_none":
        test_code.append(f"{ind}self.assertIsNone(result)")
    elif kind == "not_none":
        test_code.append(f"{ind}self.assertIsNotNone(result)")
        test_code.append(f"{ind}# Exact value unknown: pin it by hand or generate the suite with --record.")
    else:
        test_code.append(f"{ind}# Value unknown: this test only checks that no exception is raised.")
        test_code.append(f"{ind}# Pin it by hand or generate the suite with --record.")
        test_code.append(f"{ind}_ = result")


def _emit_unittest_result_asserts(
    test_code: List[str],
    ind: str,
    resolved: Tuple[Optional[Outcome], str, List[str], TargetSpec],
) -> None:
    outcome, source, targets, spec = resolved
    if outcome is not None and outcome[0] == "value":
        test_code.append(f"{ind}# {SOURCE_COMMENT[source]}")
        if outcome[1] == "None":
            test_code.append(f"{ind}self.assertIsNone(result)")
            return
        method = "assertAlmostEqual" if is_float_literal(outcome[1]) else "assertEqual"
        test_code.append(f"{ind}self.{method}(result, {outcome[1]})")
        return
    if outcome is not None and outcome[0] == "type":
        test_code.append(f"{ind}# {SOURCE_COMMENT[source]}")
        test_code.append(f'{ind}self.assertEqual(type(result).__name__, "{outcome[1]}")')
        return
    if targets:
        expected = io_assertion(spec)
        if expected == "called":
            test_code.append(f"{ind}self.assertTrue({io_called_expr(targets)}, \"does not use the patched I/O\")")
        elif expected == "none":
            test_code.append(f"{ind}self.assertIsNone(result)")
        else:
            test_code.append(f"{ind}# With the I/O patched the value depends on the doubles: not failing is enough.")
        return
    _emit_unittest_fallback_assert(test_code, ind, spec)


def _emit_unittest_skipped(test_code: List[str], name: str, label: str, reason: str) -> None:
    test_code.append(f"    def test_{name}_happy_path(self):")
    test_code.append(f'        """{label}: cannot be tested without completing it by hand."""')
    test_code.append(f"        self.skipTest({reason!r})")
    test_code.append("")


def _emit_unittest_happy_path(
    test_code: List[str],
    spec: TargetSpec,
    resolved: Tuple[Optional[Outcome], str, List[str]],
) -> None:
    outcome, source, targets = resolved
    raises_outcome = outcome is not None and outcome[0] == "raises"

    name = f"test_{spec.name}_sample_input_raises" if raises_outcome else f"test_{spec.name}_happy_path"
    test_code.append(f"    def {name}(self):")
    test_code.append(f'        """{spec.label} with sample values."""')
    test_code.append("        # Arrange")
    test_code.extend(_setup_lines(spec, "        ", "self.skipTest"))
    ind = "        "
    expected = io_assertion(spec) if targets and outcome is None else ""
    if targets:
        test_code.append(f"        # I/O replaced by test doubles: {', '.join(targets)}")
        test_code.append(f"        with {patch_clause(targets, named=expected == 'called')}:")
        ind = "            "
    if raises_outcome and outcome is not None:
        test_code.append(f"{ind}# Act & Assert: {RAISES_COMMENT[source]}")
        if outcome[2]:
            test_code.append(f"{ind}with self.assertRaisesRegex({outcome[1]}, {_regex_literal(outcome[2])}):")
        else:
            test_code.append(f"{ind}with self.assertRaises({outcome[1]}):")
        test_code.append(f"{ind}    {spec.call()}")
    else:
        test_code.append(f"{ind}# Act")
        fake_io = bool(targets) and outcome is None
        statement = f"result = {spec.call()}" if not fake_io or expected == "none" else spec.call()
        test_code.extend(_call_lines(spec, ind, statement, "self.skipTest", fake_io))
        test_code.append(f"{ind}# Assert")
        _emit_unittest_result_asserts(test_code, ind, (outcome, source, targets, spec))
    test_code.append("")


def _emit_unittest_invalid_input(test_code: List[str], spec: TargetSpec, targets: List[str]) -> None:
    rejection = expected_rejection(spec)
    if rejection is None:
        return
    test_code.append(f"    def test_{spec.name}_invalid_input(self):")
    test_code.append(f'        """Invalid input for {spec.label}: the function validates it and rejects it."""')
    test_code.append("        # Arrange")
    test_code.extend(_setup_lines(spec, "        ", "self.skipTest"))
    test_code.append("        # Act & Assert")
    doubles = _with_doubles(targets)
    if rejection.pattern:
        test_code.append(f"        with {doubles}self.assertRaisesRegex({rejection.exceptions}, {rejection.pattern}):")
    else:
        test_code.append(f"        with {doubles}self.assertRaises({rejection.exceptions}):")
    test_code.append(f"            {spec.call(_with_arg(spec.plan, rejection.position, rejection.value))}")
    test_code.append("")


def emit_unittest_call_tests(test_code: List[str], spec: TargetSpec, recorded: Optional[Dict[str, Outcome]] = None) -> None:
    """Emit the unittest test methods (happy path and invalid input) for one target."""
    if spec.skip:
        _emit_unittest_skipped(test_code, spec.name, spec.label, spec.skip)
        return
    outcome, source = _spec_outcome(spec, recorded)
    outcome, targets = absorb_blocked(outcome, io_targets(spec.meta.get("io_calls") or []))
    _emit_unittest_happy_path(test_code, spec, (outcome, source, targets))
    _emit_unittest_invalid_input(test_code, spec, targets)


def _emit_unittest_instantiation(test_code: List[str], cls_name: str, ctx: SampleContext) -> None:
    expr, skip = instantiation_for(cls_name, ctx)
    if expr is None:
        _emit_unittest_skipped(test_code, f"{cls_name}_instantiation", cls_name, skip or "")
        return
    test_code.append(f"    def test_{cls_name}_instantiation(self):")
    test_code.append(f'        """Basic instantiation of {cls_name}."""')
    if construction_assumed(cls_name, ctx):
        test_code.extend([
            "        try:",
            f"            obj = {expr}",
            f"        except {_MISFIT} as exc:",
            '            self.skipTest(f"Could not create the object from assumed values: {exc}")',
        ])
    else:
        test_code.append(f"        obj = {expr}")
    test_code.append(f"        self.assertIsInstance(obj, {cls_name})")
    test_code.append("")


def render_unittest_suite(
    source_filepath: str,
    output_test_filepath: str,
    visitor: UnitTestGenerator,
    recorded: Dict[str, Outcome],
) -> str:
    """Render the complete source of a unittest suite."""
    ctx = SampleContext(visitor.tree, visitor.project)
    specs = build_targets(visitor, ctx)
    dotted, _ = module_import(source_filepath)
    module_name = dotted.rsplit(".", 1)[-1]
    class_name = "".join(part.capitalize() for part in module_name.replace("-", "_").split("_"))
    body = [
        f"class Test{class_name}QA(unittest.TestCase):",
        "    def setUp(self):",
        '        """No network, empty standard input and a time limit: no test is left waiting."""',
        '        for target, new in (("socket.socket.connect", _qa_local_connect),',
        '                            ("socket.getaddrinfo", _qa_local_getaddrinfo), ("sys.stdin", _qa_empty_stdin())):',
        "            patcher = patch(target, new)",
        "            patcher.start()",
        "            self.addCleanup(patcher.stop)",
        "        self.addCleanup(_qa_time_limit(self.skipTest))",
        "",
        "    def tearDown(self):",
        "        pass",
        "",
    ]
    for spec in specs:
        emit_unittest_call_tests(body, spec, recorded=recorded)
    for cls_name, _, methods in visitor.classes:
        if not methods:
            _emit_unittest_instantiation(body, cls_name, ctx)
    if not visitor.functions and not visitor.classes:
        body.append("    def test_module_importable(self):")
        body.append('        """The module imports cleanly."""')
        body.append("        self.assertIsNotNone(True)")
        body.append("")
    body.append("if __name__ == '__main__':")
    body.append("    unittest.main()")

    header = ["import io", "import signal", "import socket", "import threading", "import unittest"]
    if any(spec.is_async for spec in specs if not spec.skip):
        header.append("import asyncio")
    header.append("from unittest.mock import mock_open, patch" if _uses_open_double(specs)
                  else "from unittest.mock import patch")
    if recorded:
        header.extend(RECORDED_HEADER)
    header.extend(import_header(source_filepath, output_test_filepath, ctx.used_names, ctx.used_modules,
                                ctx.foreign_imports))
    return "\n".join([*header, "", "", *_ISOLATION_HELPERS, "", "", *body])


# ---------------------------------------------------------------------------
# pytest emitter
# ---------------------------------------------------------------------------

class _PytestCase(NamedTuple):
    """What every pytest test of one target shares: its description, its expected outcome and its I/O."""

    spec: TargetSpec
    outcome: Optional[Outcome]
    source: str
    io_targets: List[str]

    @property
    def safe_id(self) -> str:
        """The target name as used inside a test identifier."""
        return self.spec.name.replace(".", "_")

    @property
    def func_node(self) -> Optional[ast.AST]:
        """The function or method node, for analysing its body."""
        return self.spec.func_node


def build_pytest_case(spec: TargetSpec, recorded: Optional[Dict[str, Outcome]]) -> _PytestCase:
    """Prepare the normalised case the pytest tests are emitted from."""
    outcome, source = _spec_outcome(spec, recorded)
    outcome, targets = absorb_blocked(outcome, io_targets(spec.meta.get("io_calls", [])))
    return _PytestCase(spec, outcome, source, targets)


def _value_assertion(value: str) -> str:
    if value in ("None", "True", "False"):
        return f"assert result is {value}"
    if is_float_literal(value):
        return f"assert result == pytest.approx({value})"
    return f"assert result == {value}"


def _fallback_assertion_line(spec: TargetSpec) -> str:
    kind, type_name = fallback_kind(spec)
    if kind == "isinstance":
        return f"assert isinstance(result, {type_name})"
    if kind == "is_none":
        return "assert result is None"
    if kind == "not_none":
        return "assert result is not None"
    return "_ = result  # no value assertion: this only checks that no exception is raised"


def _nominal_assertion(case: _PytestCase) -> List[str]:
    """Comment and assertion for the nominal case, from the most reliable source available."""
    outcome = case.outcome
    if outcome is not None and outcome[0] == "value":
        return [f"# Assert: {SOURCE_COMMENT[case.source]}", _value_assertion(outcome[1])]
    if outcome is not None and outcome[0] == "type":
        return [f"# Assert: {SOURCE_COMMENT[case.source]}", f'assert type(result).__name__ == "{outcome[1]}"']
    if case.io_targets:
        expected = io_assertion(case.spec)
        if expected == "called":
            return ["# Assert: the function delegates to the patched I/O", f"assert {io_called_expr(case.io_targets)}"]
        if expected == "none":
            return ["# Assert: the function returns nothing", "assert result is None"]
        return ["# Assert: with the I/O patched the value depends on the doubles; not failing is enough", "_ = result"]
    if case.spec.access == "property":
        return ["# Assert: the property can be read (pin its value by hand or use --record)", "_ = result"]
    return [
        "# Assert: only what can be checked without knowing the value (pin it by hand or use --record)",
        _fallback_assertion_line(case.spec),
    ]


def _emit_pytest_skipped(lines: List[str], name: str, reason: str) -> None:
    lines.extend([
        f"def test_{name}_happy_path() -> None:",
        f"    pytest.skip({reason!r})",
        "",
    ])


def _emit_pytest_nominal(lines: List[str], case: _PytestCase) -> None:
    """Nominal case: the expected value is computed from the body or recorded; it is never guessed from the name."""
    spec = case.spec
    raises_outcome = case.outcome is not None and case.outcome[0] == "raises"
    test_name = f"test_{case.safe_id}_sample_input_raises" if raises_outcome else f"test_{case.safe_id}_happy_path"
    lines.append(f"def {test_name}(qa_workspace) -> None:")
    lines.append("    # Arrange: isolated environment and nominal input arguments")
    lines.extend(_setup_lines(spec, "    ", "pytest.skip"))
    lines.append("    _ = qa_workspace")
    ind = "    "
    # When the test checks delegation to the doubles, the value is not inspected: dropping the
    # `result =` avoids leaving an unused variable (F841) in the suite.
    named = bool(case.io_targets) and case.outcome is None and io_assertion(spec) == "called"
    if case.io_targets:
        lines.append(f"    # I/O replaced by test doubles: {', '.join(case.io_targets)}")
        lines.append(f"    with {patch_clause(case.io_targets, named=named)}:")
        ind = "        "
    if raises_outcome and case.outcome is not None:
        lines.append(f"{ind}# Act and Assert: {RAISES_COMMENT[case.source]}")
        match = _regex_literal(case.outcome[2]) if case.outcome[2] else 'r".*"'
        lines.append(f"{ind}with pytest.raises({case.outcome[1]}, match={match}):")
        lines.append(f"{ind}    {spec.call()}")
    else:
        lines.append(f"{ind}# Act: call the target with valid values")
        fake_io = bool(case.io_targets) and case.outcome is None
        statement = spec.call() if named else f"result = {spec.call()}"
        lines.extend(_call_lines(spec, ind, statement, "pytest.skip", fake_io))
        lines.extend(f"{ind}{line}" for line in _nominal_assertion(case))
    lines.append("")


def _boundary_body(case: _PytestCase, call: str, first_assumed: bool) -> List[str]:
    """
    Given a boundary value, the function may return something or reject it with one of the
    expected exceptions: a validating assert counts too, and so does an OSError when the value is
    a path ("" does not exist; 2,048 characters is too long a name). Only what is certain is
    asserted about the value: None when it never returns anything, and not None when it always
    ends by returning a value. When it can return None on some path, or its I/O is patched,
    nothing is asserted about the value: raising no other exception is enough.
    """
    raises = declared_raises(case.spec, reachable=True)
    exc_tuple = ", ".join(sorted({name for name, _ in raises}
                                 | {"ArithmeticError", "AssertionError", "LookupError", "OSError", "TypeError",
                                    "ValueError"}))
    kind = fallback_kind(case.spec)[0]
    assign = ""
    if case.io_targets:
        value_check = ["    # The I/O is patched: the value depends on the doubles and is not asserted."]
    elif kind == "none":
        value_check = ["    # It can return None on some path: nothing is asserted about the value."]
    else:
        assign = "res = "
        value_check = ["    assert res is None" if kind == "is_none" else "    assert res is not None"]
    # A rejection must explain itself, except for exceptions the function raises without a
    # message (raise KeyError(), or an assert with no text), whose text is empty.
    silent = sorted({name for name, msg in raises if msg == ""}
                    | ({"AssertionError"} if case.spec.meta.get("bare_assert") else set()))
    message_check = f"    assert str(exc) or isinstance(exc, ({', '.join(silent)},))" if silent else "    assert str(exc)"
    body = ["try:", f"    {assign}{call}", *value_check, f"except ({exc_tuple}) as exc:", message_check]
    if first_assumed:
        body.extend([
            "except AttributeError as exc:",
            '    pytest.skip(f"The boundary value is not of the type the function expects: {exc}")',
        ])
    return body


def _emit_pytest_boundary(lines: List[str], case: _PytestCase) -> None:
    """Parametrised boundary values for the first parameter, by its value kind."""
    spec = case.spec
    if spec.access == "property" or spec.plan.first is None:
        return
    param, sample = spec.plan.first
    values = boundary_values(sample, param.arg)
    if param.arg in spec.meta.get("durations", []):
        # A duration of 10**6 seconds would leave the test waiting for eleven days.
        values = [(b_id, value) for b_id, value in values if b_id != "large_num"]
    if not values:
        return
    rows = ", ".join(value for _, value in values)
    row_ids = ", ".join(f'"{b_id}"' for b_id, _ in values)
    lines.append(f'@pytest.mark.parametrize("boundary_value", [{rows}], ids=[{row_ids}])')
    lines.append(f"def test_{case.safe_id}_boundary_values(boundary_value) -> None:")
    lines.append(f"    # Arrange: {param.arg} takes each boundary value supplied by pytest")
    lines.extend(_setup_lines(spec, "    ", "pytest.skip"))
    lines.append("    # Act and Assert: a coherent result, or a typed rejection that explains itself")
    call = spec.call(spec.plan.with_first("boundary_value"))
    # Elements of a list or dict with no known type are an assumption, just like its value.
    guessed = sample.assumed or param.arg in spec.plan.assumed or (sample.kind in ("list", "dict") and sample.item is None)
    body = _boundary_body(case, call, guessed)
    if case.io_targets:
        lines.append(f"    with {patch_clause(case.io_targets)}:")
        lines.extend(f"        {b}" for b in body)
    else:
        lines.extend(f"    {b}" for b in body)
    lines.append("")


def _emit_pytest_adversarial(lines: List[str], case: _PytestCase) -> None:
    """Hostile scenarios: the exact exception type with a matching message, or None for the first parameter."""
    spec = case.spec
    if spec.access == "property" or spec.plan.first is None:
        return
    rejection = expected_rejection(spec)
    if rejection is not None:
        match_kw = f", match={rejection.pattern}" if rejection.pattern else ""
        lines.append(f"def test_{case.safe_id}_adversarial_raises_exact_error() -> None:")
        lines.append("    # Arrange: a hostile argument that triggers the domain validation")
        lines.extend(_setup_lines(spec, "    ", "pytest.skip"))
        lines.append("    # Act and Assert: require the exact type and expected message in pytest.raises")
        lines.append(f"    with {_with_doubles(case.io_targets)}pytest.raises({rejection.exceptions}{match_kw}):")
        lines.append(f"        {spec.call(_with_arg(spec.plan, rejection.position, rejection.value))}")
        lines.append("")
        return
    param, _ = spec.plan.first
    if param.arg not in spec.meta.get("none_unsafe", []) or accepts_none(param, None):
        return
    lines.append(f"def test_{case.safe_id}_adversarial_none_input() -> None:")
    lines.append(f"    # Arrange: replace {param.arg} with None (the body uses it without checking)")
    lines.extend(_setup_lines(spec, "    ", "pytest.skip"))
    lines.append("    # Act and Assert: require an explicit exception for the null reference")
    exceptions = ", ".join(_none_input_exceptions(case))
    lines.append(f"    with {_with_doubles(case.io_targets)}pytest.raises(({exceptions}), match={_none_input_match(case)}):")
    lines.append(f"        {spec.call(spec.plan.with_first('None'))}")
    lines.append("")


# What Python usually raises when it operates on None where a value was expected, plus the
# AssertionError of a function that validates its input with assert.
_NONE_INPUT_EXCEPTIONS = ("TypeError", "ValueError", "AttributeError", "KeyError", "ZeroDivisionError",
                          "AssertionError")


def _none_input_exceptions(case: _PytestCase) -> List[str]:
    """The exceptions the function raises explicitly, followed by those Python raises when given None."""
    declared = sorted({name for name, _ in declared_raises(case.spec, reachable=True)} - set(_NONE_INPUT_EXCEPTIONS))
    return [*declared, *_NONE_INPUT_EXCEPTIONS]


def _none_input_match(case: _PytestCase) -> str:
    """A message is required, unless the function raises some exception without one (raise KeyError(), assert x)."""
    silent = any(msg == "" for _, msg in case.spec.meta.get("raises_reachable") or case.spec.meta.get("raises") or [])
    return 'r".*"' if silent or case.spec.meta.get("bare_assert") else 'r".+"'


def _emit_pytest_property(lines: List[str], case: _PytestCase) -> None:
    spec = case.spec
    lines.extend([
        "if _HAS_HYPOTHESIS:",
        "    @given(st.integers(min_value=-10000, max_value=10000), st.integers(min_value=-10000, max_value=10000))",
        f"    def test_{case.safe_id}_property_integers(x_val: int, y_val: int) -> None:",
        "        # Arrange & Act: check the invariant on randomly generated integers",
        *_setup_lines(spec, "        ", "pytest.skip"),
        f"        res = {spec.call('x_val, y_val')}",
        "        # Assert: the result is still numeric (int or float)",
        "        assert isinstance(res, (int, float))",
        "",
    ])


def _emit_pytest_async(lines: List[str], case: _PytestCase) -> None:
    """Coroutines: timeouts, cooperative cancellation and concurrent execution."""
    spec = case.spec
    target, args = spec.call_target, spec.plan.arg_str
    setup = _setup_lines(spec, "    ", "pytest.skip") or ["    # Module-level function: nothing to instantiate first."]
    gather = [f"        batch = await asyncio.gather({target}({args}), {target}({args}))"]
    if spec.plan.assumed:
        gather = [
            "        try:",
            f"            batch = await asyncio.gather({target}({args}), {target}({args}))",
            f"        except {_MISFIT} as exc:",
            '            pytest.skip(f"The assumed values do not fit the function: {exc}")',
        ]
    lines.extend([
        f"def test_{case.safe_id}_async_timeout_cancellation_and_gather() -> None:",
        "    # Arrange: initial state for the asyncio lifecycle tests",
        *setup,
        "    async def _slow_op(*_args, **_kwargs):",
        "        await asyncio.sleep(0.2)",
        f"        return await {target}({args})",
        "    async def _run_checks() -> None:",
        "        # Act and Assert: the timeout expires through wait_for",
        "        with pytest.raises((TimeoutError, asyncio.TimeoutError)):",
        "            await asyncio.wait_for(_slow_op(), timeout=0.001)",
        "        # Act and Assert: asyncio.CancelledError propagates cleanly",
        f"        task = asyncio.create_task({target}({args}))",
        "        task.cancel()",
        "        try:",
        "            await task",
        "        except asyncio.CancelledError:",
        "            assert task.cancelled()",
        "        # Act and Assert: concurrent execution with asyncio.gather",
        *gather,
        "        assert len(batch) == 2",
        *([f"    with {patch_clause(case.io_targets)}:", "        asyncio.run(_run_checks())"] if case.io_targets
          else ["    asyncio.run(_run_checks())"]),
        "",
    ])


def _emit_pytest_io_fault(lines: List[str], case: _PytestCase) -> None:
    """
    Failing I/O: every call with side effects is patched to raise OSError. Any call left unpatched
    would really run in the test (a real rmtree, for instance).
    """
    spec = case.spec
    faulty = ", ".join(
        f'patch("{t}", autospec=True, side_effect=OSError("io_fault")) as io_{i}'
        for i, t in enumerate(case.io_targets)
    )  # named, so the test can check whether the function reached them
    misfit = []
    if spec.plan.assumed:
        misfit = [
            f"        except {_MISFIT} as exc:",
            '            pytest.skip(f"The assumed values do not fit the function: {exc}")',
        ]
    lines.extend([
        f"def test_{case.safe_id}_isolated_io_fault() -> None:",
        "    # Arrange: autospec doubles that simulate the I/O being unavailable",
        *(_setup_lines(spec, "    ", "pytest.skip") or ["    # Module-level function: nothing to instantiate first."]),
        f"    with {faulty}:",
        "        # Act and Assert: the function handles the failure or propagates it as a typed, descriptive error",
        "        try:",
        f"            {spec.call()}",
        "        except (OSError, RuntimeError, ValueError) as exc:",
        "            assert str(exc)",
        *misfit,
        f"        if not ({io_called_expr(case.io_targets)}):",
        '            pytest.skip("With the sample values the function never reaches the patched I/O.")',
        "",
    ])


def emit_pytest_function(lines: List[str], spec: TargetSpec, recorded: Optional[Dict[str, Outcome]] = None) -> None:
    """Emit every pytest test for a target (nominal, boundary, adversarial, properties, async and I/O)."""
    if spec.skip:
        _emit_pytest_skipped(lines, spec.name.replace(".", "_"), spec.skip)
        return
    case = build_pytest_case(spec, recorded)
    _emit_pytest_nominal(lines, case)
    if spec.access == "property":
        return
    _emit_pytest_boundary(lines, case)
    _emit_pytest_adversarial(lines, case)
    names = spec.plan.names
    if case.outcome is not None and case.outcome[0] == "value" and not spec.plan.keywords \
            and is_pure_binop(case.func_node, names):  # type: ignore[arg-type]
        _emit_pytest_property(lines, case)
    if spec.is_async:
        _emit_pytest_async(lines, case)
    if case.io_targets:
        _emit_pytest_io_fault(lines, case)


def _emit_pytest_instantiation(lines: List[str], cls_name: str, ctx: SampleContext) -> None:
    expr, skip = instantiation_for(cls_name, ctx)
    if expr is None:
        _emit_pytest_skipped(lines, f"{cls_name}_instantiation", skip or "")
        return
    setup = [f"    obj = {expr}"]
    if construction_assumed(cls_name, ctx):
        setup = [
            "    try:",
            f"        obj = {expr}",
            f"    except {_MISFIT} as exc:",
            '        pytest.skip(f"Could not create the object from assumed values: {exc}")',
        ]
    lines.extend([
        f"def test_{cls_name}_instantiation(qa_workspace) -> None:",
        "    # Arrange",
        "    _ = qa_workspace",
        "    # Act",
        *setup,
        "    # Assert",
        f"    assert isinstance(obj, {cls_name})",
        "",
    ])


def render_pytest_suite(
    source_filepath: str,
    output_test_filepath: str,
    visitor: UnitTestGenerator,
    recorded: Dict[str, Outcome],
) -> str:
    """Render the complete source of an adversarial pytest suite."""
    ctx = SampleContext(visitor.tree, visitor.project)
    specs = build_targets(visitor, ctx)
    dotted, _ = module_import(source_filepath)
    body: List[str] = [
        "@pytest.fixture(autouse=True)",
        "def _qa_isolation(monkeypatch):",
        '    """No network, empty standard input and a time limit: no test is left waiting."""',
        '    monkeypatch.setattr(socket.socket, "connect", _qa_local_connect)',
        '    monkeypatch.setattr(socket, "getaddrinfo", _qa_local_getaddrinfo)',
        '    monkeypatch.setattr(sys, "stdin", _qa_empty_stdin())',
        "    disarm = _qa_time_limit(pytest.skip)",
        "    yield",
        "    disarm()",
        "",
        "",
        "@pytest.fixture",
        "def qa_workspace(tmp_path, monkeypatch):",
        '    """Module fixture with setup/teardown (yield) and environment isolation."""',
        '    monkeypatch.setenv("QA_TEST_MODE", "1")',
        "    sandbox = tmp_path / 'qa_sandbox'",
        "    sandbox.mkdir(exist_ok=True)",
        "    yield {'sandbox': sandbox, 'monkeypatch': monkeypatch}",
        "    _ = (MagicMock, AsyncMock)  # Kept referenced so hand-written tests can add spec'd doubles",
        "",
        "",
    ]
    for spec in specs:
        emit_pytest_function(body, spec, recorded=recorded)
    for cls_name, _, methods in visitor.classes:
        if not methods:
            _emit_pytest_instantiation(body, cls_name, ctx)
    if not visitor.functions and not visitor.classes:
        body.extend([
            "def test_module_importable(qa_workspace) -> None:",
            "    # Arrange",
            "    assert qa_workspace['sandbox'].is_dir()",
            "    # Act & Assert",
            "    spec = MagicMock(spec=dict)",
            "    assert spec is not None",
            "",
        ])

    text = "\n".join(body)
    hypothesis = [
        "try:",
        "    from hypothesis import given, strategies as st",
        "    _HAS_HYPOTHESIS = True",
        "except ImportError:",
        "    _HAS_HYPOTHESIS = False",
        "",
    ] if "_HAS_HYPOTHESIS" in text else []
    header = [
        f'"""Adversarial pytest suite generated for {dotted}."""',
        *(["import asyncio"] if "asyncio." in text else []),
        "import io",
        "import signal",
        "import socket",
        "import threading",
        "from unittest.mock import " + ", ".join(
            ["AsyncMock", "MagicMock", *(["mock_open"] if _uses_open_double(specs) else []),
             *(["patch"] if "patch(" in text else [])]),
        "import pytest",
        "",
        *hypothesis,
        *(RECORDED_HEADER if recorded else []),
        *import_header(source_filepath, output_test_filepath, ctx.used_names, ctx.used_modules, ctx.foreign_imports),
        "",
        "",
        *_ISOLATION_HELPERS,
        "",
        "",
    ]
    return "\n".join([*header, *body])


def write_suite(source_filepath: str, output_test_filepath: str, *, framework: str, record: bool) -> str:
    """Analyse the source and write the unittest or pytest suite to output_test_filepath."""
    from .ast_inspector import read_and_parse
    from .expected_values import record_outcomes

    try:
        tree = read_and_parse(source_filepath)
    except (FileNotFoundError, IsADirectoryError, SyntaxError, UnicodeDecodeError, OSError):
        return ""
    visitor = UnitTestGenerator(source_filepath)
    visitor.visit(tree)
    recorded = record_outcomes(source_filepath, recording_calls(visitor)) if record else {}
    render = render_pytest_suite if framework == "pytest" else render_unittest_suite
    content = render(source_filepath, output_test_filepath, visitor, recorded)
    os.makedirs(os.path.dirname(os.path.abspath(output_test_filepath)), exist_ok=True)
    with open(output_test_filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return output_test_filepath
