"""
Internals of the qa agent: the interpreter that computes expected results, recording, the
suite quality rules, the sample values and the generator facade.

The interpreter is tested against Python itself: for each case the static outcome must equal
what running the function produces, and for anything it cannot evaluate it must give up (None)
rather than invent a value the generated test would then assert.
"""
import ast
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentes.qa import expected_values as ev  # noqa: E402
from agentes.qa import sample_values as sv  # noqa: E402
from agentes.qa.test_generator import QATestGenerator  # noqa: E402
from agentes.qa.test_runner import QATestRunner  # noqa: E402


def _func(src: str) -> ast.FunctionDef:
    node = ast.parse(src).body[0]
    assert isinstance(node, ast.FunctionDef)
    return node


def _arg_names(func: ast.FunctionDef):
    return [a.arg for a in func.args.args]


def _real_outcome(src: str, samples):
    """What really running the function produces, in the same shape as static_outcome."""
    namespace: dict = {}
    exec(compile(src, "<case>", "exec"), namespace)  # agentes: ignore[dynamic-exec] - fixed code written by this test
    args = [ast.literal_eval(s) for s in samples]
    try:
        value = namespace["f"](*args)
    except Exception as exc:  # noqa: BLE001 - the exception type is exactly what is being compared
        return ("raises", type(exc).__name__, str(exc))
    return ("value", repr(value), "")


# --- Static interpreter -------------------------------------------------------------------

EVALUABLE = {
    "subscript": ("def f(x):\n    return x[1]", ["[1, 2, 3]"]),
    "slice": ("def f(x):\n    return x[1:3]", ["[1, 2, 3]"]),
    "slice with step": ("def f(x):\n    return x[::-1]", ["'abc'"]),
    "tuple, list and set": ("def f(x):\n    return (x, [x], {x})", ["1"]),
    "dict": ("def f(x):\n    return {'a': x, 'b': [x]}", ["1"]),
    "f-string with conversion and format": ("def f(x):\n    return f'{x!r:>6}|{x}|{x!s}|{x!a}'", ["'ñ'"]),
    "annotated assignment, += and pass": ("def f(x):\n    y: int = x\n    y += 2\n    pass\n    return y", ["1"]),
    "short-circuit and, or and not": ("def f(x, y):\n    return x and y, x or y, not x, y and x", ["0", "3"]),
    "chained comparison": ("def f(x):\n    return 1 < x < 3, 5 < x < 10", ["2"]),
    "unary operators and small powers": ("def f(x):\n    return -x, +x, ~x, x ** 3, x << 2", ["5"]),
    "side-effect-free builtins": ("def f(x):\n    return len(x), abs(-3), min(x), sorted(x), round(2.5)", ["[4, 2]"]),
    "IndexError": ("def f(x):\n    return x[10]", ["[1]"]),
    "ZeroDivisionError": ("def f(x):\n    return 1 / x", ["0"]),
    "raise with a message": ("def f(x):\n    if x < 0:\n        raise ValueError('negative')\n    return x", ["-1"]),
    "raise without arguments": ("def f(x):\n    raise KeyError()", ["1"]),
    "docstring and bare literal": ('def f(x):\n    """Doc."""\n    "note"\n    return x', ["7"]),
}


@pytest.mark.parametrize("src, samples", EVALUABLE.values(), ids=EVALUABLE.keys())
def test_interpreter_matches_real_execution(src, samples):
    func = _func(src)
    assert ev.static_outcome(func, _arg_names(func), samples) == _real_outcome(src, samples)


NOT_EVALUABLE = {
    "huge power": ("def f(x):\n    return x ** 100", ["2"]),
    "huge shift": ("def f(x):\n    return x << 100", ["2"]),
    "@ operator": ("def f(x):\n    return x @ x", ["2"]),
    "list with *": ("def f(x):\n    return [*x]", ["[1]"]),
    "dict with **": ("def f(x):\n    return {**x}", ["{}"]),
    "call with *": ("def f(x):\n    return len(*x)", ["[[1]]"]),
    "attribute": ("def f(x):\n    return x.real", ["1"]),
    "comprehension": ("def f(x):\n    return [i for i in x]", ["[1]"]),
    "loop": ("def f(x):\n    for i in x:\n        pass\n    return x", ["[1]"]),
    "unknown name": ("def f(x):\n    return y", ["1"]),
    "disallowed builtin": ("def f(x):\n    return print(x)", ["1"]),
    "non-literal value": ("def f(x):\n    return float('inf')", ["1"]),
    "raise of a variable": ("def f(x):\n    e = ValueError('x')\n    raise e", ["1"]),
}


@pytest.mark.parametrize("src, samples", NOT_EVALUABLE.values(), ids=NOT_EVALUABLE.keys())
def test_interpreter_gives_up_on_what_it_cannot_evaluate(src, samples):
    func = _func(src)
    assert ev.static_outcome(func, _arg_names(func), samples) is None


def test_static_outcome_without_a_function_or_with_samples_that_do_not_fit():
    func = _func("def f(x, y):\n    return x + y")
    assert ev.static_outcome(None, [], []) is None
    assert ev.static_outcome(func, ["x", "y"], ["1"]) is None
    assert ev.static_outcome(func, ["x", "y"], ["1", "not a literal("]) is None


@pytest.mark.parametrize("src", ["def f(x):\n    raise ValueError(x)", "def f(x):\n    raise ValueError"])
def test_raise_without_a_literal_message_leaves_the_message_unknown(src):
    """The type is known and the message is not asserted: the generated test will check the type only."""
    assert ev.static_outcome(_func(src), ["x"], ["5"]) == ("raises", "ValueError", None)


@pytest.mark.parametrize("value, expected", [
    (1, True), ([1, (2, "a")], True), ({"k": {1, 2}}, True), (None, True),
    (float("nan"), False), (float("inf"), False), (object(), False), ([object()], False),
])
def test_is_literal(value, expected):
    assert ev.is_literal(value) is expected


@pytest.mark.parametrize("src, expected", [
    ("def f(x) -> None:\n    print(x)", ("is_none", "")),
    ("def f(x) -> int:\n    return g(x)", ("isinstance", "int")),
    ("def f(x):\n    yield x", ("none", "")),
    ("def f(x):\n    print(x)", ("is_none", "")),
    ("def f(x):\n    return None", ("is_none", "")),
    ("def f(x):\n    return g(x)", ("not_none", "")),
    ("def f(x):\n    if x:\n        return g(x)\n    print(x)", ("none", "")),
    ("def f(x):\n    def g():\n        return 1\n    print(g)", ("is_none", "")),
])
def test_fallback_assertion(src, expected):
    assert ev.fallback_assertion(_func(src)) == expected


def test_fallback_assertion_without_a_function():
    assert ev.fallback_assertion(None) == ("none", "")


@pytest.mark.parametrize("src, expected", [
    ("def f():\n    return random.choice([1, 2])", True),
    ("def f():\n    return secrets.token_hex()", True),
    ("def f():\n    return time.time()", True),
    ("def f():\n    return fetch()[0]", False),
    ("def f(x):\n    return x + 1", False),
])
def test_uses_nondeterminism(src, expected):
    assert ev.uses_nondeterminism(_func(src), {"time.time"}) is expected


def test_uses_nondeterminism_without_a_function():
    assert ev.uses_nondeterminism(None, {"time.time"}) is False


# --- Recording -------------------------------------------------------------------------------

def test_recording_without_calls_starts_no_process(tmp_path):
    assert ev.record_outcomes(str(tmp_path / "missing.py"), {}) == {}


def test_recording_a_module_that_ends_the_process(tmp_path):
    mod = tmp_path / "exits.py"
    mod.write_text("import os\nos._exit(3)\n\n\ndef f():\n    return 1\n", encoding="utf-8")
    with pytest.raises(ev.RecordingError, match="Could not record"):
        ev.record_outcomes(str(mod), {"f": "f()"})


def test_recording_a_function_that_never_finishes(tmp_path):
    mod = tmp_path / "forever.py"
    mod.write_text("def f():\n    while True:\n        pass\n", encoding="utf-8")
    with pytest.raises(ev.RecordingError, match="took longer than 1 s"):
        ev.record_outcomes(str(mod), {"f": "f()"}, timeout=1)


# --- Suite quality ------------------------------------------------------------------------------

SUITE = '''import unittest
from unittest import mock

import pytest


def test_tautology():
    assert True


class T(unittest.TestCase):
    def test_assert_true(self):
        self.assertTrue(True)

    def test_generic_raises(self):
        with self.assertRaises(Exception):
            do_work()

    def test_raises_with_generic_tuple(self):
        with self.assertRaises((ValueError, BaseException)):
            do_work()

    def test_mock_without_spec(self):
        double = mock.MagicMock()
        double.assert_not_called()

    def test_mock_with_spec(self):
        double = mock.MagicMock(spec=dict)
        double.assert_not_called()

    def test_patch_of_a_private_member_without_autospec(self):
        with mock.patch("module._internal"):
            self.assertEqual(1, 1 + 0)

    def test_patch_object_of_a_private_member(self):
        with mock.patch.object(Klass, "_secret", autospec=True):
            self.assertIsNotNone(Klass)


def test_skipped():
    pytest.skip("not applicable")


def test_fails_on_purpose():
    pytest.fail("pending")


def test_timeout_raises_without_match():
    with pytest.raises((TimeoutError, asyncio.TimeoutError)):
        wait()


def test_uses_monkeypatch(monkeypatch):
    monkeypatch.setattr("os.getcwd", lambda: "/")
    assert open("x").read()
'''


def test_suite_quality_detects_every_antipattern(tmp_path):
    suite = tmp_path / "test_suite.py"
    suite.write_text(SUITE, encoding="utf-8")
    findings = QATestRunner.audit_test_suite_quality(str(suite))["findings"]
    by_rule = {}
    for line, rule, level, msg in findings:
        by_rule.setdefault(rule, []).append(msg)
    assert any("assertTrue(True)" in m for m in by_rule["WEAK-ASSERT"])
    assert any("assert True" in m for m in by_rule["WEAK-ASSERT"])
    generic = " ".join(by_rule["GENERIC-RAISES"])
    assert "test_generic_raises" in generic and "test_raises_with_generic_tuple" in generic
    assert "test_timeout_raises_without_match" not in generic, "timeout exceptions need no match"
    mocks = " ".join(by_rule["UNSAFE-MOCK"])
    assert "test_mock_with_spec" not in mocks
    assert "Private method '_secret' is mocked" in mocks
    # The test using monkeypatch is isolated, so its open() does not count as real I/O.
    assert not any("test_uses_monkeypatch" in m for msgs in by_rule.values() for m in msgs)


def test_suite_quality_recognises_doubles_imported_through_the_module(tmp_path):
    """`from unittest import mock` followed by mock.MagicMock() or mock.patch() is very common."""
    suite = tmp_path / "test_suite.py"
    suite.write_text(SUITE, encoding="utf-8")
    mocks = " ".join(m for _, rule, _, m in QATestRunner.audit_test_suite_quality(str(suite))["findings"]
                     if rule == "UNSAFE-MOCK")
    assert "test_mock_without_spec" in mocks
    assert "Private member 'module._internal' is mocked" in mocks and "autospec=True" in mocks


def test_suite_quality_of_an_unreadable_suite(tmp_path):
    assert "does not exist" in QATestRunner.audit_test_suite_quality(str(tmp_path / "test_x.py"))["error"]
    broken = tmp_path / "test_broken.py"
    broken.write_text("def (:\n", encoding="utf-8")
    assert "Test quality audit error" in QATestRunner.audit_test_suite_quality(str(broken))["error"]


def test_running_a_missing_suite_or_a_directory(tmp_path):
    assert "does not exist" in QATestRunner.run_unittest_suite(str(tmp_path / "test_x.py"))["error"]
    assert "Could not open" in QATestRunner.run_unittest_suite(str(tmp_path))["error"]


def test_estimated_coverage_of_an_unreadable_suite(tmp_path):
    assert QATestRunner.estimate_function_coverage(str(tmp_path / "test_x.py")) == {"error": "could not read the test file"}


# --- Sample values -------------------------------------------------------------------------------

@pytest.mark.parametrize("annotation, expected", [
    ("'str'", '"sample"'), ("Optional[int]", "1"), ("int | None", "1"), ("None | str", '"sample"'),
    ("List[int]", "[]"), ("Callable[[], int]", None), ("'Unknown'", None),
])
def test_sample_from_the_annotation(annotation, expected):
    assert sv.annotation_sample(ast.parse(annotation, mode="eval").body) == expected


@pytest.mark.parametrize("name, expected", [
    ("user_name", '"sample"'), ("item_count", "1"), ("client_id", "1"), ("thing", "1"),
])
def test_sample_from_the_name(name, expected):
    assert sv.sample_for_arg(name) == expected


@pytest.mark.parametrize("name, annotation, nominal, first", [
    ("items", "list", "[]", "empty_list"), ("data", None, "{}", "empty_dict"),
    ("percent", None, "10", "zero_percent"), ("n", None, "5", "zero"), ("s", "str", '"a"', "empty_str"),
])
def test_boundary_cases_by_type_or_name(name, annotation, nominal, first):
    assert sv.boundary_samples_for_param(name, annotation, nominal)[0][0] == first


def test_scenario_matrix_includes_methods_and_functions_without_arguments(tmp_path):
    mod = tmp_path / "mod.py"
    mod.write_text("class C:\n    def m(self, x):\n        return x\n\n\ndef no_args():\n    return 1\n",
                   encoding="utf-8")
    matrix = sv.build_scenario_matrix(str(mod))
    targets = {s["target"] for s in matrix}
    assert {"C.m", "no_args"} <= targets
    assert any(s["scenario"] == "unexpected_extra_arg" for s in matrix if s["target"] == "no_args")
    broken = tmp_path / "broken.py"
    broken.write_text("def (:\n", encoding="utf-8")
    assert sv.build_scenario_matrix(str(broken)) == []


# --- Generator facade: backward-compatible aliases ------------------------------------------------

def test_the_generators_private_aliases_still_delegate(tmp_path):
    """The private names from before the generator was split into modules are kept and behave the same."""
    mod = tmp_path / "mod.py"
    mod.write_text("def double(x: int) -> int:\n    return x * 2\n", encoding="utf-8")
    arg = ast.parse("def f(user_name): pass").body[0].args
    assert isinstance(QATestGenerator._read_and_parse(str(mod)), ast.Module)
    assert QATestGenerator._boundary_samples_for_param("n", None, "1") == sv.boundary_samples_for_param("n", None, "1")
    assert QATestGenerator._annotation_sample(ast.Name(id="int")) == "1"
    assert QATestGenerator._sample_for_arg_node(arg.args[0]) == '"sample"'
    assert QATestGenerator._samples_from_arginfo(arg, ["user_name"])[1] == ["user_name"]
    assert QATestGenerator._sample_for_arg("client_id") == "1"
    assert QATestGenerator._is_float_literal("1.5") and not QATestGenerator._is_float_literal("1")
    assert QATestGenerator._io_targets([]) == []
    assert QATestGenerator._absorb_blocked(None, []) == (None, [])
    assert "patch(" in QATestGenerator._patch_clause(["os.remove"])
    assert QATestGenerator._io_called_expr(["os.remove"])
    visitor, recorded = QATestGenerator._visit(str(mod), record=False)
    assert recorded == {} and QATestGenerator._recording_calls(visitor)
    func = _func("def double(x):\n    return x * 2")
    assert QATestGenerator._outcome_for("double", func, ["x"], ["2"], {})[0] == ("value", "4", "")
    assert QATestGenerator._visit(str(tmp_path / "missing.py"), record=False) is None


# --- Generated suites: common shapes of analysed code ---------------------------------------

# Common shapes of analysed code.
BASE_SHAPES = '''class Empty:
    pass


class WithInit:
    def __init__(self, value=1):
        self.value = value


def returns_nothing(x):
    print(x)


def make_object(x):
    return Empty()


async def double(x):
    return x * 2
'''

# A function that always raises with a non-literal message, and another that only returns a value
# in one branch: both suites have to handle them correctly.
SHAPES = BASE_SHAPES + '''

def always_fails(x):
    raise RuntimeError(x)


def sometimes(x):
    if x > 5:
        return [x]
    print(x)
'''


def _run_suite(args, cwd):
    import subprocess

    return subprocess.run([sys.executable, "-m", *args], capture_output=True, text=True, cwd=str(cwd))


def _pytest_suite(tmp_path, source, record=False):
    src = tmp_path / "shapes.py"
    src.write_text(source, encoding="utf-8")
    suite = tmp_path / "test_shapes_pytest.py"
    QATestGenerator.generate_pytest_suite(str(src), str(suite), record=record)
    return suite.read_text(encoding="utf-8"), _run_suite(["pytest", "-q", "-p", "no:cacheprovider", suite.name], tmp_path)


@pytest.mark.parametrize("record", [False, True], ids=["static", "recorded"])
def test_generated_unittest_suite_passes_for_every_shape(tmp_path, record):
    src = tmp_path / "shapes.py"
    src.write_text(SHAPES, encoding="utf-8")
    unit = tmp_path / "test_shapes_unit.py"
    QATestGenerator.generate_test_suite(str(src), str(unit), record=record)
    body = unit.read_text(encoding="utf-8")
    assert "def test_Empty_instantiation" in body and "import asyncio" in body
    assert "self.assertIsNone(result)" in body
    if record:
        # The exception message and the type of the returned object are recorded too.
        assert 'with self.assertRaisesRegex(RuntimeError, r"1"):' in body
        assert 'self.assertEqual(type(result).__name__, "Empty")' in body
    else:
        assert "with self.assertRaises(RuntimeError):" in body
        assert "Exact value unknown" in body
        # sometimes only returns a value in one branch: nothing is safe to assert, and the test says so.
        assert "this test only checks that no exception is raised" in body
    run = _run_suite(["unittest", "-q", unit.stem], tmp_path)
    assert run.returncode == 0, run.stdout + run.stderr


@pytest.mark.parametrize("record", [False, True], ids=["static", "recorded"])
def test_generated_pytest_suite_passes_for_every_shape(tmp_path, record):
    body, run = _pytest_suite(tmp_path, SHAPES, record)
    assert "assert result is None" in body
    if record:
        assert 'assert type(result).__name__ == "Empty"' in body
    assert run.returncode == 0, run.stdout + run.stderr


def test_pytest_none_test_respects_the_functions_own_exceptions(tmp_path):
    source = ("def process(data):\n    total = len(data)\n    if total > 100:\n"
              "        raise RuntimeError('too many')\n    return total\n")
    body, run = _pytest_suite(tmp_path, source)
    assert "pytest.raises((RuntimeError, TypeError, ValueError, AttributeError, KeyError, ZeroDivisionError, " \
           'AssertionError), match=r".+")' in body
    assert run.returncode == 0, run.stdout + run.stderr


def test_pytest_suite_has_no_none_test_when_the_parameter_is_not_used_unchecked(tmp_path):
    """Rejecting None is only required when the body uses the parameter in something that fails on None."""
    sources = [
        "def always_fails(x):\n    raise RuntimeError(x)\n",               # only passed to another function
        "def normalise(level):\n    return str(level or '').upper()\n",     # level or '' accepts None
        "def optional(x=None):\n    return x\n",                            # defaults to None
        "def guard(x):\n    if x is None:\n        return 0\n    return x + 1\n",
        "def depends(flag, x):\n    if flag:\n        return 0\n    return x + 1\n",  # flag decides first
    ]
    for source in sources:
        body, run = _pytest_suite(tmp_path, source)
        assert "adversarial_none_input" not in body, source
        assert run.returncode == 0, run.stdout + run.stderr


def test_pytest_none_test_does_not_require_a_message_when_the_function_raises_without_one(tmp_path):
    source = "def lookup(table, key):\n    if key not in table:\n        raise KeyError()\n    return table[key]\n"
    body, run = _pytest_suite(tmp_path, source)
    assert 'match=r".*"' in body and 'match=r".+"' not in body
    # With a boundary value, a message-less KeyError() is also a valid rejection.
    assert "assert str(exc) or isinstance(exc, (KeyError,))" in body
    assert run.returncode == 0, run.stdout + run.stderr


def test_pytest_suite_does_not_require_a_value_when_the_function_may_return_none(tmp_path):
    body, run = _pytest_suite(tmp_path, "def sometimes(x):\n    if x > 5:\n        return [x]\n    print(x)\n")
    assert "It can return None on some path" in body
    assert run.returncode == 0, run.stdout + run.stderr


def test_suite_for_a_module_without_functions_or_classes(tmp_path):
    src = tmp_path / "constants.py"
    src.write_text("LIMIT = 10\n", encoding="utf-8")
    unit = tmp_path / "test_constants_unit.py"
    QATestGenerator.generate_test_suite(str(src), str(unit))
    assert "def test_module_importable" in unit.read_text(encoding="utf-8")
    suite = tmp_path / "test_constants_pytest.py"
    QATestGenerator.generate_pytest_suite(str(src), str(suite))
    run = _run_suite(["pytest", "-q", "-p", "no:cacheprovider", suite.name], tmp_path)
    assert run.returncode == 0, run.stdout + run.stderr


def test_is_float_literal_with_text_that_is_not_a_literal():
    assert QATestGenerator._is_float_literal("not a literal(") is False


# --- Adversarial payloads ------------------------------------------------------------------------

def test_adversarial_payloads_for_bool_objects_and_unknown_types():
    from agentes.qa.api_contract_testing import APIContractTester

    schema = {"active": bool, "owner": {"name": str}, "raw": bytes}
    payloads = dict(APIContractTester.generate_adversarial_payloads(schema))
    assert payloads["boundary_zero_or_empty"] == {"active": False, "owner": {}, "raw": {}}
    assert payloads["boundary_negative_unicode"] == {"active": True, "owner": {"name": None}, "raw": None}
    assert payloads["extreme_nan_giant"] == {"active": False, "owner": {"name": "sample"}, "raw": {}}
    assert payloads["bool_as_int_or_type_trap"] == {"active": "true", "owner": [], "raw": None}
    assert payloads["unexpected_extra_key"] == {"active": True, "owner": {"name": "sample"}, "raw": {},
                                                "__unexpected_extra__": "adversarial"}


SKIPS_SUITE = '''import unittest

import pytest


class T(unittest.TestCase):
    def test_skipped_in_unittest(self):
        self.skipTest("not applicable")

    def test_skipped_with_an_exception(self):
        raise unittest.SkipTest("not applicable")

    def test_skipped_inside_a_with(self):
        with open("x"):
            self.skipTest("not applicable")

    def test_skips_only_sometimes(self):
        try:
            do_work()
        except TypeError:
            self.skipTest("does not fit")


def test_skips_only_sometimes_in_pytest():
    try:
        do_work()
    except TypeError:
        pytest.skip("does not fit")


def test_skips_sometimes_but_checks():
    try:
        res = do_work()
    except TypeError:
        pytest.skip("does not fit")
    assert res == 1
'''


def test_suite_quality_treats_pytest_and_unittest_skips_alike(tmp_path):
    """A test that always skips needs no assertions; one that only skips sometimes does."""
    suite = tmp_path / "test_skips.py"
    suite.write_text(SKIPS_SUITE, encoding="utf-8")
    weak = " ".join(m for _, rule, _, m in QATestRunner.audit_test_suite_quality(str(suite))["findings"]
                    if rule == "WEAK-ASSERT")
    for always in ("test_skipped_in_unittest'", "test_skipped_with_an_exception'", "test_skipped_inside_a_with'"):
        assert always not in weak
    assert "test_skips_only_sometimes'" in weak and "test_skips_only_sometimes_in_pytest'" in weak
    assert "test_skips_sometimes_but_checks" not in weak
