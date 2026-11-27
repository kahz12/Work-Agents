import ast
import io
import os
import re
import sys
import time
import unittest
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple, Union

_IO_CALL_PREFIXES = ("requests.", "urllib.request.", "sqlite3.")
_UNISOLATED_CALLS = frozenset({"urlopen", "time.sleep", "sqlite3.connect"})
_ISOLATION_NAMES = frozenset({
    "patch", "monkeypatch", "MagicMock", "AsyncMock", "Mock", "HTTPServer",
})
_TIMEOUT_EXC_NAMES = frozenset({"TimeoutError", "asyncio.TimeoutError", "CancelledError", "asyncio.CancelledError"})


def _chain(node: ast.AST) -> str:
    """Dotted name of a Name/Attribute chain ("mock.patch.object"), or "" for anything else."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        p = _chain(node.value)
        return f"{p}.{node.attr}" if p else node.attr
    return ""


def _is_generic_exc(arg: ast.AST) -> bool:
    """True for Exception or BaseException, alone or inside a tuple."""
    if isinstance(arg, ast.Name):
        return arg.id in ("Exception", "BaseException")
    if isinstance(arg, ast.Tuple):
        return any(_is_generic_exc(e) for e in arg.elts)
    return False


def _is_timeout_exc_arg(arg: ast.AST) -> bool:
    """True for timeout/cancellation exceptions, whose messages are not worth matching."""
    if isinstance(arg, (ast.Name, ast.Attribute)):
        return _chain(arg) in _TIMEOUT_EXC_NAMES
    if isinstance(arg, ast.Tuple):
        return bool(arg.elts) and all(_is_timeout_exc_arg(e) for e in arg.elts)
    return False


def _has_isolation_context(func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> bool:
    """True when the test isolates itself: monkeypatch/mocker fixtures, patch decorators or mock objects."""
    for arg in func_node.args.args:
        if arg.arg in ("monkeypatch", "mocker"):
            return True
    for dec in func_node.decorator_list:
        if any(name in _chain(dec) for name in ("patch", "mock")):
            return True
    for child in ast.walk(func_node):
        if isinstance(child, ast.Name) and child.id in _ISOLATION_NAMES:
            return True
        if isinstance(child, ast.Attribute) and child.attr in ("patch", "setattr", "object"):
            return True
    return False


# Ways to skip a test from inside its body, in pytest and in unittest.
_SKIP_CALLS = frozenset({"pytest.skip", "self.skipTest"})
_SKIP_EXCEPTIONS = frozenset({"SkipTest", "unittest.SkipTest", "pytest.skip.Exception"})


def _is_skip(stmt: ast.stmt) -> bool:
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        return _chain(stmt.value.func) in _SKIP_CALLS
    if isinstance(stmt, ast.Raise) and stmt.exc is not None:
        exc = stmt.exc.func if isinstance(stmt.exc, ast.Call) else stmt.exc
        return _chain(exc) in _SKIP_EXCEPTIONS
    return False


def _skips_unconditionally(body: List[ast.stmt]) -> bool:
    """
    True when the test always skips: a pytest.skip(), self.skipTest() or raise SkipTest in its
    body, outside any if, try or loop (a with block decides nothing). A conditional skip does
    not excuse the test from having assertions: the path that is not skipped must check something.
    """
    for stmt in body:
        if _is_skip(stmt):
            return True
        if isinstance(stmt, (ast.With, ast.AsyncWith)) and _skips_unconditionally(stmt.body):
            return True
    return False


def _decorator_name(dec: ast.AST) -> str:
    """Name of a decorator, called or not: @pytest.mark.skip or @pytest.mark.skip(...)."""
    return _chain(dec.func if isinstance(dec, ast.Call) else dec)


def _is_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _compares_equal_constants(node: ast.AST) -> bool:
    """`1 == 1`, `"a" == "a"`: a comparison that always holds."""
    return (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.Eq)
        and isinstance(node.left, ast.Constant)
        and isinstance(node.comparators[0], ast.Constant)
        and node.left.value == node.comparators[0].value
    )


def _string_literal(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_private(name: str) -> bool:
    """`_internal` is private; `__dunder__` is not, since it is part of the object's contract."""
    return name.startswith("_") and not name.startswith("__")


# A quality issue before its line is attached: (code, level, message).
_Issue = Tuple[str, str, str]

def _mock_names(*names: str) -> FrozenSet[str]:
    """The spellings of a unittest.mock name: bare, as mock.X, or as unittest.mock.X."""
    return frozenset(f"{prefix}{name}" for name in names for prefix in ("", "mock.", "unittest.mock."))


_MOCK_CLASSES = _mock_names("MagicMock", "Mock")
_PATCH_NAMES = _mock_names("patch")


def _assert_statement_issues(test: ast.AST, test_name: str) -> List[_Issue]:
    """assert True and comparisons between two equal constants check nothing."""
    if _is_true(test):
        return [("WEAK-ASSERT", "HIGH",
                 f"Tautological assertion 'assert True' in '{test_name}'. Write assertions that would catch a mutation.")]
    if _compares_equal_constants(test):
        return [("WEAK-ASSERT", "HIGH", f"Trivial constant assertion in '{test_name}'. Check real behaviour.")]
    return []


def _assertion_call(call: ast.Call, cname: str, test_name: str) -> Tuple[int, List[_Issue]]:
    """
    self.assert*(), pytest.raises() and pytest.fail() count as assertions. Returns
    (assertions counted, issues).
    """
    if isinstance(call.func, ast.Attribute) and call.func.attr.startswith("assert"):
        return 1, _assert_method_issues(call, call.func.attr, test_name)
    if cname == "pytest.raises":
        return 1, _pytest_raises_issues(call, test_name)
    if cname == "pytest.fail":
        return 1, []
    return 0, []


def _assert_method_issues(call: ast.Call, method: str, test_name: str) -> List[_Issue]:
    if method == "assertTrue" and call.args and _is_true(call.args[0]):
        return [("WEAK-ASSERT", "HIGH", f"Tautological assertion 'assertTrue(True)' in '{test_name}'.")]
    if method == "assertRaises" and call.args and _is_generic_exc(call.args[0]):
        return [("GENERIC-RAISES", "HIGH",
                 f"Generic assertRaises(Exception/BaseException) in '{test_name}'. "
                 "Check the exact exception and use assertRaisesRegex.")]
    return []


def _pytest_raises_issues(call: ast.Call, test_name: str) -> List[_Issue]:
    if not call.args:
        return []
    if _is_generic_exc(call.args[0]):
        return [("GENERIC-RAISES", "HIGH",
                 f"pytest.raises(Exception/BaseException) in '{test_name}'. "
                 "Require a specific exception plus match=r'...'.")]
    if not _is_timeout_exc_arg(call.args[0]) and not any(kw.arg == "match" for kw in call.keywords):
        return [("GENERIC-RAISES", "MEDIUM", f"pytest.raises(...) without a 'match=r\"...\"' argument in '{test_name}'.")]
    return []


def _test_double_issues(call: ast.Call, cname: str, test_name: str) -> List[_Issue]:
    """
    Test doubles should carry spec/spec_set or autospec, so they are bound to the real signature
    and fail when the interface changes, and they should not replace private members.
    """
    if cname in _MOCK_CLASSES:
        if any(kw.arg in ("spec", "spec_set") for kw in call.keywords):
            return []
        return [("UNSAFE-MOCK", "MEDIUM",
                 f"'{cname}()' without 'spec=' or 'spec_set=' in '{test_name}'. "
                 "Use spec/autospec=True to catch signature changes.")]
    if cname in _PATCH_NAMES:
        return _patch_issues(call, test_name)
    if cname.endswith("patch.object") and len(call.args) >= 2:
        method = _string_literal(call.args[1])
        if method is not None and _is_private(method):
            return [("UNSAFE-MOCK", "MEDIUM",
                     f"Private method '{method}' is mocked in '{test_name}'. Test the observable behaviour instead.")]
    return []


def _patch_issues(call: ast.Call, test_name: str) -> List[_Issue]:
    """patch() without autospec/spec/new, or patching a private member."""
    issues: List[_Issue] = []
    if not any(kw.arg in ("autospec", "spec", "spec_set", "new") for kw in call.keywords):
        issues.append(("UNSAFE-MOCK", "MEDIUM", f"patch() without 'autospec=True' in '{test_name}'."))
    target = _string_literal(call.args[0]) if call.args else None
    if target is not None and _is_private(target.rsplit(".", 1)[-1]):
        issues.append(("UNSAFE-MOCK", "MEDIUM",
                       f"Private member '{target}' is mocked in '{test_name}'. Test public contracts instead."))
    return issues


class TestQualityAuditor(ast.NodeVisitor):
    """
    AST quality audit of unit test suites: weak assertions, generic exception checks, real I/O
    without isolation, and test doubles not bound to a signature.
    """

    def __init__(self) -> None:
        self.findings: List[Tuple[int, str, str, str]] = []
        self.tests_count: int = 0
        self.assertions_count: int = 0
        self.uses_parametrize: bool = False
        self.uses_fixtures: bool = False

    def _audit_test_func(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> None:
        self._note_decorators(node)
        if not node.name.startswith("test_"):
            self.generic_visit(node)
            return

        self.tests_count += 1
        isolated = _has_isolation_context(node)
        has_skip = any("skip" in _decorator_name(d) for d in node.decorator_list) \
            or _skips_unconditionally(node.body)
        local_asserts = 0

        for sub in ast.walk(node):
            if isinstance(sub, ast.Assert):
                local_asserts += 1
                self._report(sub.lineno, _assert_statement_issues(sub.test, node.name))
            elif isinstance(sub, ast.Call):
                local_asserts += self._audit_call(sub, node.name, isolated)
        self.assertions_count += local_asserts

        if local_asserts == 0 and not has_skip:
            self._report(node.lineno, [(
                "WEAK-ASSERT", "HIGH",
                f"Test '{node.name}' contains no real assertion (assert / pytest.raises).",
            )])

        self.generic_visit(node)

    def _report(self, line: int, issues: List[_Issue]) -> None:
        self.findings.extend((line, code, level, message) for code, level, message in issues)

    def _note_decorators(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> None:
        for dec in node.decorator_list:
            name = _decorator_name(dec)
            if "parametrize" in name:
                self.uses_parametrize = True
            if "fixture" in name:
                self.uses_fixtures = True

    def _audit_call(self, sub: ast.Call, test_name: str, isolated: bool) -> int:
        """Audit one call inside a test. Returns how many assertions it contributes."""
        cname = _chain(sub.func)
        counted, issues = _assertion_call(sub, cname, test_name)

        # Real I/O in a unit test brings non-deterministic latency and environment-dependent
        # failures: it has to be isolated with patch, monkeypatch or a test double.
        if not isolated and (cname in _UNISOLATED_CALLS or cname.startswith(_IO_CALL_PREFIXES)):
            issues.append((
                "UNISOLATED-IO", "HIGH",
                f"Real call '{cname}()' inside unit test '{test_name}' without patch/monkeypatch/Mock.",
            ))

        issues.extend(_test_double_issues(sub, cname, test_name))
        self._report(sub.lineno, issues)
        return counted

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._audit_test_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._audit_test_func(node)


class QATestRunner:
    """
    Runs test suites and collects results, timing, an estimate of function coverage and a
    quality audit of the suite itself.
    """

    @staticmethod
    def run_unittest_suite(test_filepath: str) -> Dict[str, Any]:
        """
        Load and run the unittest suite in a single file, in-process. Results are captured in
        a buffer instead of being printed. Returns {"error": ...} when the file cannot be
        loaded.
        """
        try:
            with open(test_filepath, "r", encoding="utf-8"):
                pass
        except FileNotFoundError:
            return {"error": f"Test file '{test_filepath}' does not exist."}
        except (IsADirectoryError, PermissionError, OSError) as e:
            return {"error": f"Could not open '{test_filepath}': {e}"}

        test_dir = os.path.dirname(os.path.abspath(test_filepath))
        test_file_name = os.path.basename(test_filepath)

        # The suite imports the module under test as a sibling, so its directory must be importable.
        if test_dir not in sys.path:
            sys.path.insert(0, test_dir)

        start_time = time.time()
        loader = unittest.TestLoader()

        try:
            suite = loader.discover(start_dir=test_dir, pattern=test_file_name)
        except (ImportError, SyntaxError, OSError, ValueError) as e:
            return {"error": f"Could not discover the tests: {e}"}

        stream = io.StringIO()
        runner = unittest.TextTestRunner(stream=stream, verbosity=2)
        result = runner.run(suite)
        duration = round(time.time() - start_time, 4)

        tests_run = result.testsRun
        failures = len(result.failures)
        errors = len(result.errors)
        skipped = len(result.skipped)
        passed = tests_run - failures - errors - skipped
        pass_rate = round((passed / tests_run * 100), 2) if tests_run > 0 else 0.0

        failure_details = []
        for test_case, err_trace in result.failures + result.errors:
            failure_details.append({
                "test": str(test_case),
                "traceback": err_trace,
            })

        return {
            "test_file": test_filepath,
            "duration_seconds": duration,
            "tests_run": tests_run,
            "passed": passed,
            "failures": failures,
            "errors": errors,
            "skipped": skipped,
            "pass_rate_percentage": pass_rate,
            "failure_details": failure_details,
            "raw_output": stream.getvalue(),
            "coverage": QATestRunner.estimate_function_coverage(test_filepath),
        }

    @staticmethod
    def audit_test_suite_quality(test_filepath: str) -> Dict[str, Any]:
        """
        Audit a unit test file: assertion strength, exception specificity, I/O isolation and
        spec/autospec on test doubles.
        """
        try:
            with open(test_filepath, "r", encoding="utf-8") as f:
                test_src = f.read()
            tree = ast.parse(test_src, filename=test_filepath)
        except FileNotFoundError:
            return {"error": f"Test file '{test_filepath}' does not exist.", "findings": []}
        except (IsADirectoryError, PermissionError, OSError, SyntaxError, UnicodeDecodeError) as e:
            return {"error": f"Test quality audit error: {e}", "findings": []}

        auditor = TestQualityAuditor()
        auditor.visit(tree)
        return {
            "findings": auditor.findings,
            "tests_count": auditor.tests_count,
            "assertions_count": auditor.assertions_count,
            "uses_parametrize": auditor.uses_parametrize,
            "uses_fixtures": auditor.uses_fixtures,
        }

    @staticmethod
    def estimate_function_coverage(test_filepath: str) -> Dict[str, Any]:
        """
        Lightweight coverage estimate: the share of the source module's public functions that
        some test mentions by name, plus the suite's quality audit. The source module is the
        first `from X import` in the test file, resolved next to it.
        """
        test_dir = os.path.dirname(os.path.abspath(test_filepath))
        try:
            with open(test_filepath, "r", encoding="utf-8") as f:
                test_src = f.read()
        except OSError:
            return {"error": "could not read the test file"}

        quality_audit = QATestRunner.audit_test_suite_quality(test_filepath)

        mod_match = re.search(r"from\s+(\w+)\s+import", test_src)
        if not mod_match:
            return {
                "functions_total": 0,
                "functions_tested": 0,
                "coverage_percentage": 0.0,
                "quality_audit": quality_audit,
            }
        module_name = mod_match.group(1)
        source_path = os.path.join(test_dir, f"{module_name}.py")
        try:
            with open(source_path, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=source_path)
        except (FileNotFoundError, IsADirectoryError, OSError, SyntaxError, UnicodeDecodeError):
            return {
                "functions_total": 0,
                "functions_tested": 0,
                "coverage_percentage": 0.0,
                "module": module_name,
                "quality_audit": quality_audit,
            }

        functions: List[str] = []
        seen: Set[str] = set()
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
                if node.name not in seen:
                    functions.append(node.name)
                    seen.add(node.name)
            elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and not item.name.startswith("_"):
                        if item.name not in seen:
                            functions.append(item.name)
                            seen.add(item.name)
        tested = [fn for fn in functions if f"test_{fn}" in test_src or f"{fn}(" in test_src]
        total = len(functions)
        cov = round((len(tested) / total * 100), 2) if total else 0.0
        return {
            "module": module_name,
            "functions_total": total,
            "functions_tested": len(tested),
            "functions_tested_names": tested,
            "coverage_percentage": cov,
            "quality_audit": quality_audit,
        }
