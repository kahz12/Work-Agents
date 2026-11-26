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
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        p = _chain(node.value)
        return f"{p}.{node.attr}" if p else node.attr
    return ""


def _is_generic_exc(arg: ast.AST) -> bool:
    if isinstance(arg, ast.Name):
        return arg.id in ("Exception", "BaseException")
    if isinstance(arg, ast.Tuple):
        return any(_is_generic_exc(e) for e in arg.elts)
    return False


def _is_timeout_exc_arg(arg: ast.AST) -> bool:
    if isinstance(arg, (ast.Name, ast.Attribute)):
        return _chain(arg) in _TIMEOUT_EXC_NAMES
    if isinstance(arg, ast.Tuple):
        return bool(arg.elts) and all(_is_timeout_exc_arg(e) for e in arg.elts)
    return False


def _has_isolation_context(func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> bool:
    """Indica si el test usa fixtures/mocks de aislamiento."""
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


# Formas de omitir un test desde su cuerpo, en pytest y en unittest.
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
    El test se omite siempre: un pytest.skip(), self.skipTest() o raise SkipTest en su cuerpo,
    fuera de cualquier if, try o bucle (un with no decide nada). Un skip condicional no exime al
    test de tener aserciones: en el camino que no se omite tiene que comprobar algo.
    """
    for stmt in body:
        if _is_skip(stmt):
            return True
        if isinstance(stmt, (ast.With, ast.AsyncWith)) and _skips_unconditionally(stmt.body):
            return True
    return False


def _decorator_name(dec: ast.AST) -> str:
    """Nombre de un decorador con o sin llamada: @pytest.mark.skip o @pytest.mark.skip(...)."""
    return _chain(dec.func if isinstance(dec, ast.Call) else dec)


def _is_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _compares_equal_constants(node: ast.AST) -> bool:
    """`1 == 1`, `"a" == "a"`: una comparación que siempre se cumple."""
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
    """`_interno` sí; `__dunder__` no, porque forma parte del contrato del objeto."""
    return name.startswith("_") and not name.startswith("__")


# Aviso de calidad sin la línea: (código, nivel, mensaje).
_Issue = Tuple[str, str, str]

def _mock_names(*names: str) -> FrozenSet[str]:
    """Las formas de llamar a algo de unittest.mock: suelto, como mock.X o como unittest.mock.X."""
    return frozenset(f"{prefix}{name}" for name in names for prefix in ("", "mock.", "unittest.mock."))


_MOCK_CLASSES = _mock_names("MagicMock", "Mock")
_PATCH_NAMES = _mock_names("patch")


def _assert_statement_issues(test: ast.AST, test_name: str) -> List[_Issue]:
    """assert True y comparaciones entre dos constantes iguales: no comprueban nada."""
    if _is_true(test):
        return [("WEAK-ASSERT", "ALTO",
                 f"Aserción tautológica 'assert True' en '{test_name}'. Diseña aserciones pensando en mutación.")]
    if _compares_equal_constants(test):
        return [("WEAK-ASSERT", "ALTO", f"Aserción constante trivial en '{test_name}'. Valida comportamiento real.")]
    return []


def _assertion_call(call: ast.Call, cname: str, test_name: str) -> Tuple[int, List[_Issue]]:
    """
    self.assert*(), pytest.raises() y pytest.fail() cuentan como aserción. Devuelve (aserciones,
    avisos).
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
        return [("WEAK-ASSERT", "ALTO", f"Aserción tautológica 'assertTrue(True)' en '{test_name}'.")]
    if method == "assertRaises" and call.args and _is_generic_exc(call.args[0]):
        return [("GENERIC-RAISES", "ALTO",
                 f"Uso de assertRaises(Exception/BaseException) genérico en '{test_name}'. "
                 "Valida la excepción exacta y usa assertRaisesRegex.")]
    return []


def _pytest_raises_issues(call: ast.Call, test_name: str) -> List[_Issue]:
    if not call.args:
        return []
    if _is_generic_exc(call.args[0]):
        return [("GENERIC-RAISES", "ALTO",
                 f"Uso de pytest.raises(Exception/BaseException) en '{test_name}'. "
                 "Exige excepción específica + match=r'...'.")]
    if not _is_timeout_exc_arg(call.args[0]) and not any(kw.arg == "match" for kw in call.keywords):
        return [("GENERIC-RAISES", "MEDIO", f"pytest.raises(...) sin argumento 'match=r\"...\"' en '{test_name}'.")]
    return []


def _test_double_issues(call: ast.Call, cname: str, test_name: str) -> List[_Issue]:
    """
    Los dobles deben llevar spec/spec_set o autospec para acoplarse a la firma real y fallar
    cuando la interfaz cambia, y no deben sustituir miembros privados.
    """
    if cname in _MOCK_CLASSES:
        if any(kw.arg in ("spec", "spec_set") for kw in call.keywords):
            return []
        return [("UNSAFE-MOCK", "MEDIO",
                 f"'{cname}()' sin 'spec=' ni 'spec_set=' en '{test_name}'. "
                 "Usa spec/autospec=True para detectar cambios de firma.")]
    if cname in _PATCH_NAMES:
        return _patch_issues(call, test_name)
    if cname.endswith("patch.object") and len(call.args) >= 2:
        method = _string_literal(call.args[1])
        if method is not None and _is_private(method):
            return [("UNSAFE-MOCK", "MEDIO",
                     f"Mockeo del método privado '{method}' en '{test_name}'. Prueba el comportamiento observable.")]
    return []


def _patch_issues(call: ast.Call, test_name: str) -> List[_Issue]:
    issues: List[_Issue] = []
    if not any(kw.arg in ("autospec", "spec", "spec_set", "new") for kw in call.keywords):
        issues.append(("UNSAFE-MOCK", "MEDIO", f"patch() sin 'autospec=True' en '{test_name}'."))
    target = _string_literal(call.args[0]) if call.args else None
    if target is not None and _is_private(target.rsplit(".", 1)[-1]):
        issues.append(("UNSAFE-MOCK", "MEDIO",
                       f"Mockeo de miembro privado '{target}' en '{test_name}'. Prueba contratos públicos."))
    return issues


class TestQualityAuditor(ast.NodeVisitor):
    """
    Auditor AST de calidad para suites de prueba unitarias: detecta aserciones débiles,
    capturas genéricas de excepción, I/O real sin aislamiento y dobles sin contrato de firma.
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
                "WEAK-ASSERT", "ALTO",
                f"El test '{node.name}' no contiene ninguna aserción real (assert / pytest.raises).",
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
        """Revisa una llamada dentro del test. Devuelve las aserciones que aporta."""
        cname = _chain(sub.func)
        counted, issues = _assertion_call(sub, cname, test_name)

        # El I/O real dentro de una prueba unitaria introduce latencia no determinista y
        # fragilidad ambiental: debe ir aislado con patch, monkeypatch o un doble.
        if not isolated and (cname in _UNISOLATED_CALLS or cname.startswith(_IO_CALL_PREFIXES)):
            issues.append((
                "UNISOLATED-IO", "ALTO",
                f"Llamada real '{cname}()' dentro del test unitario '{test_name}' sin patch/monkeypatch/Mock.",
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
    Ejecutor automatizado de suites de pruebas con captura de métricas,
    tiempos de respuesta, estimación de cobertura y auditoría de calidad SDET.
    """

    @staticmethod
    def run_unittest_suite(test_filepath: str) -> Dict[str, Any]:
        """
        Carga y ejecuta una suite de pruebas unittest desde un archivo de forma aislada.
        """
        try:
            with open(test_filepath, "r", encoding="utf-8"):
                pass
        except FileNotFoundError:
            return {"error": f"Archivo de prueba '{test_filepath}' no existe."}
        except (IsADirectoryError, PermissionError, OSError) as e:
            return {"error": f"No se pudo abrir '{test_filepath}': {e}"}

        test_dir = os.path.dirname(os.path.abspath(test_filepath))
        test_file_name = os.path.basename(test_filepath)

        if test_dir not in sys.path:
            sys.path.insert(0, test_dir)

        start_time = time.time()
        loader = unittest.TestLoader()

        try:
            suite = loader.discover(start_dir=test_dir, pattern=test_file_name)
        except (ImportError, SyntaxError, OSError, ValueError) as e:
            return {"error": f"Error al descubrir pruebas: {e}"}

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
        Audita un archivo de pruebas unitarias evaluando solidez de aserciones,
        especificidad de excepciones, aislamiento de I/O y uso de spec/autospec en dobles.
        """
        try:
            with open(test_filepath, "r", encoding="utf-8") as f:
                test_src = f.read()
            tree = ast.parse(test_src, filename=test_filepath)
        except FileNotFoundError:
            return {"error": f"Archivo de prueba '{test_filepath}' no existe.", "findings": []}
        except (IsADirectoryError, PermissionError, OSError, SyntaxError, UnicodeDecodeError) as e:
            return {"error": f"Error auditando calidad de pruebas: {e}", "findings": []}

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
        Estimación ligera de cobertura: % de funciones públicas del módulo fuente
        que tienen al menos un test_* referenciándolas + auditoría de calidad de pruebas.
        """
        test_dir = os.path.dirname(os.path.abspath(test_filepath))
        try:
            with open(test_filepath, "r", encoding="utf-8") as f:
                test_src = f.read()
        except OSError:
            return {"error": "no se pudo leer test file"}

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
