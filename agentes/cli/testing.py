"""
Comandos CLI de QA y pruebas: test, testability y contract.
"""
from __future__ import annotations

import argparse
import json
import re
from typing import Any, Dict, List, Tuple

from ..common.console import describe_counts, ui
from ..common.findings import Finding, count_by_level
from .common import (
    CliError,
    dicts,
    emit_json,
    rel,
    require_path,
    require_python_file,
    show_findings,
    visible,
)

_SCHEMA_TYPES = {
    "str": str, "string": str, "int": int, "integer": int, "float": float, "number": float,
    "bool": bool, "boolean": bool, "list": list, "array": list, "dict": dict, "object": dict,
}


def _print_test_failures(failure_details: List[Dict[str, Any]], verbose: bool) -> None:
    if not failure_details:
        return
    ui.section("Tests que no pasan")
    for item in failure_details:
        trace = str(item["traceback"]).strip()
        ui.out(f"  {ui.style(item['test'], 'bold')}")
        if verbose:
            for line in trace.splitlines():
                ui.out(f"    {line}")
        else:
            ui.out(f"    {ui.style(trace.splitlines()[-1] if trace else '', 'red')}")
    if not verbose:
        ui.hint("  Añade --verbose para ver las trazas completas.")


def cmd_test(args: argparse.Namespace) -> int:
    """Ejecuta una suite unittest y evalúa su calidad y cobertura estimada."""
    from ..qa.test_runner import QATestRunner

    path = require_python_file(args.path)
    result = QATestRunner.run_unittest_suite(path)
    if result.get("error"):
        if args.json:
            emit_json(result)
        else:
            ui.fail(result["error"])
        return 1

    coverage = result.get("coverage") or {}
    quality = coverage.get("quality_audit") or {}
    failed = result["failures"] + result["errors"]
    code = 1 if failed or result["tests_run"] == 0 else 0

    if args.json:
        result.pop("raw_output", None)
        emit_json(result)
        return code

    ui.title(f"Tests de {rel(path)}")
    ui.kv([
        ("Ejecutados", result["tests_run"]),
        ("Correctos", result["passed"]),
        ("Fallidos", result["failures"]),
        ("Con error", result["errors"]),
        ("Omitidos", result["skipped"]),
        ("Tasa de éxito", f"{result['pass_rate_percentage']}%"),
        ("Duración", f"{result['duration_seconds']} s"),
    ], indent=0)

    if result["tests_run"] == 0:
        ui.out()
        ui.warn("No se encontró ningún test unittest. Si la suite es de pytest, ejecútala con 'pytest'.")

    _print_test_failures(result["failure_details"], args.verbose)

    if coverage.get("functions_total"):
        ui.section("Cobertura estimada")
        ui.out(
            f"  {coverage['functions_tested']} de {coverage['functions_total']} funciones públicas de "
            f"'{coverage.get('module')}' tienen algún test ({coverage['coverage_percentage']}%)."
        )
        ui.hint("  Es una estimación por nombres, no una medición de líneas ejecutadas.")

    q_findings = [
        Finding(path, line, level, f"[{rule}] {msg}", "TEST-QUALITY")
        for line, rule, level, msg in quality.get("findings", [])
    ]
    if q_findings:
        ui.section(f"Calidad de la suite ({len(q_findings)}): {describe_counts(count_by_level(q_findings))}")
        ui.findings(visible(q_findings), limit=args.limit)

    ui.out()
    if code == 0:
        ui.ok("Todos los tests pasan.")
    elif failed:
        ui.fail(f"{failed} tests no pasan.")
    return code


def cmd_testability(args: argparse.Namespace) -> int:
    """Detecta impedimentos de testabilidad en un módulo y propone escenarios de prueba."""
    from ..qa.test_generator import QATestGenerator

    path = require_python_file(args.path)
    findings = [
        Finding(path, line, level, f"[{rule}] {msg}", "TESTABILITY")
        for line, rule, level, msg in QATestGenerator.audit_testability(path)
    ]
    matrix = QATestGenerator.build_scenario_matrix(path) if args.matrix else []

    if args.json:
        emit_json({"file": path, "findings": dicts(findings), "scenarios": matrix})
        return 0

    ui.title(f"Testabilidad de {rel(path)}")
    show_findings(findings, args.limit, empty="No se detectaron impedimentos para probar este módulo.")
    if args.matrix:
        ui.section(f"Escenarios de prueba sugeridos ({len(matrix)})")
        rows = [
            (s.get("target", ""), s.get("category", "").strip("[]"), f"{s.get('scenario', '')}: {s.get('expected', '')}")
            for s in (matrix if args.limit <= 0 else matrix[: args.limit])
        ]
        ui.table(["Función", "Categoría", "Escenario y resultado esperado"], rows)
        if args.limit > 0 and len(matrix) > args.limit:
            ui.hint(f"  ... y {len(matrix) - args.limit} más. Usa --limit 0 para verlos todos.")
    else:
        ui.out()
        ui.hint("Añade --matrix para ver los escenarios de prueba sugeridos.")
    ui.hint(f"Para generar la suite: agentes generate tests --source {rel(path)}")
    return 0


def _schema_from_json(node: Any, where: str = "esquema") -> Any:
    if isinstance(node, dict):
        return {key: _schema_from_json(value, f"{where}.{key}") for key, value in node.items()}
    if isinstance(node, list):
        if len(node) != 1:
            raise CliError(f"En {where}, una lista debe declarar un solo tipo, por ejemplo [\"str\"].")
        return [_schema_from_json(node[0], f"{where}[]")]
    if isinstance(node, str) and node.lower() in _SCHEMA_TYPES:
        return _SCHEMA_TYPES[node.lower()]
    raise CliError(f"Tipo no reconocido en {where}: {node!r}.", "Tipos admitidos: str, int, float, bool, list y dict.")


def _parse_contract_inputs(args: argparse.Namespace) -> Tuple[Any, Dict[str, str], Any]:
    schema = None
    if args.schema:
        schema_path = require_path(args.schema, "file")
        try:
            with open(schema_path, "r", encoding="utf-8") as fh:
                schema = _schema_from_json(json.load(fh))
        except json.JSONDecodeError as exc:
            raise CliError(f"{args.schema} no es JSON válido: {exc}") from exc

    headers: Dict[str, str] = {}
    for raw in args.header or []:
        if ":" not in raw:
            raise CliError(f"Cabecera mal formada: {raw!r}.", "Usa el formato 'Nombre: valor'.")
        name, value = raw.split(":", 1)
        headers[name.strip()] = value.strip()

    body = None
    if args.body:
        try:
            body = json.loads(args.body)
        except json.JSONDecodeError:
            body = args.body
    return schema, headers, body


def cmd_contract(args: argparse.Namespace) -> int:
    """Valida estado HTTP, esquema JSON y latencia de un endpoint."""
    from ..qa.api_contract_testing import APIContractTester

    if not re.match(r"^https?://", args.url, re.IGNORECASE):
        raise CliError("La URL debe empezar por http:// o https://.")
    schema, headers, body = _parse_contract_inputs(args)

    result = APIContractTester.request_and_validate(
        args.url, method=args.method, headers=headers or None, body=body,
        expected_status=args.status, expected_schema=schema, max_sla_ms=args.max_ms,
        timeout=args.timeout, reject_extra_keys=args.strict,
    )
    code = 0 if result.get("passed") else 1
    if args.json:
        emit_json(result)
        return code

    ui.title(f"Contrato de {args.method.upper()} {args.url}")
    ui.out(f"Tiempo de respuesta: {result.get('elapsed_ms')} ms")
    ui.out()
    rows = []
    for name, status, detail in result.get("assertions", []):
        good = str(status).upper() == "OK"
        rows.append((name, ("OK" if good else "FALLO", "green" if good else "red"), detail))
    ui.table(["Comprobación", "Estado", "Detalle"], rows)
    ui.out()
    if code == 0:
        ui.ok("El endpoint cumple el contrato.")
    else:
        ui.fail("El endpoint no cumple el contrato.")
    return code
