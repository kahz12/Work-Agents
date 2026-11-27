"""
QA commands: test, testability and contract.
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
    ui.section("Failing tests")
    for item in failure_details:
        trace = str(item["traceback"]).strip()
        ui.out(f"  {ui.style(item['test'], 'bold')}")
        if verbose:
            for line in trace.splitlines():
                ui.out(f"    {line}")
        else:
            ui.out(f"    {ui.style(trace.splitlines()[-1] if trace else '', 'red')}")
    if not verbose:
        ui.hint("  Add --verbose to see the full tracebacks.")


def cmd_test(args: argparse.Namespace) -> int:
    """Run a unittest suite and assess its quality and estimated coverage."""
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

    ui.title(f"Tests in {rel(path)}")
    ui.kv([
        ("Run", result["tests_run"]),
        ("Passed", result["passed"]),
        ("Failed", result["failures"]),
        ("Errors", result["errors"]),
        ("Skipped", result["skipped"]),
        ("Pass rate", f"{result['pass_rate_percentage']}%"),
        ("Duration", f"{result['duration_seconds']} s"),
    ], indent=0)

    if result["tests_run"] == 0:
        ui.out()
        ui.warn("No unittest tests were found. If this is a pytest suite, run it with 'pytest'.")

    _print_test_failures(result["failure_details"], args.verbose)

    if coverage.get("functions_total"):
        ui.section("Estimated coverage")
        ui.out(
            f"  {coverage['functions_tested']} of {coverage['functions_total']} public functions in "
            f"'{coverage.get('module')}' have at least one test ({coverage['coverage_percentage']}%)."
        )
        ui.hint("  This is an estimate based on names, not a measurement of executed lines.")

    q_findings = [
        Finding(path, line, level, f"[{rule}] {msg}", "TEST-QUALITY")
        for line, rule, level, msg in quality.get("findings", [])
    ]
    if q_findings:
        ui.section(f"Suite quality ({len(q_findings)}): {describe_counts(count_by_level(q_findings))}")
        ui.findings(visible(q_findings), limit=args.limit)

    ui.out()
    if code == 0:
        ui.ok("All tests pass.")
    elif failed:
        ui.fail(f"{failed} tests do not pass.")
    return code


def cmd_testability(args: argparse.Namespace) -> int:
    """Find what makes a module hard to test and suggest test scenarios."""
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

    ui.title(f"Testability of {rel(path)}")
    show_findings(findings, args.limit, empty="Nothing found that makes this module hard to test.")
    if args.matrix:
        ui.section(f"Suggested test scenarios ({len(matrix)})")
        rows = [
            (s.get("target", ""), s.get("category", "").strip("[]"), f"{s.get('scenario', '')}: {s.get('expected', '')}")
            for s in (matrix if args.limit <= 0 else matrix[: args.limit])
        ]
        ui.table(["Function", "Category", "Scenario and expected result"], rows)
        if args.limit > 0 and len(matrix) > args.limit:
            ui.hint(f"  ... and {len(matrix) - args.limit} more. Use --limit 0 to show them all.")
    else:
        ui.out()
        ui.hint("Add --matrix to see the suggested test scenarios.")
    ui.hint(f"To generate the suite: agentes generate tests --source {rel(path)}")
    return 0


def _schema_from_json(node: Any, where: str = "schema") -> Any:
    """Turn a JSON schema of type names ({"id": "int", "tags": ["str"]}) into Python types."""
    if isinstance(node, dict):
        return {key: _schema_from_json(value, f"{where}.{key}") for key, value in node.items()}
    if isinstance(node, list):
        if len(node) != 1:
            raise CliError(f"In {where}, a list must declare exactly one type, for example [\"str\"].")
        return [_schema_from_json(node[0], f"{where}[]")]
    if isinstance(node, str) and node.lower() in _SCHEMA_TYPES:
        return _SCHEMA_TYPES[node.lower()]
    raise CliError(f"Unrecognised type in {where}: {node!r}.", "Supported types: str, int, float, bool, list and dict.")


def _parse_contract_inputs(args: argparse.Namespace) -> Tuple[Any, Dict[str, str], Any]:
    schema = None
    if args.schema:
        schema_path = require_path(args.schema, "file")
        try:
            with open(schema_path, "r", encoding="utf-8") as fh:
                schema = _schema_from_json(json.load(fh))
        except json.JSONDecodeError as exc:
            raise CliError(f"{args.schema} is not valid JSON: {exc}") from exc

    headers: Dict[str, str] = {}
    for raw in args.header or []:
        if ":" not in raw:
            raise CliError(f"Malformed header: {raw!r}.", "Use the format 'Name: value'.")
        name, value = raw.split(":", 1)
        headers[name.strip()] = value.strip()

    body = None
    if args.body:
        try:
            body = json.loads(args.body)
        except json.JSONDecodeError:
            # Not JSON: send it verbatim as a plain-text body.
            body = args.body
    return schema, headers, body


def cmd_contract(args: argparse.Namespace) -> int:
    """Check an endpoint's HTTP status, JSON schema and latency."""
    from ..qa.api_contract_testing import APIContractTester

    if not re.match(r"^https?://", args.url, re.IGNORECASE):
        raise CliError("The URL must start with http:// or https://.")
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

    ui.title(f"Contract for {args.method.upper()} {args.url}")
    ui.out(f"Response time: {result.get('elapsed_ms')} ms")
    ui.out()
    rows = []
    for name, status, detail in result.get("assertions", []):
        good = str(status).upper() == "OK"
        rows.append((name, ("OK" if good else "FAILED", "green" if good else "red"), detail))
    ui.table(["Check", "Status", "Detail"], rows)
    ui.out()
    if code == 0:
        ui.ok("The endpoint honours the contract.")
    else:
        ui.fail("The endpoint does not honour the contract.")
    return code
