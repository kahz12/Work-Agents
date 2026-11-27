"""
Analysis commands: pipeline, analyze, secrets, vulns, audit and metrics.
"""
from __future__ import annotations

import argparse
import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple

from .. import __version__
from ..common import audits, rules
from ..common.console import ui
from ..common.findings import Finding, blocking_count
from .common import (
    STAGE_LABELS,
    STATUS_LABELS,
    CliError,
    dicts,
    drop_inline,
    emit_json,
    python_files,
    rel,
    require_path,
    show_findings,
    show_inline_note,
    visible,
)

AUDIT_TYPES = ["auto", *audits.AUDIT_KINDS, "headers"]


def cmd_pipeline(args: argparse.Namespace) -> int:
    """Run the full six-stage audit and write the HTML/JSON/SARIF reports."""
    from ..common.orchestrator import run_pipeline

    target = require_path(args.path)
    if args.baseline and args.write_baseline:
        raise CliError("--baseline and --write-baseline cannot be used together.")
    if args.baseline:
        require_path(args.baseline, "file")
    if not args.json:
        ui.hint(f"Analysing {rel(target)} ...")
    try:
        report, code = run_pipeline(
            target,
            output_dir=args.output,
            fail_on_high=not args.no_fail,
            max_files=args.max_files,
            prefer_bandit=not args.no_bandit,
            check_vulnerabilities=False if args.offline else None,
            baseline=args.baseline,
            exclude=[args.write_baseline] if args.write_baseline else None,
        )
    except ValueError as exc:  # the baseline is unreadable or not in our format
        raise CliError(str(exc)) from exc

    if args.write_baseline:
        from ..common.baseline import write_baseline

        root = os.path.dirname(target) if os.path.isfile(target) else target
        saved, skipped = write_baseline(args.write_baseline, report.get("findings", []), root, version=__version__)
        ui.ok(f"Baseline written to {rel(args.write_baseline)}: {saved} findings accepted.")
        ui.hint(f"The {skipped} medium or low findings are not stored, because they never fail the pipeline.")
        ui.hint("Review the file before committing it: everything it lists will stop failing the analysis.")
        return 0
    if args.json:
        emit_json(report)
        return code

    _render_pipeline_summary(target, report, code, args.limit)
    return code


def _render_pipeline_summary(target: str, report: Dict[str, Any], code: int, limit: int) -> None:
    ui.title(f"Audit of {rel(target)}")
    rows = []
    for stage in report.get("stages", []):
        rows.append((
            STAGE_LABELS.get(stage["name"], stage["name"]),
            STATUS_LABELS.get(stage.get("status"), (str(stage.get("status")), "yellow")),
            stage.get("summary", ""),
        ))
    ui.out()
    ui.table(["Stage", "Status", "Summary"], rows)

    accepted = report.get("baseline")
    if accepted:
        ui.out()
        ui.hint(f"Baseline {rel(accepted['file'])}: {accepted['suppressed']} accepted findings are not counted.")
        if accepted.get("unused"):
            ui.hint(f"  {accepted['unused']} entries no longer match anything: regenerate the baseline to drop them.")

    if report.get("inline_suppressed"):
        ui.out()
        show_inline_note(report["inline_suppressed"])

    skipped = report.get("files_skipped") or 0
    if skipped:
        ui.out()
        ui.warn(f"{skipped} .py files were left out because of --max-files.")

    findings = report.get("findings", [])
    if visible(findings):
        show_findings(findings, limit, security_checked=True)

    arts = report.get("artifacts", {})
    ui.section("Reports")
    pairs = [("HTML", rel(arts.get("html", ""))), ("JSON", rel(arts.get("json", ""))), ("SARIF", rel(arts.get("sarif", "")))]
    openapi = os.path.join(os.path.dirname(arts.get("json", "")), "openapi.json")
    if os.path.isfile(openapi):
        pairs.append(("OpenAPI", rel(openapi)))
    ui.kv(pairs)

    ui.out()
    if code == 0:
        ui.ok("No blocking findings.")
    else:
        ui.fail("There are blocking findings (exit code 1).")
        ui.hint(f"Open {rel(arts.get('html', ''))} in a browser for the details.")


def cmd_analyze(args: argparse.Namespace) -> int:
    """Static analysis of Python code, infrastructure and dependencies, without the other pipeline stages."""
    from ..common.orchestrator import audit_infra_and_deps, dependency_vulnerability_stage
    from ..common.reporting import ensure_reports_dir, findings_to_sarif, write_json_report

    target = require_path(args.path)
    base_dir = os.path.dirname(target) if os.path.isfile(target) else target
    out_dir = args.output or ensure_reports_dir(base_dir)
    files = python_files(target)

    findings = dicts(audits.sast(files, prefer_bandit=not args.no_bandit))
    infra_findings, infra_count = audit_infra_and_deps(target, reports_dir=out_dir)
    findings.extend(infra_findings)
    vuln_stage, vuln_findings = dependency_vulnerability_stage(
        target, fail_on_high=args.fail_on_high, reports_dir=out_dir, check=False if args.offline else None,
    )
    findings.extend(vuln_findings)
    findings, silenced = drop_inline(findings)
    rules.annotate(findings)

    os.makedirs(out_dir, exist_ok=True)
    json_path = write_json_report({"target": target, "findings": findings}, os.path.join(out_dir, "analyze.json"))
    sarif_path = findings_to_sarif("AGENTES-Analyze", findings, os.path.join(out_dir, "analyze.sarif"), base_dir=base_dir)
    high = blocking_count(findings)
    code = 1 if (args.fail_on_high and high) else 0

    if args.json:
        emit_json({
            "target": target, "files": len(files) + infra_count, "findings": findings, "inline_suppressed": silenced,
            "vulnerability_check": vuln_stage, "artifacts": {"json": json_path, "sarif": sarif_path},
        })
        return code

    ui.title(f"Static analysis of {rel(target)}")
    ui.out(f"Files: {len(files) + infra_count} · Findings: {len(findings)}")
    ui.out(f"Dependency vulnerabilities: {vuln_stage['summary']}")
    show_findings(findings, args.limit, security_checked=True)
    show_inline_note(silenced)
    ui.section("Reports")
    ui.kv([("JSON", rel(json_path)), ("SARIF", rel(sarif_path))])
    if high and not args.fail_on_high:
        ui.out()
        ui.hint("To make the command fail on high or critical findings, add --fail-on-high.")
    return code


def cmd_secrets(args: argparse.Namespace) -> int:
    """Look for keys, tokens and credentials embedded in code and configuration."""
    from ..common.orchestrator import _iter_secret_scan_files

    target = require_path(args.path)
    files = [target] if os.path.isfile(target) else _iter_secret_scan_files(target, python_files(target))
    findings: List[Finding] = []
    for fp in files:
        findings.extend(audits.scan_secrets(fp))
    findings, silenced = drop_inline(findings)
    code = 1 if findings else 0

    if args.json:
        emit_json({"target": target, "files_scanned": len(files), "findings": dicts(findings),
                   "inline_suppressed": silenced})
        return code

    ui.title(f"Secret scan of {rel(target)}")
    ui.out(f"Files scanned: {len(files)}")
    show_findings(findings, args.limit, empty="No secrets found.")
    show_inline_note(silenced)
    if findings:
        ui.out()
        ui.hint("Values are shown masked. If a secret was ever published, rotate it as well as deleting it.")
    return code


def _audit_headers(url: str) -> List[Finding]:
    req = urllib.request.Request(url, headers={"User-Agent": f"agentes-cli/{__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:  # noqa: S310 - the caller only passes http(s) URLs
            headers = dict(resp.headers.items())
    except urllib.error.HTTPError as exc:
        headers = dict(exc.headers.items()) if exc.headers else {}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise CliError(f"Could not connect to {url}: {exc}") from exc
    return audits.audit_http_headers(url, headers)


def _audit_directory(target: str) -> Tuple[List[Finding], int]:
    """Infrastructure and dependencies as in the pipeline, plus every .env file and log in the tree."""
    from ..common.orchestrator import _should_skip_dir, audit_infra_and_deps

    infra, count = audit_infra_and_deps(target)
    findings = [Finding.from_dict(f) for f in infra]
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(dirpath, d)]
        for fn in sorted(filenames):
            kind = audits.detect_kind(fn)
            if kind in ("env", "logs"):
                findings.extend(audits.audit_file(os.path.join(dirpath, fn), kind))
                count += 1
    return findings, count


def _resolve_audit_target(target: str, type_arg: str) -> Tuple[List[Finding], int, str, str]:
    is_url = re.match(r"^https?://", target, re.IGNORECASE) is not None
    if is_url or type_arg == "headers":
        if not is_url:
            raise CliError("The headers audit needs an http:// or https:// URL.")
        return _audit_headers(target), 1, "HTTP headers", target

    full = require_path(target)
    shown_target = rel(full)
    if os.path.isdir(full):
        if type_arg != "auto":
            raise CliError("--type only applies to a single file. In a directory, each file's kind is inferred from its name.")
        findings, count = _audit_directory(full)
        return findings, count, "infrastructure, dependencies, .env and logs", shown_target

    kind = type_arg if type_arg != "auto" else audits.detect_kind(full)
    if kind is None:
        raise CliError(
            f"Cannot tell what kind of file {target} is.",
            "Pass it with --type: " + ", ".join(audits.AUDIT_KINDS) + ". For Python code, use 'agentes analyze'.",
        )
    return audits.audit_file(full, kind), 1, kind, shown_target


def cmd_audit(args: argparse.Namespace) -> int:
    """Audit a configuration/infrastructure file, a directory, or a URL's HTTP headers."""
    findings, count, label, shown_target = _resolve_audit_target(args.target, args.type)
    findings, silenced = drop_inline(findings)
    code = 1 if blocking_count(findings) else 0

    if args.json:
        emit_json({"target": args.target, "kind": label, "files": count, "findings": dicts(findings),
                   "inline_suppressed": silenced})
        return code

    ui.title(f"Audit of {shown_target}")
    ui.out(f"Kind: {label} · Items checked: {count}")
    show_findings(findings, args.limit)
    show_inline_note(silenced)
    return code


def _vuln_rows(findings: List[Finding]) -> None:
    show_findings(findings, 0, empty="No known vulnerabilities.")


def cmd_vulns(args: argparse.Namespace) -> int:
    """Query OSV for known vulnerabilities in declared or installed dependencies."""
    from ..common.orchestrator import _iter_dependency_manifests
    from ..quality import vulnerabilities
    from ..quality.package_index import is_offline

    target = require_path(args.path)
    root = target if os.path.isdir(target) else os.path.dirname(target)
    manifests = _iter_dependency_manifests(target)
    environments = vulnerabilities.find_environments(root) if os.path.isdir(target) else []
    if not manifests and not environments:
        raise CliError(
            f"No dependency manifests or installed environments in {args.path}.",
            "requirements*.txt, pyproject.toml, package.json, lock files and the project's .venv are read.",
        )
    if is_offline():
        raise CliError(
            "This command needs to query OSV, but offline mode is on.",
            "Remove --offline or unset AGENTES_OFFLINE.",
        )
    if not args.json:
        ui.hint(f"Querying OSV ({len(manifests)} manifests, {len(environments)} installed environments) ...")
    result = vulnerabilities.scan(manifests, environments=environments, root=root)
    if result.error:
        raise CliError(f"Could not query OSV: {result.error}", "Check the connection or try again later.")
    vuln_findings, silenced = drop_inline(result.findings)
    code = 1 if blocking_count(vuln_findings) else 0

    if args.json:
        emit_json({
            "target": target, "manifests": manifests, "environments": environments,
            "status": "unchecked" if result.unchecked else ("fail" if code else "ok"),
            "dependencies_checked": result.checked, "dependencies_unpinned": result.unpinned,
            "installed_packages": result.installed, "findings": dicts(vuln_findings), "inline_suppressed": silenced,
            "blocked_fixes": [{"package": n, "constraint": c, "file": f, "fixed": v} for n, c, f, v in result.blocked_fixes],
        })
        return code

    ui.title(f"Dependency vulnerabilities in {rel(target)}")
    pairs: List[Tuple[str, Any]] = [("Manifests", ", ".join(rel(m) for m in manifests) or "none")]
    if environments:
        pairs.append(("Installed environments", ", ".join(f"{rel(e)} ({result.installed} packages)" for e in environments)))
    pairs.append(("Packages checked", result.checked))
    ui.kv(pairs, indent=0)
    if result.unchecked:
        ui.out()
        ui.warn(f"No dependency was checked: all {result.unpinned} declared ones use ranges, and there is "
                "no installed environment or lock file with exact versions.")
        ui.hint("Create the project's .venv or a lock file (poetry.lock, Pipfile.lock, pinned requirements) "
                "and run it again.")
        return 0
    if result.unpinned and not environments:
        ui.warn(f"{result.unpinned} dependencies without an exact version cannot be checked. "
                "Pin them with 'agentes fix' or use a lock file.")
    show_findings(vuln_findings, args.limit, empty="No known vulnerabilities.")
    show_inline_note(silenced)
    if result.blocked_fixes:
        ui.section("Constraints that block installing the fix")
        for name, spec, file, fixed in result.blocked_fixes:
            ui.bullet(f"{name}{spec} in {rel(file)}: the fix needs {fixed}. Raise the upper bound.")
    if vuln_findings:
        ui.out()
        ui.hint("Upgrade each package to at least the fixed version shown.")
    return code


def _collect_metrics_data(files: List[str]) -> Dict[str, Any]:
    from ..common.suppressions import InlineSuppressions
    from ..refactor.code_metrics import CodeMetricsCalculator
    from ..refactor.refactor_suggester import EXCELLENT, RefactorSuggester
    from ..refactor.solid_checker import SOLIDChecker

    inline = InlineSuppressions()
    per_file: List[Dict[str, Any]] = []
    functions: List[Tuple[str, str, int, int, int]] = []
    findings: List[Finding] = []
    located: List[str] = []
    total_lines = comment_lines = 0

    for fp in files:
        metrics = CodeMetricsCalculator.calculate_file_metrics(fp)
        if metrics.get("error"):
            findings.append(Finding(fp, 0, "ERROR", metrics["error"], "METRICS"))
            continue
        total_lines += metrics["total_lines"]
        comment_lines += metrics["comment_lines"]
        # Anything suppressed on its line is neither reported nor turned into a recommendation.
        solid = [(line, principle, level, rec) for line, principle, level, rec in SOLIDChecker.audit_file(fp)
                 if not inline.silences(Finding(fp, line, level, f"[{principle}] {rec}", f"SOLID-{principle}"))]
        perf = [(line, category, level, rec) for line, category, level, rec in metrics["performance_findings"]
                if not inline.silences(Finding(fp, line, level, f"[{category}] {rec}", "PERF"))]
        per_file.append({
            "file": fp,
            "code_loc": metrics["code_loc"],
            "functions": metrics["functions_count"],
            "avg_cyclomatic": metrics["avg_cyclomatic_complexity"],
            "avg_cognitive": metrics["avg_cognitive_complexity"],
            "comment_ratio": metrics["comment_ratio"],
        })
        for name, line, cyc, cog in metrics["function_details"]:
            functions.append((name, fp, line, cyc, cog))
        for line, principle, level, rec in solid:
            findings.append(Finding(fp, line, level, f"[{principle}] {rec}", f"SOLID-{principle}"))
        for line, category, level, rec in perf:
            findings.append(Finding(fp, line, level, f"[{category}] {rec}", "PERF"))
        located.extend(RefactorSuggester.generate_recommendations(
            {"performance_findings": perf}, solid, praise_if_clean=False, location=rel(fp),
        ))

    total_funcs = sum(f["functions"] for f in per_file)
    totals = {
        "files": len(per_file),
        "code_loc": sum(f["code_loc"] for f in per_file),
        "functions": total_funcs,
        "avg_cyclomatic": round(sum(c[3] for c in functions) / total_funcs, 2) if total_funcs else 0.0,
        "avg_cognitive": round(sum(c[4] for c in functions) / total_funcs, 2) if total_funcs else 0.0,
    }
    overall = {
        "avg_cyclomatic_complexity": totals["avg_cyclomatic"],
        "avg_cognitive_complexity": totals["avg_cognitive"],
        "comment_ratio": round(comment_lines / total_lines * 100, 2) if total_lines else 0.0,
        "code_loc": totals["code_loc"],
    }
    recommendations = list(dict.fromkeys(
        RefactorSuggester.generate_recommendations(overall, [], praise_if_clean=False) + located
    ))
    if not recommendations and not findings:
        recommendations.append(EXCELLENT)
    functions.sort(key=lambda c: (-c[3], -c[4]))
    return {
        "totals": totals,
        "files": per_file,
        "functions": functions,
        "findings": findings,
        "recommendations": recommendations,
        "inline_suppressed": inline.suppressed,
    }


def _render_metrics_tables(target: str, data: Dict[str, Any], limit_arg: int) -> None:
    totals = data["totals"]
    per_file = data["files"]
    functions = data["functions"]
    findings = data["findings"]
    recommendations = data["recommendations"]
    limit = limit_arg if limit_arg > 0 else None

    ui.title(f"Metrics for {rel(target)}")
    ui.kv([
        ("Files", totals["files"]),
        ("Lines of code", totals["code_loc"]),
        ("Functions", totals["functions"]),
        ("Average cyclomatic complexity", totals["avg_cyclomatic"]),
        ("Average cognitive complexity", totals["avg_cognitive"]),
    ], indent=0)

    if len(per_file) > 1:
        ui.section("Most complex files")
        ranked = sorted(per_file, key=lambda f: -f["avg_cyclomatic"])[:limit]
        ui.table(
            ["Lines", "Funcs", "Cyclom.", "Cognit.", "File"],
            [(f["code_loc"], f["functions"], f["avg_cyclomatic"], f["avg_cognitive"], rel(f["file"])) for f in ranked],
            right=(0, 1, 2, 3),
        )

    if functions:
        ui.section("Most complex functions")
        rows = []
        for name, fp, line, cyc, cog in (functions[:10] if limit else functions):
            color = "red" if cyc > 10 else ("yellow" if cyc > 5 else "green")
            rows.append(((cyc, color), cog, f"{name}  ({rel(fp)}:{line})"))
        ui.table(["Cyclom.", "Cognit.", "Function"], rows, right=(0, 1))
        ui.hint("  Reference: up to 5 is simple, 6 to 10 is worth watching, above 10 calls for splitting it up.")

    if visible(findings):
        show_findings(findings, limit_arg)
    show_inline_note(data["inline_suppressed"])
    if recommendations:
        ui.section("Recommendations")
        for rec in recommendations[:limit]:
            ui.bullet(rec)
        if limit and len(recommendations) > limit:
            ui.hint(f"  ... and {len(recommendations) - limit} more. Use --limit 0 to show them all.")


def cmd_metrics(args: argparse.Namespace) -> int:
    """Complexity metrics, SOLID and performance findings, and refactoring advice."""
    target = require_path(args.path)
    files = python_files(target)
    if not files:
        raise CliError(f"No .py files in {args.path}.")

    data = _collect_metrics_data(files)
    if args.json:
        emit_json({
            "target": target,
            "totals": data["totals"],
            "files": data["files"],
            "functions": [
                {"name": n, "file": f, "line": ln, "cyclomatic": cy, "cognitive": co}
                for n, f, ln, cy, co in data["functions"]
            ],
            "findings": dicts(data["findings"]),
            "recommendations": data["recommendations"],
            "inline_suppressed": data["inline_suppressed"],
        })
        return 0

    _render_metrics_tables(target, data, args.limit)
    return 0
