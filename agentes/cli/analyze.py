"""
Comandos CLI de análisis: pipeline, analyze, secrets, vulns, audit y metrics.
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
    """Ejecuta la auditoría completa de 6 etapas y genera informes HTML/JSON/SARIF."""
    from ..common.orchestrator import run_pipeline

    target = require_path(args.path)
    if args.baseline and args.write_baseline:
        raise CliError("--baseline y --write-baseline no se pueden usar a la vez.")
    if args.baseline:
        require_path(args.baseline, "file")
    if not args.json:
        ui.hint(f"Analizando {rel(target)} ...")
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
    except ValueError as exc:  # línea base ilegible o con otro formato
        raise CliError(str(exc)) from exc

    if args.write_baseline:
        from ..common.baseline import write_baseline

        root = os.path.dirname(target) if os.path.isfile(target) else target
        saved, skipped = write_baseline(args.write_baseline, report.get("findings", []), root, version=__version__)
        ui.ok(f"Línea base escrita en {rel(args.write_baseline)}: {saved} hallazgos aceptados.")
        ui.hint(f"Los {skipped} hallazgos medios o bajos no se guardan porque no hacen fallar el pipeline.")
        ui.hint("Revisa el archivo antes de versionarlo: todo lo que contiene dejará de hacer fallar el análisis.")
        return 0
    if args.json:
        emit_json(report)
        return code

    _render_pipeline_summary(target, report, code, args.limit)
    return code


def _render_pipeline_summary(target: str, report: Dict[str, Any], code: int, limit: int) -> None:
    ui.title(f"Auditoría de {rel(target)}")
    rows = []
    for stage in report.get("stages", []):
        rows.append((
            STAGE_LABELS.get(stage["name"], stage["name"]),
            STATUS_LABELS.get(stage.get("status"), (str(stage.get("status")), "yellow")),
            stage.get("summary", ""),
        ))
    ui.out()
    ui.table(["Etapa", "Estado", "Resumen"], rows)

    accepted = report.get("baseline")
    if accepted:
        ui.out()
        ui.hint(f"Línea base {rel(accepted['file'])}: {accepted['suppressed']} hallazgos aceptados no cuentan.")
        if accepted.get("unused"):
            ui.hint(f"  {accepted['unused']} entradas ya no aparecen: regenera la línea base para retirarlas.")

    if report.get("inline_suppressed"):
        ui.out()
        show_inline_note(report["inline_suppressed"])

    skipped = report.get("files_skipped") or 0
    if skipped:
        ui.out()
        ui.warn(f"{skipped} archivos .py quedaron fuera por --max-files.")

    findings = report.get("findings", [])
    if visible(findings):
        show_findings(findings, limit, security_checked=True)

    arts = report.get("artifacts", {})
    ui.section("Informes")
    pairs = [("HTML", rel(arts.get("html", ""))), ("JSON", rel(arts.get("json", ""))), ("SARIF", rel(arts.get("sarif", "")))]
    openapi = os.path.join(os.path.dirname(arts.get("json", "")), "openapi.json")
    if os.path.isfile(openapi):
        pairs.append(("OpenAPI", rel(openapi)))
    ui.kv(pairs)

    ui.out()
    if code == 0:
        ui.ok("Sin hallazgos bloqueantes.")
    else:
        ui.fail("Hay hallazgos bloqueantes (código de salida 1).")
        ui.hint(f"Abre {rel(arts.get('html', ''))} en el navegador para ver el detalle.")


def cmd_analyze(args: argparse.Namespace) -> int:
    """Ejecuta análisis estático de Python, infraestructura y dependencias."""
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

    ui.title(f"Análisis estático de {rel(target)}")
    ui.out(f"Archivos: {len(files) + infra_count} · Hallazgos: {len(findings)}")
    ui.out(f"Vulnerabilidades en dependencias: {vuln_stage['summary']}")
    show_findings(findings, args.limit, security_checked=True)
    show_inline_note(silenced)
    ui.section("Informes")
    ui.kv([("JSON", rel(json_path)), ("SARIF", rel(sarif_path))])
    if high and not args.fail_on_high:
        ui.out()
        ui.hint("Para que el comando falle con hallazgos altos o críticos, añade --fail-on-high.")
    return code


def cmd_secrets(args: argparse.Namespace) -> int:
    """Busca claves, tokens y credenciales incrustadas en código y configuración."""
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

    ui.title(f"Búsqueda de secretos en {rel(target)}")
    ui.out(f"Archivos revisados: {len(files)}")
    show_findings(findings, args.limit, empty="No se encontraron secretos.")
    show_inline_note(silenced)
    if findings:
        ui.out()
        ui.hint("Los valores se muestran enmascarados. Si un secreto llegó a publicarse, rótalo además de borrarlo.")
    return code


def _audit_headers(url: str) -> List[Finding]:
    req = urllib.request.Request(url, headers={"User-Agent": f"agentes-cli/{__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:  # noqa: S310 - el esquema se valida antes
            headers = dict(resp.headers.items())
    except urllib.error.HTTPError as exc:
        headers = dict(exc.headers.items()) if exc.headers else {}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise CliError(f"No se pudo conectar con {url}: {exc}") from exc
    return audits.audit_http_headers(url, headers)


def _audit_directory(target: str) -> Tuple[List[Finding], int]:
    """Infraestructura y dependencias como en el pipeline, más los .env y logs del árbol."""
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
            raise CliError("La auditoría de cabeceras necesita una URL http:// o https://.")
        return _audit_headers(target), 1, "cabeceras HTTP", target

    full = require_path(target)
    shown_target = rel(full)
    if os.path.isdir(full):
        if type_arg != "auto":
            raise CliError("--type solo se aplica a un archivo. En un directorio se detecta cada archivo por su nombre.")
        findings, count = _audit_directory(full)
        return findings, count, "infraestructura, dependencias, .env y logs", shown_target

    kind = type_arg if type_arg != "auto" else audits.detect_kind(full)
    if kind is None:
        raise CliError(
            f"No sé qué tipo de archivo es {target}.",
            "Indícalo con --type: " + ", ".join(audits.AUDIT_KINDS) + ". Para código Python usa 'agentes analyze'.",
        )
    return audits.audit_file(full, kind), 1, kind, shown_target


def cmd_audit(args: argparse.Namespace) -> int:
    """Audita un archivo de configuración/infraestructura, directorio o cabeceras HTTP."""
    findings, count, label, shown_target = _resolve_audit_target(args.target, args.type)
    findings, silenced = drop_inline(findings)
    code = 1 if blocking_count(findings) else 0

    if args.json:
        emit_json({"target": args.target, "kind": label, "files": count, "findings": dicts(findings),
                   "inline_suppressed": silenced})
        return code

    ui.title(f"Auditoría de {shown_target}")
    ui.out(f"Tipo: {label} · Elementos revisados: {count}")
    show_findings(findings, args.limit)
    show_inline_note(silenced)
    return code


def _vuln_rows(findings: List[Finding]) -> None:
    show_findings(findings, 0, empty="Ninguna vulnerabilidad conocida.")


def cmd_vulns(args: argparse.Namespace) -> int:
    """Consulta OSV para detectar vulnerabilidades conocidas en dependencias declaradas o instaladas."""
    from ..common.orchestrator import _iter_dependency_manifests
    from ..quality import vulnerabilities
    from ..quality.package_index import is_offline

    target = require_path(args.path)
    root = target if os.path.isdir(target) else os.path.dirname(target)
    manifests = _iter_dependency_manifests(target)
    environments = vulnerabilities.find_environments(root) if os.path.isdir(target) else []
    if not manifests and not environments:
        raise CliError(
            f"No hay manifiestos de dependencias ni entornos instalados en {args.path}.",
            "Se leen requirements*.txt, pyproject.toml, package.json, archivos de bloqueo y el .venv del proyecto.",
        )
    if is_offline():
        raise CliError(
            "Este comando necesita consultar OSV y está activo el modo sin conexión.",
            "Quita --offline o la variable AGENTES_OFFLINE.",
        )
    if not args.json:
        ui.hint(f"Consultando OSV ({len(manifests)} manifiestos, {len(environments)} entornos instalados) ...")
    result = vulnerabilities.scan(manifests, environments=environments, root=root)
    if result.error:
        raise CliError(f"No se pudo consultar OSV: {result.error}", "Comprueba la conexión o repite más tarde.")
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

    ui.title(f"Vulnerabilidades en las dependencias de {rel(target)}")
    pairs: List[Tuple[str, Any]] = [("Manifiestos", ", ".join(rel(m) for m in manifests) or "ninguno")]
    if environments:
        pairs.append(("Entornos instalados", ", ".join(f"{rel(e)} ({result.installed} paquetes)" for e in environments)))
    pairs.append(("Paquetes comprobados", result.checked))
    ui.kv(pairs, indent=0)
    if result.unchecked:
        ui.out()
        ui.warn(f"No se ha comprobado ninguna dependencia: las {result.unpinned} declaradas usan rangos y no hay "
                "un entorno instalado ni un archivo de bloqueo con versiones exactas.")
        ui.hint("Crea el .venv del proyecto o un archivo de bloqueo (poetry.lock, Pipfile.lock, requirements fijado) "
                "y repite.")
        return 0
    if result.unpinned and not environments:
        ui.warn(f"{result.unpinned} dependencias sin versión exacta no se pueden comprobar. "
                "Fíjalas con 'agentes fix' o usa un archivo de bloqueo.")
    show_findings(vuln_findings, args.limit, empty="Ninguna vulnerabilidad conocida.")
    show_inline_note(silenced)
    if result.blocked_fixes:
        ui.section("Restricciones que impiden instalar la corrección")
        for name, spec, file, fixed in result.blocked_fixes:
            ui.bullet(f"{name}{spec} en {rel(file)}: la corrección necesita {fixed}. Amplía el límite superior.")
    if vuln_findings:
        ui.out()
        ui.hint("Actualiza cada paquete al menos a la versión corregida que se indica.")
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
        # Lo silenciado en su línea no aparece como hallazgo ni genera recomendación.
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

    ui.title(f"Métricas de {rel(target)}")
    ui.kv([
        ("Archivos", totals["files"]),
        ("Líneas de código", totals["code_loc"]),
        ("Funciones", totals["functions"]),
        ("Complejidad ciclomática media", totals["avg_cyclomatic"]),
        ("Complejidad cognitiva media", totals["avg_cognitive"]),
    ], indent=0)

    if len(per_file) > 1:
        ui.section("Archivos con mayor complejidad")
        ranked = sorted(per_file, key=lambda f: -f["avg_cyclomatic"])[:limit]
        ui.table(
            ["Líneas", "Func.", "Ciclom.", "Cognit.", "Archivo"],
            [(f["code_loc"], f["functions"], f["avg_cyclomatic"], f["avg_cognitive"], rel(f["file"])) for f in ranked],
            right=(0, 1, 2, 3),
        )

    if functions:
        ui.section("Funciones más complejas")
        rows = []
        for name, fp, line, cyc, cog in (functions[:10] if limit else functions):
            color = "red" if cyc > 10 else ("yellow" if cyc > 5 else "green")
            rows.append(((cyc, color), cog, f"{name}  ({rel(fp)}:{line})"))
        ui.table(["Ciclom.", "Cognit.", "Función"], rows, right=(0, 1))
        ui.hint("  Referencia: hasta 5 es simple, de 6 a 10 conviene vigilarla, más de 10 pide dividirla.")

    if visible(findings):
        show_findings(findings, limit_arg)
    show_inline_note(data["inline_suppressed"])
    if recommendations:
        ui.section("Recomendaciones")
        for rec in recommendations[:limit]:
            ui.bullet(rec)
        if limit and len(recommendations) > limit:
            ui.hint(f"  ... y {len(recommendations) - limit} más. Usa --limit 0 para verlas todas.")


def cmd_metrics(args: argparse.Namespace) -> int:
    """Calcula métricas de complejidad, SOLID, rendimiento y recomendaciones de refactor."""
    target = require_path(args.path)
    files = python_files(target)
    if not files:
        raise CliError(f"No hay archivos .py en {args.path}.")

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
