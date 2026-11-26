"""
Orquestador del pipeline.

Ejecuta las seis etapas sobre un archivo o directorio (análisis estático, secretos, métricas y
SOLID, OpenAPI, infraestructura y vulnerabilidades en dependencias), aplica la línea base y los
hallazgos silenciados en su línea, y escribe los informes JSON, HTML y SARIF.
"""
from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Set, Tuple

from . import audits, rules
from .baseline import Baseline
from .findings import blocking_count
from .reporting import (
    build_pipeline_report,
    ensure_reports_dir,
    findings_to_sarif,
    write_html_summary,
    write_json_report,
)
from .suppressions import InlineSuppressions

_EXCLUDED_DIRS = {
    ".git", "__pycache__", "reports", ".venv", "venv", "node_modules",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "build", "dist",
}
_SECRET_CONFIG_EXTS = {".env", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".sh", ".sql"}
_REPORT_FILENAMES = {"pipeline.json", "analyze.json", "openapi.json"}


def _should_skip_dir(dirpath: str, dirname: str, *, reports_abs: Optional[str] = None) -> bool:
    if dirname in _EXCLUDED_DIRS or dirname.endswith(".egg-info") or dirname.startswith(("venv", ".venv")):
        return True
    full = os.path.join(dirpath, dirname)
    if reports_abs is not None and os.path.abspath(full) == reports_abs:
        return True
    return os.path.isfile(os.path.join(full, "pyvenv.cfg"))


def _iter_python_files(target: str) -> List[str]:
    if os.path.isfile(target) and target.endswith(".py"):
        return [target]
    if os.path.isfile(target):
        return []
    files = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(dirpath, d)]
        for fn in filenames:
            if fn.endswith(".py"):
                files.append(os.path.join(dirpath, fn))
    return sorted(files)


def _is_secret_config_file(filename: str) -> bool:
    if filename in _REPORT_FILENAMES or filename.endswith(".sarif"):
        return False
    if filename == ".env" or filename.startswith(".env."):
        return True
    _, ext = os.path.splitext(filename)
    return ext.lower() in _SECRET_CONFIG_EXTS


def _iter_secret_scan_files(target: str, py_scanned: List[str], *, reports_dir: Optional[str] = None) -> List[str]:
    """Combina los .py escaneados con archivos de configuración susceptibles de contener secretos."""
    extra_files: List[str] = []
    seen = set(py_scanned)
    reports_abs = os.path.abspath(reports_dir) if reports_dir else None

    if os.path.isfile(target):
        if target not in seen and _is_secret_config_file(os.path.basename(target)):
            extra_files.append(target)
        return list(py_scanned) + extra_files

    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(dirpath, d, reports_abs=reports_abs)]
        for fn in sorted(filenames):
            if _is_secret_config_file(fn):
                fp = os.path.join(dirpath, fn)
                if fp not in seen:
                    seen.add(fp)
                    extra_files.append(fp)

    return list(py_scanned) + sorted(extra_files)


def _is_infra_file(fn: str) -> bool:
    if fn in _REPORT_FILENAMES or fn.endswith(".sarif"):
        return False
    return (
        fn == "Dockerfile"
        or fn.startswith("Dockerfile.")
        or fn.endswith(".dockerfile")
        or fn.endswith(".service")
        or (fn.startswith("requirements") and fn.endswith(".txt"))
        or fn == "package.json"
        or fn.endswith((".yml", ".yaml"))
    )


def _is_helm_template(dirpath: str, fn: str) -> bool:
    return (
        fn.endswith((".yml", ".yaml"))
        and os.path.basename(dirpath) == "templates"
        and os.path.isfile(os.path.join(os.path.dirname(dirpath), "Chart.yaml"))
    )


def _iter_infra_files(target: str, *, reports_dir: Optional[str] = None) -> List[str]:
    if os.path.isfile(target):
        return [target] if _is_infra_file(os.path.basename(target)) else []

    files: List[str] = []
    reports_abs = os.path.abspath(reports_dir) if reports_dir else None
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(dirpath, d, reports_abs=reports_abs)]
        for fn in sorted(filenames):
            if _is_infra_file(fn) and not _is_helm_template(dirpath, fn):
                files.append(os.path.join(dirpath, fn))
    return sorted(files)


def _iter_dependency_manifests(target: str, *, reports_dir: Optional[str] = None) -> List[str]:
    """requirements*.txt, package.json y archivos de bloqueo (package-lock, poetry.lock, Pipfile.lock)."""
    from ..quality.vulnerabilities import manifest_reader

    if os.path.isfile(target):
        return [target] if manifest_reader(os.path.basename(target)) else []
    files: List[str] = []
    reports_abs = os.path.abspath(reports_dir) if reports_dir else None
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(dirpath, d, reports_abs=reports_abs)]
        files.extend(os.path.join(dirpath, fn) for fn in filenames if manifest_reader(fn))
    return sorted(files)


def dependency_vulnerability_stage(
    target: str,
    *,
    fail_on_high: bool = True,
    reports_dir: Optional[str] = None,
    check: Optional[bool] = None,
    keep: Optional[Callable[[List[Dict[str, Any]]], List[Dict[str, Any]]]] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Etapa de vulnerabilidades conocidas (OSV). Devuelve (etapa, hallazgos).

    check=None consulta OSV salvo con AGENTES_OFFLINE=1. Si no hay conexión, la etapa queda
    como "skipped" y no hace fallar el pipeline: no haber podido comprobar no es un hallazgo.
    """
    from ..quality import vulnerabilities
    from ..quality.package_index import is_offline

    manifests = _iter_dependency_manifests(target, reports_dir=reports_dir)
    root = target if os.path.isdir(target) else os.path.dirname(target)
    environments = vulnerabilities.find_environments(root) if os.path.isdir(target) else []
    stage: Dict[str, Any] = {
        "name": "dependency_vulns", "manifests": len(manifests),
        "environments": [os.path.relpath(e, root) for e in environments], "findings_count": 0,
    }
    if check is None:
        check = not is_offline()
    if not manifests and not environments:
        stage.update(status="ok", summary="sin manifiestos de dependencias ni entornos instalados")
        return stage, []
    if not check:
        stage.update(status="skipped", summary=f"omitida: modo sin conexión · {len(manifests)} manifiestos sin comprobar")
        return stage, []

    result = vulnerabilities.scan(manifests, environments=environments, root=root)
    if result.error:
        stage.update(status="skipped", summary=f"omitida: {result.error}")
        return stage, []
    if result.unchecked:
        # Decir "0 vulnerabilidades" sin haber comprobado nada daría una falsa sensación de seguridad.
        stage.update(
            status="skipped",
            summary=(f"sin comprobar: ninguna dependencia con versión exacta ni entorno instalado "
                     f"({result.unpinned} declaradas con rangos). Usa un archivo de bloqueo o un .venv en el proyecto"),
            dependencies_checked=0, dependencies_unpinned=result.unpinned,
        )
        return stage, []
    items = [f.to_dict() for f in result.findings]
    if keep is not None:
        items = keep(items)
    high = blocking_count(items)
    parts = [f"{len(items)} vulnerabilidades ({high} altas/críticas) en {result.checked} paquetes"]
    if result.installed:
        parts.append(f"{result.installed} instalados en {', '.join(stage['environments'])}")
    elif result.unpinned:
        parts.append(f"{result.unpinned} sin versión exacta (no comprobables)")
    if result.blocked_fixes:
        parts.append(f"{len(result.blocked_fixes)} restricciones impiden instalar la corrección")
    stage.update(
        status="fail" if (fail_on_high and high) else "ok",
        summary=" · ".join(parts),
        findings_count=len(items),
        dependencies_checked=result.checked,
        dependencies_unpinned=result.unpinned,
        installed_packages=result.installed,
        blocked_fixes=[{"package": n, "constraint": c, "file": os.path.relpath(f, root), "fixed": v}
                       for n, c, f, v in result.blocked_fixes],
    )
    return stage, items


def audit_infra_and_deps(
    target: str,
    *,
    agents_root: Optional[str] = None,
    reports_dir: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Audita Dockerfiles, unidades systemd, requirements*.txt, package.json y YAML/K8s.

    agents_root se conserva por compatibilidad y no se usa.
    """
    infra_files = _iter_infra_files(target, reports_dir=reports_dir)
    findings: List[Dict[str, Any]] = []
    for fp in infra_files:
        kind = audits.detect_kind(fp)
        if kind in audits.INFRA_KINDS:
            findings.extend(f.to_dict() for f in audits.audit_file(fp, kind))
    return findings, len(infra_files)


# Etapas cuyo fallo hace fallar el pipeline. Métricas y documentación informan, pero no bloquean.
_GATING_STAGES = frozenset({"quality_sast", "defensive_secrets", "infra_and_deps", "dependency_vulns"})


class _PipelineRun(NamedTuple):
    """Lo que comparten las etapas de una ejecución del pipeline."""

    target: str
    root: str
    reports_dir: str
    py_files: List[str]
    scanned: List[str]
    max_files: Optional[int]
    fail_on_high: bool
    accepted: Optional[Baseline]
    inline: InlineSuppressions

    def keep(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Quita los hallazgos silenciados en su línea y después los aceptados en la línea base.
        Tiene estado: el orden de llamada cuenta.
        """
        items = self.inline.filter(items)
        return self.accepted.filter(items) if self.accepted else list(items)

    @property
    def skipped(self) -> int:
        return len(self.py_files) - len(self.scanned)

    @property
    def truncated_note(self) -> str:
        return f" · {self.skipped} archivos NO escaneados (max_files={self.max_files})" if self.skipped else ""

    @property
    def coverage(self) -> Dict[str, int]:
        return {"files_scanned": len(self.scanned), "files_total": len(self.py_files), "files_skipped": self.skipped}


def run_pipeline(
    target: str,
    *,
    agents_root: Optional[str] = None,
    output_dir: Optional[str] = None,
    fail_on_high: bool = True,
    max_files: Optional[int] = None,
    prefer_bandit: bool = True,
    check_vulnerabilities: Optional[bool] = None,
    baseline: Optional[str] = None,
    exclude: Optional[List[str]] = None,
) -> Tuple[Dict[str, Any], int]:
    """
    Ejecuta pipeline DevSecOps sobre un directorio/archivo.
    agents_root se conserva por compatibilidad y no se usa.
    check_vulnerabilities=None consulta OSV salvo con AGENTES_OFFLINE=1.
    baseline: ruta a una línea base (ver agentes.common.baseline). Los hallazgos aceptados
    no cuentan para el estado de las etapas ni para el código de salida.
    exclude: archivos que no se analizan (la propia línea base contiene fragmentos de secretos).
    max_files limita cuántos .py se escanean (None = todos); si recorta, queda
    reflejado en el reporte en vez de perderse en silencio.
    prefer_bandit=False fuerza el motor AST: bandit lanza un subproceso por
    archivo, así que en árboles grandes domina el tiempo total.
    Retorna (report_dict, exit_code).
    """
    target = os.path.abspath(target)
    root = os.path.dirname(target) if os.path.isfile(target) else target
    accepted = Baseline.load(baseline, root) if baseline else None
    reports_dir = output_dir or ensure_reports_dir(root)
    os.makedirs(reports_dir, exist_ok=True)
    py_files = _iter_python_files(target)
    scanned = py_files if max_files is None else py_files[:max_files]
    run = _PipelineRun(target, root, reports_dir, py_files, scanned, max_files, fail_on_high, accepted,
                       InlineSuppressions())
    not_scanned = {os.path.abspath(p) for p in [*(exclude or []), *([baseline] if baseline else [])]}

    # El orden de las etapas importa: la línea base descuenta cada hallazgo aceptado una sola vez.
    sast, sast_raw, sast_findings = _sast_stage(run, prefer_bandit)
    secrets, secret_findings = _secrets_stage(run, not_scanned)
    metrics, design_findings = _metrics_stage(run, sast_raw)
    documentation = _documentation_stage(run)
    infra, infra_findings = _infra_stage(run)
    vulns, vuln_findings = dependency_vulnerability_stage(
        target, fail_on_high=fail_on_high, reports_dir=reports_dir, check=check_vulnerabilities, keep=run.keep,
    )
    stages = [sast, secrets, metrics, documentation, infra, vulns]
    all_findings = sast_findings + secret_findings + design_findings + infra_findings + vuln_findings
    exit_code = 1 if any(s["status"] == "fail" and s["name"] in _GATING_STAGES for s in stages) else 0

    report = build_pipeline_report(target, stages, exit_code=exit_code)
    report["python_files"] = len(py_files)
    report["files_scanned"] = len(scanned)
    report["files_skipped"] = run.skipped
    report["findings"] = rules.annotate(all_findings)
    report["findings_by_category"] = rules.count_by_category(all_findings)
    report["inline_suppressed"] = run.inline.suppressed
    if accepted is not None:
        report["baseline"] = {"file": baseline, "suppressed": accepted.suppressed, "unused": accepted.unused()}
    report["artifacts"] = _write_reports(report, run)
    return report, exit_code


def _sast_stage(run: _PipelineRun, prefer_bandit: bool) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Análisis estático en lote (Bandit + reglas AST). Devuelve (etapa, hallazgos sin filtrar, hallazgos)."""
    from ..quality.static_checker import StaticCodeAnalyzer

    sast_raw = [f.to_dict() for f in audits.sast(run.scanned, prefer_bandit=prefer_bandit)]
    findings = run.keep(sast_raw)
    high = blocking_count(findings)
    bandit_used = prefer_bandit and bool(run.scanned) and StaticCodeAnalyzer.bandit_command() is not None
    # Que falte Bandit no debe pasar desapercibido: el análisis queda solo con el motor AST.
    engine_note = " · sin Bandit (solo motor AST; instala el extra 'sast')" if prefer_bandit and run.scanned and not bandit_used else ""
    stage = {
        "name": "quality_sast",
        "status": "fail" if (run.fail_on_high and high) else "ok",
        "summary": (
            f"{len(findings)} hallazgos SAST ({high} altos/críticos) "
            f"en {len(run.scanned)} de {len(run.py_files)} archivos{run.truncated_note}{engine_note}"
        ),
        "findings_count": len(findings),
        **run.coverage,
        "engine": "bandit+ast" if bandit_used else "ast",
    }
    return stage, sast_raw, findings


def _secrets_stage(run: _PipelineRun, not_scanned: Set[str]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Secretos en el código Python y en la configuración (.env, YAML, JSON, INI...)."""
    secret_files = [f for f in _iter_secret_scan_files(run.target, run.scanned, reports_dir=run.reports_dir)
                    if os.path.abspath(f) not in not_scanned]
    extra_config_count = len(secret_files) - len(run.scanned)
    secret_findings: List[Dict[str, Any]] = []
    scan_errors: List[Dict[str, Any]] = []
    for fp in secret_files:
        for item in audits.scan_secrets(fp):
            # Un archivo que no se pudo leer no cuenta como limpio: va aparte y también hace fallar la etapa.
            (scan_errors if item.rule_id == "SECRET-SCAN-ERROR" else secret_findings).append(item.to_dict())
    secret_findings, scan_errors = run.keep(secret_findings), run.keep(scan_errors)

    extra_note = f" (+{extra_config_count} config)" if extra_config_count else ""
    stage = {
        "name": "defensive_secrets",
        "status": "fail" if (secret_findings or scan_errors) else "ok",
        "summary": (
            f"{len(secret_findings)} posibles secretos/config insegura "
            f"en {len(run.scanned)} de {len(run.py_files)} archivos{extra_note}{run.truncated_note}"
            + (f" · {len(scan_errors)} ilegibles" if scan_errors else "")
        ),
        "findings_count": len(secret_findings) + len(scan_errors),
        "scan_errors": len(scan_errors),
        "extra_config_files": extra_config_count,
        **run.coverage,
    }
    return stage, secret_findings + scan_errors


class _MetricsAccumulator:
    """Métricas, hallazgos SOLID y de rendimiento y recomendaciones situadas, archivo a archivo."""

    def __init__(self, root: str, inline: Optional[InlineSuppressions] = None) -> None:
        self.root = root
        # Lo silenciado en su línea no aparece como hallazgo ni genera recomendación.
        self.inline = inline or InlineSuppressions()
        self.total_lines = 0
        self.code_loc = 0
        self.comment_lines = 0
        self.func_details: List[Any] = []
        self.errors: List[str] = []
        self.solid_items: List[Dict[str, Any]] = []
        self.perf_findings: List[Tuple[int, str, str, str]] = []
        self.perf_items: List[Dict[str, Any]] = []
        self.located_recs: List[str] = []

    def add_file(self, fp: str) -> None:
        from ..refactor.code_metrics import CodeMetricsCalculator
        from ..refactor.refactor_suggester import RefactorSuggester
        from ..refactor.solid_checker import SOLIDChecker

        fm = CodeMetricsCalculator.calculate_file_metrics(fp)
        if "error" in fm:
            self.errors.append(f"{os.path.basename(fp)}: {fm['error']}")
            file_perf: List[Tuple[int, str, str, str]] = []
        else:
            file_perf = self._add_metrics(fp, fm)
        file_solid = self._add_solid(fp, SOLIDChecker.audit_file(fp))
        # Las recomendaciones de una línea concreta llevan su archivo: con varios archivos,
        # "Línea N" sola no dice de cuál es.
        self.located_recs.extend(RefactorSuggester.generate_recommendations(
            {"performance_findings": file_perf}, file_solid, praise_if_clean=False,
            location=os.path.relpath(fp, self.root).replace(os.sep, "/"),
        ))

    def _add_metrics(self, fp: str, fm: Dict[str, Any]) -> List[Tuple[int, str, str, str]]:
        self.total_lines += fm.get("total_lines", 0)
        self.code_loc += fm.get("code_loc", 0)
        self.comment_lines += fm.get("comment_lines", 0)
        self.func_details.extend(fm.get("function_details", []))
        file_perf = [(line, cat, level, msg) for line, cat, level, msg in fm.get("performance_findings", [])
                     if level != "ERROR" and not self.inline.silences(
                         {"file": fp, "line": line, "level": level, "message": f"[{cat}] {msg}", "rule_id": "PERF"})]
        self.perf_findings.extend(file_perf)
        # En el pipeline el rendimiento se registra como MEDIO: orienta, no bloquea.
        self.perf_items.extend({"file": fp, "line": line, "level": "MEDIO", "message": f"[{cat}] {msg}", "rule_id": "PERF"}
                               for line, cat, _, msg in file_perf)
        return file_perf

    def _add_solid(self, fp: str, solid: List[Tuple[int, str, str, str]]) -> List[Tuple[int, str, str, str]]:
        file_solid = [(line, principle, level, msg) for line, principle, level, msg in solid
                      if level != "ERROR" and not self.inline.silences(
                          {"file": fp, "line": line, "level": level, "message": f"[{principle}] {msg}",
                           "rule_id": f"SOLID-{principle}"})]
        self.solid_items.extend({"file": fp, "line": line, "level": level, "message": f"[{principle}] {msg}",
                                 "rule_id": f"SOLID-{principle}"} for line, principle, level, msg in file_solid)
        return file_solid

    def summary(self, files_analyzed: int) -> Dict[str, Any]:
        return {
            "files_analyzed": files_analyzed,
            "total_lines": self.total_lines,
            "code_loc": self.code_loc,
            "comment_lines": self.comment_lines,
            "comment_ratio": round((self.comment_lines / self.total_lines * 100), 2) if self.total_lines > 0 else 0.0,
            "functions_count": len(self.func_details),
            "avg_cyclomatic_complexity": _average([f[2] for f in self.func_details], default=1.0),
            "avg_cognitive_complexity": _average([f[3] for f in self.func_details], default=0.0),
            "performance_findings": self.perf_findings,
        }


def _average(values: List[float], *, default: float) -> float:
    return round(sum(values) / len(values), 2) if values else default


def _metrics_stage(run: _PipelineRun, sast_raw: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Complejidad, auditoría SOLID y rendimiento sobre todo lo analizado. Informa, no bloquea."""
    acc = _MetricsAccumulator(run.root, run.inline)
    for fp in run.scanned:
        acc.add_file(fp)

    # Lo que SOLID o rendimiento repiten del análisis estático (misma línea y tema) no se cuenta dos veces.
    solid_items = run.keep(audits.drop_covered(acc.solid_items, sast_raw))
    perf_items = run.keep(audits.drop_covered(acc.perf_items, sast_raw))
    summary = acc.summary(len(run.scanned))
    perf_note = f" · {len(perf_items)} de rendimiento" if perf_items else ""
    stage = {
        "name": "refactor_metrics",
        "status": "fail" if (run.scanned and acc.errors and len(acc.errors) == len(run.scanned)) else "ok",
        "summary": (
            f"avg_cyclomatic={summary['avg_cyclomatic_complexity']} "
            f"avg_cognitive={summary['avg_cognitive_complexity']} "
            f"· {len(run.scanned)} archivos · {len(solid_items)} hallazgos SOLID{perf_note}"
        ),
        "findings_count": len(solid_items) + len(perf_items),
        "files_analyzed": len(run.scanned),
        "metrics": summary,
        "recommendations": _metrics_recommendations(summary, acc, bool(run.scanned)),
        "errors": acc.errors,
    }
    return stage, solid_items + perf_items


def _metrics_recommendations(summary: Dict[str, Any], acc: _MetricsAccumulator, scanned: bool) -> List[str]:
    """Las de promedios se valoran sobre el conjunto; las de una línea concreta llevan su archivo."""
    from ..refactor.refactor_suggester import EXCELLENT, RefactorSuggester

    if not scanned:
        return []
    averages = {k: v for k, v in summary.items() if k != "performance_findings"}
    recommendations = list(dict.fromkeys(
        RefactorSuggester.generate_recommendations(averages, [], praise_if_clean=False) + acc.located_recs))
    # El elogio solo procede si nada tiene recomendaciones y todo se pudo analizar.
    if not recommendations and not acc.errors:
        return [EXCELLENT]
    return recommendations


def _documentation_stage(run: _PipelineRun) -> Dict[str, Any]:
    """Contrato OpenAPI combinando las rutas de todos los módulos analizados."""
    from ..docs.openapi_generator import OpenAPIGenerator

    frameworks = OpenAPIGenerator.detect_web_frameworks(run.scanned) if run.scanned else []
    if not frameworks:
        # Sin framework web, las funciones get_/post_ son helpers, no endpoints: no se inventa una API.
        return {
            "name": "documentation",
            "status": "skipped",
            "summary": "omitida: no se detectó un framework web (Flask, FastAPI, Django...)",
            "findings_count": 0,
            "files_analyzed": len(run.scanned),
            "errors": [],
        }
    spec = OpenAPIGenerator.generate_openapi_spec_from_files(run.scanned, title="Pipeline API", naming_convention=False)
    docs_errors = spec.get("x-agentes-errors", [])
    openapi_paths = len(spec.get("paths", {}))
    if openapi_paths:
        OpenAPIGenerator.export_spec_to_json(spec, os.path.join(run.reports_dir, "openapi.json"))
    return {
        "name": "documentation",
        "status": "fail" if docs_errors else "ok",
        "summary": (
            f"{', '.join(frameworks)}: {openapi_paths} rutas en {len(run.scanned)} archivos"
            + ("" if openapi_paths else " (sin rutas con decoradores reconocibles)")
            + (f" · {docs_errors[0]}" if docs_errors else "")
        ),
        "findings_count": 0,
        "files_analyzed": len(run.scanned),
        "frameworks": frameworks,
        "errors": docs_errors,
    }


def _infra_stage(run: _PipelineRun) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Dockerfiles, unidades systemd, dependencias declaradas y YAML del proyecto."""
    infra_findings, infra_files_count = audit_infra_and_deps(run.target, reports_dir=run.reports_dir)
    infra_findings = run.keep(infra_findings)
    infra_high = blocking_count(infra_findings)
    stage = {
        "name": "infra_and_deps",
        "status": "fail" if (run.fail_on_high and infra_high) else "ok",
        "summary": (
            f"{len(infra_findings)} hallazgos ({infra_high} altos/críticos) "
            f"en {infra_files_count} archivos de infra/deps/YAML"
        ),
        "findings_count": len(infra_findings),
        "files_scanned": infra_files_count,
    }
    return stage, infra_findings


def _write_reports(report: Dict[str, Any], run: _PipelineRun) -> Dict[str, str]:
    """Escribe pipeline.json, pipeline.html y pipeline.sarif. El JSON se reescribe con sus rutas."""
    json_path = write_json_report(report, os.path.join(run.reports_dir, "pipeline.json"))
    html_path = write_html_summary(report, os.path.join(run.reports_dir, "pipeline.html"))
    sarif_path = findings_to_sarif(
        "AGENTES-Pipeline",
        report["findings"],
        os.path.join(run.reports_dir, "pipeline.sarif"),
        base_dir=run.root,
    )
    artifacts = {"json": json_path, "html": html_path, "sarif": sarif_path}
    report["artifacts"] = artifacts
    write_json_report(report, json_path)
    return artifacts
