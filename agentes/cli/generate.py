"""
Comandos CLI de generación y corrección: generate y fix.
"""
from __future__ import annotations

import argparse
import os
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..common.console import ui
from ..common.findings import Finding, blocking_count
from .common import (
    CliError,
    dicts,
    emit_json,
    ensure_parent,
    guard_overwrite,
    rel,
    require_path,
    require_python_file,
    show_findings,
)


def _gen_compose(args: argparse.Namespace, out: str) -> List[str]:
    from ..devops.docker_compose_generator import DockerComposeGenerator

    guard_overwrite(out, args.force)
    ensure_parent(out)
    DockerComposeGenerator.generate_compose_file(
        out, service_name=args.service, image=args.image, port=args.port, mem_limit=args.mem_limit, cpus=args.cpus,
    )
    return [out]


def _gen_helm(args: argparse.Namespace, out: str) -> List[str]:
    from ..devops.helm_generator import HelmGenerator

    guard_overwrite(os.path.join(out, "Chart.yaml"), args.force)
    HelmGenerator.generate_helm_chart(out, chart_name=args.service, image_repo=args.image, port=args.port)
    return [out]


def _gen_webserver(server: str) -> Callable[[argparse.Namespace, str], List[str]]:
    def handler(args: argparse.Namespace, out: str) -> List[str]:
        from ..hardening.webserver_hardening import WebServerHardening

        guard_overwrite(out, args.force)
        ensure_parent(out)
        build = WebServerHardening.generate_nginx_config if server == "nginx" else WebServerHardening.generate_caddy_config
        content = build(args.domain, args.csp) if args.csp else build(args.domain)
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(content)
        return [out]

    return handler


def _gen_dockerfile(args: argparse.Namespace, out: str) -> List[str]:
    from ..hardening.container_hardening import ContainerHardening

    guard_overwrite(out, args.force)
    ensure_parent(out)
    return [ContainerHardening.generate_hardened_dockerfile(out)]


def _gen_systemd(args: argparse.Namespace, out: str) -> List[str]:
    from ..hardening.service_hardening import ServiceHardening

    guard_overwrite(out, args.force)
    ensure_parent(out)
    return [ServiceHardening.generate_hardened_service(out)]


def _gen_k8s(args: argparse.Namespace, out: str) -> List[str]:
    from ..hardening.k8s_hardening import K8sHardening

    guard_overwrite(out, args.force)
    ensure_parent(out)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(K8sHardening.generate_hardened_pod_manifest(name=args.service, image=args.image))
    return [out]


def _gen_github(args: argparse.Namespace, out: str) -> List[str]:
    from ..devops.github_actions_generator import GitHubActionsGenerator

    guard_overwrite(out, args.force)
    return [GitHubActionsGenerator.generate_workflow(out)]


def _gen_gitlab(args: argparse.Namespace, out: str) -> List[str]:
    from ..devops.gitlab_ci_generator import GitLabCIGenerator

    guard_overwrite(out, args.force)
    return [GitLabCIGenerator.generate_ci_file(out)]


def _gen_linters(args: argparse.Namespace, out: str) -> List[str]:
    from ..quality.linter_config import LinterConfigGenerator

    os.makedirs(out, exist_ok=True)
    written: List[str] = []
    builders = [
        (".flake8", LinterConfigGenerator.generate_flake8_config),
        ("pyproject.toml", LinterConfigGenerator.generate_pyproject_toml),
        (".eslintrc.json", LinterConfigGenerator.generate_eslint_config),
    ]
    for name, build in builders:
        dest = os.path.join(out, name)
        if os.path.exists(dest) and not args.force:
            ui.warn(f"Se conserva {rel(dest)} porque ya existe. Usa --force para reemplazarlo.")
            continue
        written.append(build(out))
    return written


def _spec_from_source(args: argparse.Namespace) -> Dict[str, Any]:
    from ..docs.openapi_generator import OpenAPIGenerator

    source = require_python_file(args.source)
    spec = OpenAPIGenerator.generate_openapi_spec(source, title=args.service, naming_convention=args.naming_convention)
    errors = spec.get("x-agentes-errors") or []
    if errors:
        raise CliError(f"No se pudo leer {args.source}: {errors[0]}")
    if not spec.get("paths"):
        by_name = OpenAPIGenerator.generate_openapi_spec(source, naming_convention=True).get("paths", {})
        if by_name and not args.naming_convention:
            ui.warn(
                f"No hay rutas con decoradores de Flask o FastAPI, pero {len(by_name)} funciones siguen la "
                "convención get_/post_/put_/delete_. Si son endpoints, añade --naming-convention."
            )
        else:
            ui.warn("No se detectó ninguna ruta: el archivo no declara endpoints con decoradores de Flask o FastAPI.")
    return spec


def _gen_openapi(args: argparse.Namespace, out: str) -> List[str]:
    from ..docs.openapi_generator import OpenAPIGenerator

    spec = _spec_from_source(args)
    if out.endswith((".yaml", ".yml")):
        guard_overwrite(out, args.force)
        return [OpenAPIGenerator.export_spec_to_yaml(spec, out)]
    dest = out if out.endswith(".json") else os.path.join(out, "openapi.json")
    guard_overwrite(dest, args.force)
    return [OpenAPIGenerator.export_spec_to_json(spec, dest)]


def _gen_swagger(args: argparse.Namespace, out: str) -> List[str]:
    from ..docs.swagger_ui_generator import SwaggerUIGenerator

    spec = _spec_from_source(args)
    guard_overwrite(out, args.force)
    return [SwaggerUIGenerator.generate_swagger_ui_html(spec, out)]


def _gen_docs(args: argparse.Namespace, out: str) -> List[str]:
    from ..docs.markdown_doc_generator import MarkdownDocGenerator

    source = require_python_file(args.source)
    guard_overwrite(out, args.force)
    ensure_parent(out)
    MarkdownDocGenerator.generate_module_docs(source, out)
    return [out]


def _gen_diagram(args: argparse.Namespace, out: str) -> List[str]:
    from ..refactor.architecture_diagram import ArchitectureDiagramGenerator

    source = require_python_file(args.source)
    guard_overwrite(out, args.force)
    ensure_parent(out)
    diagram = ArchitectureDiagramGenerator.generate_mermaid_diagram(source).strip()
    if out.endswith(".md") and not diagram.startswith("```"):
        diagram = f"# Diagrama de clases de {os.path.basename(source)}\n\n```mermaid\n{diagram}\n```"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(diagram + "\n")
    return [out]


def _gen_tests(args: argparse.Namespace, out: str) -> List[str]:
    from ..qa.expected_values import RecordingError
    from ..qa.test_generator import QATestGenerator

    source = require_python_file(args.source)
    guard_overwrite(out, args.force)
    ensure_parent(out)
    build = QATestGenerator.generate_pytest_suite if args.framework == "pytest" else QATestGenerator.generate_test_suite
    if args.record:
        ui.warn(f"--record importa y ejecuta {rel(source)} para grabar lo que devuelve cada función.")
    try:
        written = build(source, out, record=args.record)
    except RecordingError as exc:
        raise CliError(str(exc), "Genera la suite sin --record o corrige el error del módulo.") from exc
    if not written:
        raise CliError(f"No se pudo leer {args.source}: revisa que sea Python válido.")
    if args.record:
        ui.hint("Los valores grabados fijan el comportamiento actual: revísalos antes de confiar en ellos.")
    return [out]


def _default_tests_output(args: argparse.Namespace) -> str:
    source = os.path.abspath(args.source)
    return os.path.join(os.path.dirname(source), f"test_{os.path.basename(source)}")


# tipo -> (descripción, salida por defecto, necesita --source, función, siguiente paso)
GENERATORS: Dict[str, Tuple[str, Any, bool, Callable[[argparse.Namespace, str], List[str]], Optional[str]]] = {
    "compose": ("Docker Compose endurecido", "docker-compose.yml", False, _gen_compose, "docker compose -f {out} up"),
    "helm": ("Chart de Helm sin root ni privilegios", "chart", False, _gen_helm, "helm install mi-servicio {out}"),
    "k8s": ("Manifiesto de Pod de Kubernetes endurecido", "pod.yaml", False, _gen_k8s, "kubectl apply -f {out}"),
    "dockerfile": ("Dockerfile multietapa sin root", "Dockerfile.hardened", False, _gen_dockerfile, None),
    "systemd": ("Unidad systemd endurecida", "app.service", False, _gen_systemd, None),
    "nginx": ("Configuración de Nginx con TLS y cabeceras de seguridad", "nginx.conf", False, _gen_webserver("nginx"), None),
    "caddy": ("Caddyfile con TLS y cabeceras de seguridad", "Caddyfile", False, _gen_webserver("caddy"), None),
    "github-actions": ("Workflow DevSecOps para GitHub Actions", ".github/workflows/devsecops.yml", False, _gen_github, None),
    "gitlab-ci": ("Pipeline DevSecOps para GitLab CI", ".gitlab-ci.yml", False, _gen_gitlab, None),
    "linters": ("Configuración de flake8, black, isort, mypy y ESLint", ".", False, _gen_linters, None),
    "openapi": ("Especificación OpenAPI 3.0.3 (JSON o YAML)", "openapi.json", True, _gen_openapi, None),
    "swagger": ("Página HTML con Swagger UI", "swagger_ui.html", True, _gen_swagger, "Ábrelo en el navegador (necesita conexión)."),
    "docs": ("Manual en Markdown a partir de los docstrings", "DOCS.md", True, _gen_docs, None),
    "diagram": ("Diagrama de clases en Mermaid", "diagrama.md", True, _gen_diagram, None),
    "tests": ("Suite de tests (unittest o pytest); --record graba los resultados reales", _default_tests_output, True, _gen_tests, "agentes test {out}"),
}


def _print_generators() -> None:
    ui.title("Tipos que puede generar 'agentes generate'")
    ui.out()
    rows = []
    for name, (desc, default, needs_source, _, _) in GENERATORS.items():
        out = "test_<fuente>.py" if callable(default) else default
        rows.append(((name, "bold"), out, desc + (" (requiere --source)" if needs_source else "")))
    ui.table(["Tipo", "Salida por defecto", "Qué genera"], rows)
    ui.out()
    ui.hint("Ejemplo: agentes generate compose --service api --port 8000")
    ui.hint("Opciones de cada tipo: agentes generate -h")


def cmd_generate(args: argparse.Namespace) -> int:
    """Genera configuraciones endurecidas, pipelines CI, documentación, diagramas o suites de tests."""
    if not args.kind:
        _print_generators()
        return 0
    _, default, needs_source, handler, next_step = GENERATORS[args.kind]
    if needs_source and not args.source:
        raise CliError(
            f"'generate {args.kind}' necesita el archivo Python de origen.",
            f"Ejemplo: agentes generate {args.kind} --source app.py",
        )
    out = args.output or (default(args) if callable(default) else default)
    out = os.path.abspath(os.path.expanduser(out))
    written = handler(args, out)
    if not written:
        ui.warn("No se generó ningún archivo.")
        return 0
    for path in written:
        ui.ok(f"Generado: {rel(path)}")
    if args.kind == "tests" and args.framework == "pytest":
        next_step = "pytest {out}"
    if next_step:
        ui.hint(f"Siguiente paso: {next_step.format(out=rel(out))}")
    return 0


def cmd_fix(args: argparse.Namespace) -> int:
    """Fija dependencias en requirements.txt a versiones recientes de PyPI y verifica CVEs."""
    from ..quality import vulnerabilities
    from ..quality.dependency_auditor import DependencyAuditor
    from ..quality.package_index import is_offline

    path = require_path(args.path, "file")
    if args.default_version is not None and not args.json:
        ui.warn("--default-version ya no tiene efecto: las versiones se consultan en PyPI.")
    if is_offline():
        raise CliError(
            "'fix' necesita consultar PyPI para elegir versiones y está activo el modo sin conexión.",
            "Quita --offline o la variable AGENTES_OFFLINE.",
        )

    plan = DependencyAuditor.plan_requirements_fix(path)
    if not args.dry_run:
        plan.apply()

    # Vulnerabilidades de las versiones que quedan fijadas (las nuevas y las que ya lo estaban).
    tmp_fd, tmp_path = tempfile.mkstemp(prefix="requirements-", suffix=".txt")
    with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
        fh.writelines(plan.fixed)
    try:
        scan = vulnerabilities.scan([tmp_path])
    finally:
        os.unlink(tmp_path)
    vulns = [Finding(path, f.line, f.level, f.message, f.rule_id) for f in scan.findings]
    code = 1 if blocking_count(vulns) else 0

    if args.json:
        emit_json({
            "file": path, "dry_run": args.dry_run, "corrections": len(plan.changes),
            "changes": [{"line": n, "before": a, "after": b} for n, a, b in plan.changes],
            "unresolved": [{"line": n, "package": p, "reason": r} for n, p, r in plan.unresolved],
            "vulnerabilities": dicts(vulns), "vulnerability_check_error": scan.error,
        })
        return code

    if plan.changes:
        ui.title(f"{'Cambios propuestos' if args.dry_run else 'Cambios aplicados'} en {rel(path)}")
        ui.out()
        for _, old, new in plan.changes:
            ui.out(f"  {ui.style('- ' + old, 'red')}")
            ui.out(f"  {ui.style('+ ' + new, 'green')}")
    else:
        ui.ok(f"{rel(path)} no tiene versiones que fijar.")

    if plan.unresolved:
        ui.section("Sin cambios")
        for line, package, reason in plan.unresolved:
            ui.bullet(f"Línea {line}, {package}: {reason}.")

    ui.section("Vulnerabilidades conocidas")
    if scan.error:
        ui.warn(f"No se pudo consultar OSV: {scan.error}")
    else:
        show_findings(vulns, args.limit, empty="Ninguna en las versiones resultantes.")

    ui.out()
    if args.dry_run:
        ui.hint(
            f"No se ha modificado nada. Quita --dry-run para aplicar las {len(plan.changes)} correcciones."
            if plan.changes else "No se ha modificado nada."
        )
    elif plan.changes:
        ui.ok(f"{len(plan.changes)} correcciones aplicadas con la última versión publicada que cumple cada requisito.")
    if vulns:
        ui.hint("Las versiones que ya estaban fijadas no se cambian: actualízalas a la versión corregida indicada.")
    return code
