"""
Generation and repair commands: generate and fix.
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
            ui.warn(f"Keeping {rel(dest)} because it already exists. Use --force to replace it.")
            continue
        written.append(build(out))
    return written


def _spec_from_source(args: argparse.Namespace) -> Dict[str, Any]:
    from ..docs.openapi_generator import OpenAPIGenerator

    source = require_python_file(args.source)
    spec = OpenAPIGenerator.generate_openapi_spec(source, title=args.service, naming_convention=args.naming_convention)
    errors = spec.get("x-agentes-errors") or []
    if errors:
        raise CliError(f"Could not read {args.source}: {errors[0]}")
    if not spec.get("paths"):
        by_name = OpenAPIGenerator.generate_openapi_spec(source, naming_convention=True).get("paths", {})
        if by_name and not args.naming_convention:
            ui.warn(
                f"No routes with Flask or FastAPI decorators, but {len(by_name)} functions follow the "
                "get_/post_/put_/delete_ naming convention. If they are endpoints, add --naming-convention."
            )
        else:
            ui.warn("No routes detected: the file declares no endpoints with Flask or FastAPI decorators.")
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
        diagram = f"# Class diagram of {os.path.basename(source)}\n\n```mermaid\n{diagram}\n```"
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
        ui.warn(f"--record imports and runs {rel(source)} to record what each function returns.")
    try:
        written = build(source, out, record=args.record)
    except RecordingError as exc:
        raise CliError(str(exc), "Generate the suite without --record, or fix the error in the module.") from exc
    if not written:
        raise CliError(f"Could not read {args.source}: check that it is valid Python.")
    if args.record:
        ui.hint("The recorded values pin down the current behaviour: review them before relying on them.")
    return [out]


def _default_tests_output(args: argparse.Namespace) -> str:
    source = os.path.abspath(args.source)
    return os.path.join(os.path.dirname(source), f"test_{os.path.basename(source)}")


# kind -> (description, default output, needs --source, handler, suggested next step).
# The default output may be a callable when it depends on the arguments (tests sit next to
# their source file).
GENERATORS: Dict[str, Tuple[str, Any, bool, Callable[[argparse.Namespace, str], List[str]], Optional[str]]] = {
    "compose": ("Hardened Docker Compose file", "docker-compose.yml", False, _gen_compose, "docker compose -f {out} up"),
    "helm": ("Helm chart without root or privileges", "chart", False, _gen_helm, "helm install my-service {out}"),
    "k8s": ("Hardened Kubernetes Pod manifest", "pod.yaml", False, _gen_k8s, "kubectl apply -f {out}"),
    "dockerfile": ("Multi-stage Dockerfile running as non-root", "Dockerfile.hardened", False, _gen_dockerfile, None),
    "systemd": ("Hardened systemd unit", "app.service", False, _gen_systemd, None),
    "nginx": ("Nginx configuration with TLS and security headers", "nginx.conf", False, _gen_webserver("nginx"), None),
    "caddy": ("Caddyfile with TLS and security headers", "Caddyfile", False, _gen_webserver("caddy"), None),
    "github-actions": ("DevSecOps workflow for GitHub Actions", ".github/workflows/devsecops.yml", False, _gen_github, None),
    "gitlab-ci": ("DevSecOps pipeline for GitLab CI", ".gitlab-ci.yml", False, _gen_gitlab, None),
    "linters": ("flake8, black, isort, mypy and ESLint configuration", ".", False, _gen_linters, None),
    "openapi": ("OpenAPI 3.0.3 specification (JSON or YAML)", "openapi.json", True, _gen_openapi, None),
    "swagger": ("HTML page with Swagger UI", "swagger_ui.html", True, _gen_swagger, "Open it in a browser (needs a connection)."),
    "docs": ("Markdown manual built from the docstrings", "DOCS.md", True, _gen_docs, None),
    "diagram": ("Mermaid class diagram", "diagram.md", True, _gen_diagram, None),
    "tests": ("Test suite (unittest or pytest); --record captures real results", _default_tests_output, True, _gen_tests, "agentes test {out}"),
}


def _print_generators() -> None:
    ui.title("Kinds 'agentes generate' can produce")
    ui.out()
    rows = []
    for name, (desc, default, needs_source, _, _) in GENERATORS.items():
        out = "test_<source>.py" if callable(default) else default
        rows.append(((name, "bold"), out, desc + (" (requires --source)" if needs_source else "")))
    ui.table(["Kind", "Default output", "What it generates"], rows)
    ui.out()
    ui.hint("Example: agentes generate compose --service api --port 8000")
    ui.hint("Options for each kind: agentes generate -h")


def cmd_generate(args: argparse.Namespace) -> int:
    """Generate hardened configurations, CI pipelines, documentation, diagrams or test suites."""
    if not args.kind:
        _print_generators()
        return 0
    _, default, needs_source, handler, next_step = GENERATORS[args.kind]
    if needs_source and not args.source:
        raise CliError(
            f"'generate {args.kind}' needs the Python source file.",
            f"Example: agentes generate {args.kind} --source app.py",
        )
    out = args.output or (default(args) if callable(default) else default)
    out = os.path.abspath(os.path.expanduser(out))
    written = handler(args, out)
    if not written:
        ui.warn("No file was generated.")
        return 0
    for path in written:
        ui.ok(f"Generated: {rel(path)}")
    if args.kind == "tests" and args.framework == "pytest":
        next_step = "pytest {out}"
    if next_step:
        ui.hint(f"Next step: {next_step.format(out=rel(out))}")
    return 0


def cmd_fix(args: argparse.Namespace) -> int:
    """Pin a requirements.txt to recent PyPI versions and check the result for known vulnerabilities."""
    from ..quality import vulnerabilities
    from ..quality.dependency_auditor import DependencyAuditor
    from ..quality.package_index import is_offline

    path = require_path(args.path, "file")
    if args.default_version is not None and not args.json:
        ui.warn("--default-version has no effect: versions are looked up on PyPI.")
    if is_offline():
        raise CliError(
            "'fix' needs to query PyPI to choose versions, but offline mode is on.",
            "Remove --offline or unset AGENTES_OFFLINE.",
        )

    plan = DependencyAuditor.plan_requirements_fix(path)
    if not args.dry_run:
        plan.apply()

    # Check the versions that end up pinned (newly pinned and already pinned) against OSV.
    # The scanner reads manifests from disk, so the planned content goes to a temporary file;
    # with --dry-run the real file is never touched.
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
        ui.title(f"{'Proposed changes' if args.dry_run else 'Applied changes'} in {rel(path)}")
        ui.out()
        for _, old, new in plan.changes:
            ui.out(f"  {ui.style('- ' + old, 'red')}")
            ui.out(f"  {ui.style('+ ' + new, 'green')}")
    else:
        ui.ok(f"{rel(path)} has no versions to pin.")

    if plan.unresolved:
        ui.section("Unchanged")
        for line, package, reason in plan.unresolved:
            ui.bullet(f"Line {line}, {package}: {reason}.")

    ui.section("Known vulnerabilities")
    if scan.error:
        ui.warn(f"Could not query OSV: {scan.error}")
    else:
        show_findings(vulns, args.limit, empty="None in the resulting versions.")

    ui.out()
    if args.dry_run:
        ui.hint(
            f"Nothing was modified. Remove --dry-run to apply the {len(plan.changes)} changes."
            if plan.changes else "Nothing was modified."
        )
    elif plan.changes:
        ui.ok(f"{len(plan.changes)} changes applied, each using the latest published version that satisfies its requirement.")
    if vulns:
        ui.hint("Versions that were already pinned are not changed: upgrade them to the fixed version shown.")
    return code
