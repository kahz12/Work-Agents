"""
Constants, error handling and path/output helpers shared by the CLI commands.
"""
from __future__ import annotations

import os
from contextvars import ContextVar, Token
from typing import Any, Dict, List, Optional, Sequence, Tuple, TypeVar

from ..common.console import describe_counts, ui
from ..common.findings import Finding, FindingLike, as_finding, count_by_level

T = TypeVar("T", bound=FindingLike)

AGENTS = {
    "defensive": ("agentes.defensive", "Defensive security (XSS, hashing, CSRF, RBAC)"),
    "quality": ("agentes.quality", "Code quality and SAST / SARIF"),
    "hardening": ("agentes.hardening", "Nginx/Caddy/Docker/K8s/systemd hardening"),
    "refactor": ("agentes.refactor", "Metrics, SOLID and Mermaid diagrams"),
    "qa": ("agentes.qa", "Test generation, test runner and API contracts"),
    "sre": ("agentes.sre", "Logs, anomalies, health, Prometheus, alerting"),
    "devops": ("agentes.devops", "GitHub Actions, GitLab CI, Compose, Helm"),
    "docs": ("agentes.docs", "OpenAPI, Swagger UI and Markdown docs"),
}

# Single source for the command summaries: it feeds both the overview screen and each command's help.
COMMAND_GROUPS: List[Tuple[str, List[Tuple[str, str, str]]]] = [
    ("Analyse a project", [
        ("pipeline", "PATH", "Full audit: SAST, secrets, metrics, OpenAPI and infrastructure"),
        ("analyze", "PATH", "Python static analysis, infrastructure and dependencies only"),
        ("secrets", "PATH", "Look for keys and passwords in code and configuration"),
        ("vulns", "PATH", "Known vulnerabilities in dependencies (queries OSV)"),
        ("audit", "PATH|URL", "Audit a Dockerfile, YAML, .env, log, test suite or a URL's headers"),
        ("metrics", "PATH", "Complexity, SOLID, performance and refactoring advice"),
    ]),
    ("Generate and fix", [
        ("generate", "KIND", "Generate hardened configurations, documentation, diagrams and tests"),
        ("fix", "FILE", "Pin a requirements.txt to the latest published versions and check them for vulnerabilities"),
    ]),
    ("Test", [
        ("test", "FILE", "Run a unittest suite and assess its quality and coverage"),
        ("testability", "FILE", "Find what makes a module hard to test and suggest scenarios"),
        ("contract", "URL", "Check an endpoint's status code, schema and response time"),
    ]),
    ("Operate", [
        ("health", "", "Check disk and load, plus a TCP port or a URL on request"),
        ("sla", "", "Compare an error rate against a threshold"),
        ("serve", "", "HTTP server exposing /metrics (Prometheus) and /healthz"),
    ]),
    ("Utilities", [
        ("password", "ACTION", "Assess, hash or verify a password"),
        ("demo", "AGENT", "Run an agent's demo on sample data"),
        ("list", "", "List the 8 agents"),
        ("doctor", "", "Check the installation and the optional dependencies"),
        ("help", "[COMMAND]", "Show the general help or a command's help"),
    ]),
]
COMMAND_ALIASES = {"serve-sre": "serve"}
COMMAND_NAMES = [name for _, cmds in COMMAND_GROUPS for name, _, _ in cmds]

STAGE_LABELS = dict((
    ("quality_sast", "Static analysis"),
    ("defensive_secrets", "Secrets"),
    ("refactor_metrics", "Metrics and SOLID"),
    ("documentation", "OpenAPI documentation"),
    ("infra_and_deps", "Infrastructure and dependencies"),
    ("dependency_vulns", "Dependency vulnerabilities"),
))
STATUS_LABELS = {"ok": ("OK", "green"), "fail": ("FAILED", "red"), "skipped": ("SKIPPED", "yellow")}


class CliError(Exception):
    """A usage error: printed without a traceback, and the command exits with code 2."""

    def __init__(self, message: str, hint: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint


# Root of the project the running command analyses. A file far from the current directory but
# inside that root is shown relative to it: src/app/x.py instead of the full absolute path.
# A ContextVar keeps concurrent or nested main() calls (tests, embedding) from leaking roots.
_DISPLAY_ROOT_VAR: ContextVar[Optional[str]] = ContextVar("agentes_display_root", default=None)


def reset_display_root() -> Token:
    """Clear the display root for the current invocation and return the token that restores it."""
    return _DISPLAY_ROOT_VAR.set(None)


def restore_display_root(token: Token) -> None:
    """Restore the previous display root once the command has finished."""
    _DISPLAY_ROOT_VAR.reset(token)


def set_display_root(full: str) -> None:
    """Record the analysed project's root, unless one was already set in this context."""
    if _DISPLAY_ROOT_VAR.get() is None:
        _DISPLAY_ROOT_VAR.set(full if os.path.isdir(full) else os.path.dirname(full))


def rel(path: Any) -> str:
    """
    A path for display: relative to the current directory when it is close by, otherwise
    relative to the analysed project, otherwise absolute.
    """
    text = str(path)
    if not text or "://" in text:
        return text
    if not os.path.isabs(text):
        return os.path.normpath(text)
    try:
        relative = os.path.relpath(text)
    except ValueError:
        return text
    # Up to two levels up is still easier to read than the absolute path.
    if relative.split(os.sep).count("..") <= 2:
        return relative
    root = _DISPLAY_ROOT_VAR.get()
    if root and text != root and text.startswith(root.rstrip(os.sep) + os.sep):
        return os.path.relpath(text, root)
    return text


def require_path(path: str, kind: str = "any") -> str:
    """Check that the path exists and is of the expected kind ('any', 'file' or 'dir'); return it absolute."""
    full = os.path.abspath(os.path.expanduser(path))
    if os.path.exists(full):
        set_display_root(full)
    if not os.path.exists(full):
        raise CliError(
            f"Path does not exist: {path}",
            "Check the spelling. Relative paths are resolved from the current directory.",
        )
    if kind == "file" and not os.path.isfile(full):
        raise CliError(f"Expected a file, but '{path}' is a directory.")
    if kind == "dir" and not os.path.isdir(full):
        raise CliError(f"Expected a directory, but '{path}' is a file.")
    return full


def require_python_file(path: str) -> str:
    """Check that the path is an existing .py file; return it absolute."""
    full = require_path(path, "file")
    if not full.endswith(".py"):
        raise CliError(f"Expected a .py file: {path}")
    return full


def visible(findings: Sequence[FindingLike]) -> List[Finding]:
    """Display copy of the findings: relative paths, purely informational entries removed."""
    shown = []
    for item in findings:
        f = as_finding(item)
        if not f.silent:
            shown.append(Finding(rel(f.file), f.line, f.level, f.message, f.rule_id))
    return shown


def dicts(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Convert Finding objects into JSON-serialisable dicts that include their category."""
    from ..common.rules import annotate

    return annotate([f.to_dict() for f in findings])


def emit_json(data: Any) -> None:
    """Print data as indented JSON."""
    import json

    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))


def show_findings(findings: Sequence[FindingLike], limit: int, empty: str = "No findings.", *,
                  security_checked: bool = False) -> None:
    """
    Print the visible findings split into security and code quality, so a security risk is not
    buried among missing docstrings, or a success message when there are none. The limit applies
    to each section separately. security_checked means the command looks for security problems:
    when it found none, that is stated explicitly.
    """
    from ..common.rules import CATEGORY_LABELS, QUALITY, SECURITY, category

    shown = visible(findings)
    if not shown:
        ui.ok(empty)
        return
    groups = {SECURITY: [f for f in shown if category(f) == SECURITY], QUALITY: [f for f in shown if category(f) == QUALITY]}
    if security_checked and not groups[SECURITY]:
        ui.out()
        ui.ok("No security findings.")
    for key in (SECURITY, QUALITY):
        group = groups[key]
        if group:
            ui.section(f"{CATEGORY_LABELS[key]} ({len(group)}): {describe_counts(count_by_level(group))}")
            ui.findings(group, limit=limit)


def drop_inline(findings: List[T]) -> Tuple[List[T], int]:
    """Drop findings suppressed on their own line. Returns (remaining findings, number dropped)."""
    from ..common.suppressions import InlineSuppressions

    inline = InlineSuppressions()
    kept = inline.filter(findings)
    return kept, inline.suppressed


def show_inline_note(count: int) -> None:
    """Say how many findings were suppressed inline: silencing them must never go unnoticed."""
    if count:
        ui.hint(f"{count} findings suppressed inline (# agentes: ignore, noqa or nosec) are not shown.")


def guard_overwrite(path: str, force: bool) -> None:
    """Refuse to overwrite an existing file unless --force was given."""
    if os.path.exists(path) and not force:
        raise CliError(
            f"{rel(path)} already exists and was not overwritten.",
            "Add --force to replace it, or use -o to choose another path.",
        )


def ensure_parent(path: str) -> None:
    """Create the parent directory of an output path if it does not exist yet."""
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)


def python_files(target: str) -> List[str]:
    """Python files under the target file or directory."""
    from ..common.orchestrator import _iter_python_files

    return _iter_python_files(target)
