"""
Operations and utility commands: health, sla, serve, password, demo, list and doctor.
"""
from __future__ import annotations

import argparse
import difflib
import getpass
import importlib.util
import os
import runpy
import sys
from typing import Any, Optional

from .. import __version__
from ..common.console import ui
from .common import AGENTS, COMMAND_GROUPS, CliError, emit_json

_PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def cmd_health(args: argparse.Namespace) -> int:
    """Check disk space and system load, plus an optional TCP port or HTTP URL."""
    from ..sre.health_checker import SystemHealthChecker

    tcp_host, tcp_port = None, None
    if args.tcp:
        host, sep, port = args.tcp.rpartition(":")
        if not sep or not host or not port.isdigit():
            raise CliError(f"--tcp expects HOST:PORT and got {args.tcp!r}.", "Example: --tcp localhost:5432")
        tcp_host, tcp_port = host, int(port)

    report = SystemHealthChecker.check_health(
        disk_path=args.disk, min_free_mb=args.min_free_mb, tcp_host=tcp_host, tcp_port=tcp_port,
        http_url=args.http, http_expect_status=args.expect_status,
    )
    status = report["status"]
    code = 0 if status == "HEALTHY" else 1
    if args.json:
        emit_json(report)
        return code

    labels = {"disk": "Disk", "load": "Load", "tcp": "TCP", "http": "HTTP"}
    rows = []
    for check in report["checks"]:
        good = bool(check.get("ok", True))
        detail = check.get("detail", "")
        if check.get("name") == "load":
            detail = f"1-minute average: {check.get('load_1m', 0.0):.2f}"
        elif check.get("name") == "disk" and good and "free_mb" in check:
            detail = f"{check['free_mb']:.0f} MB free"
        rows.append((
            labels.get(check.get("name"), check.get("name")),
            ("OK" if good else "FAILED", "green" if good else "red"),
            detail,
        ))
    ui.title("System health")
    ui.out()
    ui.table(["Probe", "Status", "Detail"], rows)
    ui.out()
    if status == "HEALTHY":
        ui.ok("HEALTHY: every probe passed.")
    elif status == "DEGRADED":
        ui.warn("DEGRADED: an external probe failed, but the base system is fine.")
    else:
        ui.fail("UNHEALTHY: a base probe failed.")
    if not args.tcp and not args.http:
        ui.hint("Add probes with --tcp HOST:PORT and --http URL.")
    return code


def cmd_sla(args: argparse.Namespace) -> int:
    """Compare an error rate against the maximum allowed rate."""
    from ..sre.alerting_engine import AlertingEngine

    if args.errors < 0 or args.total < 0 or args.errors > args.total:
        raise CliError("--errors must be between 0 and --total.")
    alert, _ = AlertingEngine.evaluate_error_rate(args.total, args.errors, args.max_rate)
    rate = round(args.errors / args.total * 100, 2) if args.total else 0.0
    if args.json:
        emit_json({
            "total": args.total, "errors": args.errors, "error_rate_pct": rate,
            "max_rate_pct": args.max_rate, "alert": alert,
        })
        return 1 if alert else 0
    if not args.total:
        ui.warn("No traffic recorded: there is no rate to evaluate.")
    elif alert:
        ui.fail(f"Error rate {rate}%: above the {args.max_rate}% limit.")
    else:
        ui.ok(f"Error rate {rate}%: within the {args.max_rate}% limit.")
    return 1 if alert else 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Start an HTTP server exposing /metrics (Prometheus) and /healthz."""
    from ..sre.health_checker import SystemHealthChecker
    from ..sre.prometheus_exporter import PrometheusExporter

    # Without line buffering, the startup message stays stuck in the buffer when output is
    # redirected (Docker, systemd) and the operator never sees it.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    if args.host in ("0.0.0.0", "::"):
        ui.warn("Listening on every interface: the server is reachable from the network.")
    try:
        PrometheusExporter.serve(
            host=args.host,
            port=args.port,
            health_fn=lambda: SystemHealthChecker.check_health(min_free_mb=1.0),
        )
    except OSError as exc:
        raise CliError(f"Could not listen on {args.host}:{args.port}: {exc}", "Try another port: --port 9200") from exc
    return 0


def _read_password(args: argparse.Namespace, confirm: bool = False) -> str:
    if args.stdin:
        value = sys.stdin.readline().rstrip("\r\n")
    else:
        value = getpass.getpass("Password (not echoed): ")
        if confirm and value != getpass.getpass("Repeat it: "):
            raise CliError("The two passwords do not match.")
    if not value:
        raise CliError("The password is empty.")
    return value


def _strength_label(score: int) -> str:
    return "strong" if score >= 6 else ("acceptable" if score == 5 else "weak")


def _times(count: int) -> str:
    return f"{count:,} time" + ("" if count == 1 else "s")


def _breach_note(count: Optional[int]) -> str:
    if count is None:
        return "not checked (no connection or --offline mode)"
    return f"found {_times(count)}" if count else "not found"


def _password_check(args: argparse.Namespace) -> int:
    from ..defensive.auth_manager import AuthManager
    from ..defensive.password_policy import pwned_count

    password = _read_password(args)
    score, feedback = AuthManager.evaluate_password_strength(password)
    breaches = pwned_count(password)
    label = _strength_label(score)
    code = 0 if score >= 5 and not breaches else 1
    if args.json:
        emit_json({"score": score, "max_score": 6, "strength": label, "feedback": feedback, "breaches": breaches})
        return code
    if breaches:
        ui.fail(f"This password appears {_times(breaches)} in known breaches. Do not use it.")
    (ui.ok if score >= 5 else ui.fail)(f"Password is {label} ({score} of 6 points).")
    for tip in feedback:
        ui.bullet(tip)
    ui.hint(f"Known breaches (Have I Been Pwned): {_breach_note(breaches)}.")
    return code


def _password_hash(args: argparse.Namespace) -> int:
    from ..defensive.auth_manager import AuthManager
    from ..defensive.password_policy import pwned_count

    password = _read_password(args, confirm=True)
    score, _ = AuthManager.evaluate_password_strength(password)
    breaches = pwned_count(password)
    hashed = AuthManager.hash_password(password)
    backend = AuthManager.get_available_crypto_backend()
    if args.json:
        emit_json({"hash": hashed, "backend": backend, "score": score, "breaches": breaches})
        return 0
    if breaches:
        print(f"Warning: this password appears {_times(breaches)} in known breaches.", file=sys.stderr)
    if score < 5:
        print(f"Warning: the password is {_strength_label(score)} ({score} of 6 points).", file=sys.stderr)
    if backend.startswith("pbkdf2"):
        print("Warning: using PBKDF2 with 600,000 iterations. Install the 'crypto' extra to use Argon2.", file=sys.stderr)
    # Warnings go to stderr and only the hash goes to stdout, so it can be redirected or
    # captured by a script.
    print(hashed)
    return 0


def cmd_password(args: argparse.Namespace) -> int:
    """Assess a password's strength, hash it, or verify it against an existing hash."""
    from ..defensive.auth_manager import AuthManager

    if args.action == "check":
        return _password_check(args)
    if args.action == "hash":
        return _password_hash(args)

    valid = AuthManager.verify_password(_read_password(args), args.hash)
    rehash = bool(valid) and AuthManager.needs_rehash(args.hash)
    if args.json:
        emit_json({"valid": bool(valid), "needs_rehash": rehash})
    elif valid:
        ui.ok("The password matches the hash.")
        if rehash:
            ui.warn(
                "The hash uses an algorithm or iteration count below the current recommendation. "
                "Regenerate it with 'agentes password hash' and store the new one instead."
            )
    else:
        ui.fail("The password does not match the hash.")
    return 0 if valid else 1


def cmd_list(_: argparse.Namespace) -> int:
    """List the 8 available agents."""
    ui.title(f"AGENTES v{__version__} · available agents")
    ui.out()
    ui.table(
        ["Agent", "Package", "What it does"],
        [((key, "bold"), folder, desc) for key, (folder, desc) in AGENTS.items()],
    )
    ui.out()
    ui.hint("An agent's demo: agentes demo <agent>   Every command: agentes")
    return 0


def _run_demo(key: str) -> int:
    module, _ = AGENTS[key]
    # The demos write their sample files with paths relative to the working directory, so
    # each one runs from inside its own agent package and the caller's cwd is restored after.
    agent_dir = os.path.join(_PACKAGE_ROOT, key)
    cwd = os.getcwd()
    try:
        os.chdir(agent_dir)
        runpy.run_module(f"{module}.main", run_name="__main__", alter_sys=True)
    finally:
        os.chdir(cwd)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Run the demo of one agent, or of all of them."""
    key = args.agent.lower().strip()
    if key == "all":
        for name in AGENTS:
            ui.section(f"Demo: {name}")
            _run_demo(name)
        return 0
    if key not in AGENTS:
        close = difflib.get_close_matches(key, list(AGENTS), n=1)
        hint = f"Did you mean '{close[0]}'? " if close else ""
        raise CliError(f"Unknown agent: '{args.agent}'.", f"{hint}Available: {', '.join(AGENTS)} or all.")
    return _run_demo(key)


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def cmd_doctor(args: argparse.Namespace) -> int:
    """Check the Python environment and which required and optional dependencies are available."""
    from ..defensive.auth_manager import AuthManager
    from ..quality.static_checker import StaticCodeAnalyzer

    py_ok = sys.version_info >= (3, 9)
    yaml_ok = _module_available("yaml")
    checks = [
        {"name": "Python", "ok": py_ok, "required": True, "detail": sys.version.split()[0],
         "fix": "Python 3.9 or later is required."},
        {"name": "PyYAML", "ok": yaml_ok, "required": True, "detail": "YAML and Kubernetes validation",
         "fix": "pip install PyYAML"},
        {"name": "bandit", "ok": StaticCodeAnalyzer.bandit_command() is not None, "required": False,
         "detail": "second static analysis engine", "fix": "pip install bandit   (without it, the built-in AST engine is used)"},
        {"name": "argon2-cffi", "ok": _module_available("argon2"), "required": False,
         "detail": "password hashing with Argon2", "fix": "pip install argon2-cffi"},
        {"name": "bcrypt", "ok": _module_available("bcrypt"), "required": False,
         "detail": "password hashing with bcrypt", "fix": "pip install bcrypt"},
        {"name": "pytest", "ok": _module_available("pytest"), "required": False,
         "detail": "run generated pytest suites", "fix": "pip install pytest"},
    ]
    backend = AuthManager.get_available_crypto_backend()
    workdir = os.environ.get("AGENTES_WORKDIR")
    missing_required = [c for c in checks if c["required"] and not c["ok"]]
    code = 1 if missing_required else 0

    if args.json:
        emit_json({"version": __version__, "checks": checks, "crypto_backend": backend, "workdir": workdir})
        return code

    ui.title(f"AGENTES v{__version__} diagnostics")
    ui.out()
    rows = []
    for c in checks:
        if c["ok"]:
            state: Any = ("OK", "green")
        elif c["required"]:
            state = ("MISSING", "red", "bold")
        else:
            state = ("optional", "yellow")
        rows.append((c["name"], state, c["detail"] if c["ok"] else c["fix"]))
    ui.table(["Component", "Status", "Detail"], rows)
    ui.out()
    ui.kv([
        ("Password hashing", backend),
        ("Demo output", workdir or "next to each agent (set AGENTES_WORKDIR to change it)"),
        ("Terminal colour", "on" if ui.color else "off"),
    ], indent=0)
    ui.out()
    if missing_required:
        ui.fail("Required components are missing.")
    elif all(c["ok"] for c in checks):
        ui.ok("Everything is installed.")
    else:
        ui.ok("Ready to use. The optional components add features, but they are not required.")
        ui.hint('To install them all: pip install -e ".[all]"')
    return code


def print_overview() -> None:
    """Print the overview screen with every command group."""
    ui.title(f"agentes {__version__} · DevSecOps, SRE and QA for Python projects")
    ui.out()
    ui.out("Usage: agentes <command> [options]")
    width = max(len(f"{name} {arg}".strip()) for _, cmds in COMMAND_GROUPS for name, arg, _ in cmds)
    for group, cmds in COMMAND_GROUPS:
        ui.section(group)
        for name, arg, desc in cmds:
            label = f"{name} {arg}".strip()
            padding = " " * (width - len(label))
            ui.out(f"  {ui.style(name, 'cyan', 'bold')}{label[len(name):]}{padding}  {desc}")
    ui.section("Getting started")
    ui.out("  agentes doctor         check the installation")
    ui.out("  agentes pipeline .     audit the project in the current directory")
    ui.out("  agentes generate       show everything that can be generated")
    ui.out()
    ui.hint("A command's help: agentes <command> -h    Common options: --json, --offline, --no-color")
