"""
Comandos CLI de operación y utilidades: health, sla, serve, password, demo, list y doctor.
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
    """Comprueba disco, carga del sistema y opcionalmente un puerto TCP o URL HTTP."""
    from ..sre.health_checker import SystemHealthChecker

    tcp_host, tcp_port = None, None
    if args.tcp:
        host, sep, port = args.tcp.rpartition(":")
        if not sep or not host or not port.isdigit():
            raise CliError(f"--tcp espera HOST:PUERTO y recibió {args.tcp!r}.", "Ejemplo: --tcp localhost:5432")
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

    labels = {"disk": "Disco", "load": "Carga", "tcp": "TCP", "http": "HTTP"}
    rows = []
    for check in report["checks"]:
        good = bool(check.get("ok", True))
        detail = check.get("detail", "")
        if check.get("name") == "load":
            detail = f"media del último minuto: {check.get('load_1m', 0.0):.2f}"
        elif check.get("name") == "disk" and good and "free_mb" in check:
            detail = f"{check['free_mb']:.0f} MB libres"
        rows.append((
            labels.get(check.get("name"), check.get("name")),
            ("OK" if good else "FALLO", "green" if good else "red"),
            detail,
        ))
    ui.title("Estado del sistema")
    ui.out()
    ui.table(["Sonda", "Estado", "Detalle"], rows)
    ui.out()
    if status == "HEALTHY":
        ui.ok("HEALTHY: todas las sondas responden.")
    elif status == "DEGRADED":
        ui.warn("DEGRADED: falla una sonda externa, pero el sistema base está bien.")
    else:
        ui.fail("UNHEALTHY: falla una sonda base.")
    if not args.tcp and not args.http:
        ui.hint("Puedes añadir sondas con --tcp HOST:PUERTO y --http URL.")
    return code


def cmd_sla(args: argparse.Namespace) -> int:
    """Evalúa una tasa de errores frente a un umbral máximo permitido."""
    from ..sre.alerting_engine import AlertingEngine

    if args.errors < 0 or args.total < 0 or args.errors > args.total:
        raise CliError("--errors debe estar entre 0 y --total.")
    alert, _ = AlertingEngine.evaluate_error_rate(args.total, args.errors, args.max_rate)
    rate = round(args.errors / args.total * 100, 2) if args.total else 0.0
    if args.json:
        emit_json({
            "total": args.total, "errors": args.errors, "error_rate_pct": rate,
            "max_rate_pct": args.max_rate, "alert": alert,
        })
        return 1 if alert else 0
    if not args.total:
        ui.warn("Sin tráfico registrado: no hay tasa que evaluar.")
    elif alert:
        ui.fail(f"Tasa de errores del {rate}%: supera el límite del {args.max_rate}%.")
    else:
        ui.ok(f"Tasa de errores del {rate}%: dentro del límite del {args.max_rate}%.")
    return 1 if alert else 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Arranca un servidor HTTP con /metrics (Prometheus) y /healthz."""
    from ..sre.health_checker import SystemHealthChecker
    from ..sre.prometheus_exporter import PrometheusExporter

    # Sin esto, al redirigir la salida (Docker, systemd) el mensaje de arranque queda en el búfer.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    if args.host in ("0.0.0.0", "::"):
        ui.warn("Escucha en todas las interfaces: el servidor es accesible desde la red.")
    try:
        PrometheusExporter.serve(
            host=args.host,
            port=args.port,
            health_fn=lambda: SystemHealthChecker.check_health(min_free_mb=1.0),
        )
    except OSError as exc:
        raise CliError(f"No se pudo abrir {args.host}:{args.port}: {exc}", "Prueba con otro puerto: --port 9200") from exc
    return 0


def _read_password(args: argparse.Namespace, confirm: bool = False) -> str:
    if args.stdin:
        value = sys.stdin.readline().rstrip("\r\n")
    else:
        value = getpass.getpass("Contraseña (no se muestra al escribir): ")
        if confirm and value != getpass.getpass("Repítela: "):
            raise CliError("Las dos contraseñas no coinciden.")
    if not value:
        raise CliError("La contraseña está vacía.")
    return value


def _strength_label(score: int) -> str:
    return "fuerte" if score >= 6 else ("aceptable" if score == 5 else "débil")


def _breach_note(count: Optional[int]) -> str:
    if count is None:
        return "no comprobada (sin conexión o modo --offline)"
    return f"aparece {count:,} veces".replace(",", ".") if count else "no aparece"


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
        ui.fail(f"Esta contraseña aparece {_breach_note(breaches)[8:]} en filtraciones conocidas. No la uses.")
    (ui.ok if score >= 5 else ui.fail)(f"Contraseña {label} ({score} de 6 puntos).")
    for tip in feedback:
        ui.bullet(tip)
    ui.hint(f"Filtraciones conocidas (Have I Been Pwned): {_breach_note(breaches)}.")
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
        print(f"Aviso: esta contraseña aparece {_breach_note(breaches)[8:]} en filtraciones conocidas.", file=sys.stderr)
    if score < 5:
        print(f"Aviso: la contraseña es {_strength_label(score)} ({score} de 6 puntos).", file=sys.stderr)
    if backend.startswith("pbkdf2"):
        print("Aviso: se usa PBKDF2 con 600 000 iteraciones. Instala el extra 'crypto' para usar Argon2.", file=sys.stderr)
    # El hash va solo a stdout para poder redirigirlo o capturarlo en un script.
    print(hashed)
    return 0


def cmd_password(args: argparse.Namespace) -> int:
    """Evalúa la fortaleza de una contraseña, genera su hash o verifica un hash existente."""
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
        ui.ok("La contraseña coincide con el hash.")
        if rehash:
            ui.warn(
                "El hash usa un algoritmo o un número de iteraciones por debajo de lo recomendado. "
                "Regenéralo con 'agentes password hash' y guárdalo en su lugar."
            )
    else:
        ui.fail("La contraseña no coincide con el hash.")
    return 0 if valid else 1


def cmd_list(_: argparse.Namespace) -> int:
    """Lista los 8 agentes disponibles en el ecosistema."""
    ui.title(f"AGENTES v{__version__} · agentes disponibles")
    ui.out()
    ui.table(
        ["Agente", "Paquete", "Qué hace"],
        [((key, "bold"), folder, desc) for key, (folder, desc) in AGENTS.items()],
    )
    ui.out()
    ui.hint("Demo de un agente: agentes demo <agente>   Todos los comandos: agentes")
    return 0


def _run_demo(key: str) -> int:
    module, _ = AGENTS[key]
    # Las demos escriben sus archivos de muestra con rutas relativas al directorio actual.
    agent_dir = os.path.join(_PACKAGE_ROOT, key)
    cwd = os.getcwd()
    try:
        os.chdir(agent_dir)
        runpy.run_module(f"{module}.main", run_name="__main__", alter_sys=True)
    finally:
        os.chdir(cwd)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Ejecuta la demo de un agente concreto o de todos ellos."""
    key = args.agent.lower().strip()
    if key == "all":
        for name in AGENTS:
            ui.section(f"Demo: {name}")
            _run_demo(name)
        return 0
    if key not in AGENTS:
        close = difflib.get_close_matches(key, list(AGENTS), n=1)
        hint = f"¿Querías decir '{close[0]}'? " if close else ""
        raise CliError(f"Agente desconocido: '{args.agent}'.", f"{hint}Disponibles: {', '.join(AGENTS)} o all.")
    return _run_demo(key)


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def cmd_doctor(args: argparse.Namespace) -> int:
    """Comprueba el entorno Python y la disponibilidad de dependencias obligatorias y opcionales."""
    from ..defensive.auth_manager import AuthManager
    from ..quality.static_checker import StaticCodeAnalyzer

    py_ok = sys.version_info >= (3, 9)
    yaml_ok = _module_available("yaml")
    checks = [
        {"name": "Python", "ok": py_ok, "required": True, "detail": sys.version.split()[0],
         "fix": "Se necesita Python 3.9 o superior."},
        {"name": "PyYAML", "ok": yaml_ok, "required": True, "detail": "validación de YAML y Kubernetes",
         "fix": "pip install PyYAML"},
        {"name": "bandit", "ok": StaticCodeAnalyzer.bandit_command() is not None, "required": False,
         "detail": "segundo motor de análisis estático", "fix": "pip install bandit   (sin él se usa el motor AST propio)"},
        {"name": "argon2-cffi", "ok": _module_available("argon2"), "required": False,
         "detail": "hashing de contraseñas con Argon2", "fix": "pip install argon2-cffi"},
        {"name": "bcrypt", "ok": _module_available("bcrypt"), "required": False,
         "detail": "hashing de contraseñas con bcrypt", "fix": "pip install bcrypt"},
        {"name": "pytest", "ok": _module_available("pytest"), "required": False,
         "detail": "ejecutar suites pytest generadas", "fix": "pip install pytest"},
    ]
    backend = AuthManager.get_available_crypto_backend()
    workdir = os.environ.get("AGENTES_WORKDIR")
    missing_required = [c for c in checks if c["required"] and not c["ok"]]
    code = 1 if missing_required else 0

    if args.json:
        emit_json({"version": __version__, "checks": checks, "crypto_backend": backend, "workdir": workdir})
        return code

    ui.title(f"Diagnóstico de AGENTES v{__version__}")
    ui.out()
    rows = []
    for c in checks:
        if c["ok"]:
            state: Any = ("OK", "green")
        elif c["required"]:
            state = ("FALTA", "red", "bold")
        else:
            state = ("opcional", "yellow")
        rows.append((c["name"], state, c["detail"] if c["ok"] else c["fix"]))
    ui.table(["Componente", "Estado", "Detalle"], rows)
    ui.out()
    ui.kv([
        ("Hashing de contraseñas", backend),
        ("Salida de las demos", workdir or "junto a cada agente (define AGENTES_WORKDIR para cambiarlo)"),
        ("Color en terminal", "activado" if ui.color else "desactivado"),
    ], indent=0)
    ui.out()
    if missing_required:
        ui.fail("Faltan componentes obligatorios.")
    elif all(c["ok"] for c in checks):
        ui.ok("Todo instalado.")
    else:
        ui.ok("Listo para usar. Los componentes opcionales amplían funciones, pero no son necesarios.")
        ui.hint('Para instalarlos todos: pip install -e ".[all]"')
    return code


def print_overview() -> None:
    """Muestra la pantalla principal con todos los grupos de comandos del CLI."""
    ui.title(f"agentes {__version__} · DevSecOps, SRE y QA para proyectos Python")
    ui.out()
    ui.out("Uso: agentes <comando> [opciones]")
    width = max(len(f"{name} {arg}".strip()) for _, cmds in COMMAND_GROUPS for name, arg, _ in cmds)
    for group, cmds in COMMAND_GROUPS:
        ui.section(group)
        for name, arg, desc in cmds:
            label = f"{name} {arg}".strip()
            padding = " " * (width - len(label))
            ui.out(f"  {ui.style(name, 'cyan', 'bold')}{label[len(name):]}{padding}  {desc}")
    ui.section("Para empezar")
    ui.out("  agentes doctor         comprueba la instalación")
    ui.out("  agentes pipeline .     audita el proyecto del directorio actual")
    ui.out("  agentes generate       muestra todo lo que se puede generar")
    ui.out()
    ui.hint("Ayuda de un comando: agentes <comando> -h    Opciones comunes: --json, --offline, --no-color")
