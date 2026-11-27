#!/usr/bin/env python3
"""
The `agentes` command-line interface.

Run `agentes` without arguments to see every command, grouped by task.
Exit codes: 0 success, 1 findings or failures, 2 usage error.
"""
from __future__ import annotations

import argparse
import difflib
import os
import sys
from typing import List, Optional, Tuple

from ..common.console import ui
from .analyze import (
    cmd_analyze,
    cmd_audit,
    cmd_metrics,
    cmd_pipeline,
    cmd_secrets,
    cmd_vulns,
)
from .common import (
    AGENTS,
    COMMAND_ALIASES,
    COMMAND_GROUPS,
    COMMAND_NAMES,
    STAGE_LABELS,
    STATUS_LABELS,
    CliError,
    reset_display_root,
    restore_display_root,
)
from .generate import GENERATORS, cmd_fix, cmd_generate
from .ops import (
    cmd_demo,
    cmd_doctor,
    cmd_health,
    cmd_list,
    cmd_password,
    cmd_serve,
    cmd_sla,
    print_overview,
)
from .parser import AgentesParser, build_parser
from .testing import _schema_from_json, cmd_contract, cmd_test, cmd_testability

__all__ = [
    "AGENTS",
    "AgentesParser",
    "COMMAND_ALIASES",
    "COMMAND_GROUPS",
    "COMMAND_NAMES",
    "CliError",
    "GENERATORS",
    "STAGE_LABELS",
    "STATUS_LABELS",
    "_schema_from_json",
    "build_parser",
    "cmd_analyze",
    "cmd_audit",
    "cmd_contract",
    "cmd_demo",
    "cmd_doctor",
    "cmd_fix",
    "cmd_generate",
    "cmd_health",
    "cmd_list",
    "cmd_metrics",
    "cmd_password",
    "cmd_pipeline",
    "cmd_secrets",
    "cmd_serve",
    "cmd_sla",
    "cmd_test",
    "cmd_testability",
    "cmd_vulns",
    "main",
    "print_overview",
    "ui",
]


def _first_command(argv: List[str]) -> Optional[str]:
    for token in argv:
        if not token.startswith("-"):
            return token
    return None


def _resolve_help_argv(argv: List[str], known: List[str]) -> Tuple[Optional[List[str]], Optional[int]]:
    topic = next((t for t in argv[argv.index("help") + 1:] if not t.startswith("-")), None)
    if topic is None:
        print_overview()
        return None, 0
    if topic not in known:
        ui.error(f"No help available for '{topic}'.", "Run 'agentes' to see every command.")
        return None, 2
    return [topic, "-h"], None


def _execute_command(args: argparse.Namespace) -> int:
    try:
        return args.func(args)
    except CliError as exc:
        ui.error(exc.message, exc.hint)
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0
    except Exception as exc:  # noqa: BLE001 - last resort: a readable message instead of a traceback
        if os.environ.get("AGENTES_DEBUG"):
            raise
        ui.error(f"Unexpected error: {exc}", "To see the full traceback, run the command again with AGENTES_DEBUG=1.")
        return 1


def _dispatch(argv: List[str]) -> int:
    if "--no-color" in argv:
        ui.set_color(False)
    if "--offline" in argv:
        os.environ["AGENTES_OFFLINE"] = "1"

    # Shortcut: a bare agent name runs its demo (`agentes qa` is `agentes demo qa`).
    if argv and argv[0] in AGENTS:
        argv = ["demo", *argv]

    if not argv or argv in (["-h"], ["--help"], ["help"], ["--no-color"]):
        print_overview()
        return 0

    command = _first_command(argv)
    known = COMMAND_NAMES + list(COMMAND_ALIASES)
    if command is not None and command not in known:
        close = difflib.get_close_matches(command, known + list(AGENTS), n=1)
        hint = f"Did you mean '{close[0]}'? " if close else ""
        ui.error(f"Unknown command: '{command}'.", f"{hint}Run 'agentes' to see every command.")
        return 2

    if command == "help":
        resolved, early_code = _resolve_help_argv(argv, known)
        if early_code is not None or resolved is None:
            return int(early_code or 0)
        argv = resolved

    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2

    if getattr(args, "list", False) and not getattr(args, "command", None):
        return cmd_list(args)
    if not getattr(args, "command", None):
        print_overview()
        return 0
    if args.command == "password" and args.action == "verify" and not args.hash:
        ui.error("'password verify' needs the hash to check against.", "Example: agentes password verify 'argon2:$argon2id$...'")
        return 2
    return _execute_command(args)


def main(argv: Optional[List[str]] = None) -> int:
    """
    CLI entry point. Returns the exit code instead of exiting, so tests and embedding callers
    can run it in-process; global state it touches (colour, AGENTES_OFFLINE, display root) is
    restored on the way out.
    """
    token = reset_display_root()
    had_offline = "AGENTES_OFFLINE" in os.environ
    prev_offline = os.environ.get("AGENTES_OFFLINE")
    prev_color = ui._color
    try:
        return _dispatch(list(sys.argv[1:] if argv is None else argv))
    finally:
        restore_display_root(token)
        ui.set_color(prev_color)
        if had_offline and prev_offline is not None:
            os.environ["AGENTES_OFFLINE"] = prev_offline
        else:
            os.environ.pop("AGENTES_OFFLINE", None)
