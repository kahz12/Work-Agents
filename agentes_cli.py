#!/usr/bin/env python3
"""
Launcher for running the CLI from a clone without installing it: `python3 agentes_cli.py <command>`.

The CLI itself lives in agentes/cli/. Once the package is installed, use the `agentes`
command or `python -m agentes` instead.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agentes.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
