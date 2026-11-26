#!/usr/bin/env python3
"""
Lanzador para usar el CLI desde un clon sin instalarlo: `python3 agentes_cli.py <comando>`.

El código está en agentes/cli/. Una vez instalado el paquete, usa el comando `agentes`
o `python -m agentes`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agentes.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
