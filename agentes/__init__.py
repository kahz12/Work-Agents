"""
AGENTES: DevSecOps, SRE and QA agents for Python projects.

Each agent is a subpackage (agentes.defensive, agentes.quality, ...), shared code lives in
agentes.common and the command-line interface in agentes.cli.
"""

# Single source of truth for the version: pyproject.toml reads it from here, and a test
# checks that pyproject.toml does not hardcode it.
__version__ = "3.2.3"

__all__ = ["__version__"]
