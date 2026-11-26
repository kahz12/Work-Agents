"""
AGENTES: agentes de DevSecOps, SRE y QA para proyectos Python.

Cada agente es un subpaquete (agentes.defensive, agentes.quality, ...) y el código
compartido vive en agentes.common. El CLI está en agentes.cli.
"""

# Fuente única de la versión: pyproject.toml la toma de aquí, y un test
# comprueba que no la fija a mano.
__version__ = "3.2.3"

__all__ = ["__version__"]
