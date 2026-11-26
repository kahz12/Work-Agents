"""Resolución del directorio donde los demos escriben sus artefactos."""
from __future__ import annotations

import os


def agent_output_dir(agent_file: str) -> str:
    """
    Devuelve un directorio escribible para los artefactos de un demo.

    Orden: AGENTES_WORKDIR/<agente> si está definida; si no, el propio
    directorio del agente cuando se puede escribir en él (checkout de
    desarrollo); si no —instalación de solo lectura— ./<agente> bajo el cwd.
    """
    pkg_dir = os.path.dirname(os.path.abspath(agent_file))
    name = os.path.basename(pkg_dir)

    workdir = os.environ.get("AGENTES_WORKDIR")
    if workdir:
        target = os.path.join(os.path.abspath(workdir), name)
    elif os.access(pkg_dir, os.W_OK):
        return pkg_dir
    else:
        target = os.path.join(os.getcwd(), name)

    os.makedirs(target, exist_ok=True)
    return target
