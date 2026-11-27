"""Where the agent demos write their artefacts."""
from __future__ import annotations

import os


def agent_output_dir(agent_file: str) -> str:
    """
    Return a writable directory for a demo's artefacts.

    Resolution order: AGENTES_WORKDIR/<agent> when the variable is set; otherwise the agent's
    own package directory when it is writable (a development checkout); otherwise, for a
    read-only installation, ./<agent> under the current working directory.
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
