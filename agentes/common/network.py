"""Shared switch for the network lookups the agents make (PyPI, OSV, Have I Been Pwned)."""
import os


def is_offline() -> bool:
    """AGENTES_OFFLINE=1 (or --offline on the CLI) disables every network lookup."""
    # "si"/"sí" are accepted as well, since some users set the variable in Spanish.
    return os.environ.get("AGENTES_OFFLINE", "").strip().lower() in ("1", "true", "yes", "si", "sí")
