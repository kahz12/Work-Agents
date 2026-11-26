"""Control común de las consultas de red de los agentes (PyPI, OSV, Have I Been Pwned)."""
import os


def is_offline() -> bool:
    """AGENTES_OFFLINE=1 (o --offline en el CLI) desactiva toda consulta de red."""
    return os.environ.get("AGENTES_OFFLINE", "").strip().lower() in ("1", "true", "yes", "si", "sí")
