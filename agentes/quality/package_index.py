"""
Consulta de versiones publicadas en PyPI.

Sirve a `fix` para elegir la versión que fija: la más reciente estable, no retirada
(yanked) e instalable en la versión de Python actual que cumple lo que declara el
requirements.txt. Nunca inventa una versión.
"""
from __future__ import annotations

import json
import platform
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Dict, Iterable, List, Optional

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from ..common.network import is_offline  # noqa: F401 - reexportado para el resto del agente

PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"
USER_AGENT = "agentes-devsecops (+https://github.com/kahz12/Work-Agents)"

# Una función que recibe un nombre de paquete y devuelve sus versiones disponibles.
VersionIndex = Callable[[str], List[str]]


class IndexUnavailable(RuntimeError):
    """No se pudo consultar el índice (sin red, tiempo agotado, respuesta inválida)."""


class PackageNotFound(LookupError):
    """El paquete no existe en el índice."""


def http_get_json(url: str, *, timeout: float = 10.0, data: Optional[bytes] = None) -> Dict:
    """GET (o POST si hay data) que devuelve JSON. Traduce los fallos a IndexUnavailable / PackageNotFound."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - URL fija https
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise PackageNotFound(url) from exc
        raise IndexUnavailable(f"HTTP {exc.code} en {urllib.parse.urlsplit(url).netloc}") from exc
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        raise IndexUnavailable(f"sin conexión con {urllib.parse.urlsplit(url).netloc}: {reason}") from exc


def _supports_python(requires: Optional[str], python_version: str) -> bool:
    if not requires:
        return True
    try:
        return SpecifierSet(requires).contains(python_version, prereleases=True)
    except InvalidSpecifier:
        return True  # metadatos mal formados: no se descarta la versión por ello


def pypi_versions(name: str, *, timeout: float = 10.0, python_version: Optional[str] = None) -> List[str]:
    """
    Versiones de un paquete en PyPI con al menos un archivo no retirado que se pueda
    instalar en python_version (por defecto, el intérprete que ejecuta agentes).
    """
    python_version = python_version or platform.python_version()
    base = name.split("[", 1)[0].strip()
    data = http_get_json(PYPI_JSON_URL.format(name=urllib.parse.quote(canonicalize_name(base))), timeout=timeout)
    versions = []
    for version, files in (data.get("releases") or {}).items():
        usable = [f for f in files or [] if not f.get("yanked")]
        if any(_supports_python(f.get("requires_python"), python_version) for f in usable):
            versions.append(version)
    return versions


def best_version(versions: Iterable[str], specifier: str = "") -> Optional[str]:
    """
    La versión más alta que cumple specifier. Excluye prerreleases salvo que el propio
    especificador las pida o que no haya ninguna versión final que lo cumpla.
    """
    try:
        spec = SpecifierSet(specifier)
    except InvalidSpecifier:
        return None
    parsed = []
    for raw in versions:
        try:
            parsed.append(Version(raw))
        except InvalidVersion:
            continue
    candidates = list(spec.filter(parsed))
    return str(max(candidates)) if candidates else None


def cached_index(index: VersionIndex) -> VersionIndex:
    """Envuelve un índice para no consultar dos veces el mismo paquete."""
    cache: Dict[str, List[str]] = {}

    def lookup(name: str) -> List[str]:
        key = canonicalize_name(name.split("[", 1)[0])
        if key not in cache:
            cache[key] = index(name)
        return cache[key]

    return lookup
