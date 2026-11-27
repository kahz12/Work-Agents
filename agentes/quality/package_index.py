"""
Lookup of the versions published on PyPI.

`fix` uses it to choose the version to pin: the newest stable, non-yanked release that is
installable on the running Python version and satisfies what the requirements.txt declares.
It never invents a version.
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

from ..common.network import is_offline  # noqa: F401 - re-exported for the rest of the agent

PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"
USER_AGENT = "agentes-devsecops (+https://github.com/kahz12/Work-Agents)"

# A callable that takes a package name and returns its available versions. Tests pass an
# in-memory index so nothing touches the network.
VersionIndex = Callable[[str], List[str]]


class IndexUnavailable(RuntimeError):
    """The index could not be queried (no network, timeout, invalid response)."""


class PackageNotFound(LookupError):
    """The package does not exist in the index."""


def http_get_json(url: str, *, timeout: float = 10.0, data: Optional[bytes] = None) -> Dict:
    """GET (or POST when data is given) returning JSON. Failures become IndexUnavailable / PackageNotFound."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URL
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise PackageNotFound(url) from exc
        raise IndexUnavailable(f"HTTP {exc.code} from {urllib.parse.urlsplit(url).netloc}") from exc
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        raise IndexUnavailable(f"cannot reach {urllib.parse.urlsplit(url).netloc}: {reason}") from exc


def _supports_python(requires: Optional[str], python_version: str) -> bool:
    if not requires:
        return True
    try:
        return SpecifierSet(requires).contains(python_version, prereleases=True)
    except InvalidSpecifier:
        return True  # malformed metadata is not a reason to discard the release


def pypi_versions(name: str, *, timeout: float = 10.0, python_version: Optional[str] = None) -> List[str]:
    """
    A package's versions on PyPI that have at least one non-yanked file installable on
    python_version (by default, the interpreter running agentes).
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
    The highest version that satisfies specifier. Pre-releases are excluded unless the
    specifier itself asks for one or no final release satisfies it (SpecifierSet.filter
    implements exactly that rule).
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
    """Wrap an index so each package (by normalised name) is looked up only once."""
    cache: Dict[str, List[str]] = {}

    def lookup(name: str) -> List[str]:
        key = canonicalize_name(name.split("[", 1)[0])
        if key not in cache:
            cache[key] = index(name)
        return cache[key]

    return lookup
