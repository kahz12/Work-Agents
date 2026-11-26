"""
Vulnerabilidades conocidas en dependencias, consultadas en OSV (https://osv.dev).

OSV agrega los avisos de GitHub (GHSA), PyPI (PYSEC), npm y otros. Se comprueban las
dependencias con versión exacta de los manifiestos y, sobre todo, los paquetes instalados
en el entorno virtual del proyecto: con un rango no se sabe qué versión se instala, pero
lo instalado es lo que se ejecuta. Si una restricción declarada (por ejemplo `<13`) impide
instalar la versión corregida, se indica.

Envía a api.osv.dev el nombre y la versión de cada dependencia, nada más. Con
AGENTES_OFFLINE=1 no se hace ninguna consulta.
"""
from __future__ import annotations

import glob
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from ..common.findings import Finding
from .package_index import IndexUnavailable, PackageNotFound, http_get_json

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_BATCH_SIZE = 500

_GHSA_LEVELS = {"CRITICAL": "CRITICO", "HIGH": "ALTO", "MODERATE": "MEDIO", "MEDIUM": "MEDIO", "LOW": "BAJO"}


class VulnDBUnavailable(RuntimeError):
    """No se pudo consultar OSV."""


@dataclass(frozen=True)
class Dependency:
    ecosystem: str          # "PyPI" o "npm"
    name: str
    version: str
    file: str = ""
    line: int = 0

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.ecosystem, _norm(self.ecosystem, self.name), self.version)


@dataclass
class Vulnerability:
    id: str
    aliases: List[str] = field(default_factory=list)
    summary: str = ""
    level: str = "ALTO"
    fixed: Optional[str] = None

    @property
    def display_id(self) -> str:
        cves = sorted(a for a in self.aliases if a.startswith("CVE-"))
        return cves[0] if cves else self.id


def _norm(ecosystem: str, name: str) -> str:
    base = name.split("[", 1)[0].strip()
    return canonicalize_name(base) if ecosystem == "PyPI" else base.lower()


# --- Lectura de manifiestos ---------------------------------------------------

# Restricción declarada sobre un paquete: (nombre normalizado, especificador, archivo).
Constraint = Tuple[str, str, str]


def _parse_requirement(text: str) -> Optional[Requirement]:
    try:
        return Requirement(text)
    except InvalidRequirement:
        return None


def _exact_pin(req: Requirement) -> Optional[str]:
    """La versión si el requisito la fija exactamente (`==1.2.3`), o None."""
    specs = list(req.specifier)
    if len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
        return specs[0].version
    return None


def _requirements(path: str) -> "ManifestData":
    data = ManifestData()
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for idx, raw in enumerate(fh, 1):
            line = raw.split(" #", 1)[0].strip()
            if not line or line.startswith(("#", "-")):
                continue
            req = _parse_requirement(line)
            if req is None:
                continue
            data.add(req, path, idx)
    return data


def _load_toml(path: str) -> Dict:
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError as exc:
            raise ValueError("para leer pyproject.toml en Python < 3.11 hace falta 'tomli'") from exc
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def _pyproject(path: str) -> "ManifestData":
    """Dependencias de [project], sus extras, [dependency-groups] y Poetry."""
    toml = _load_toml(path)
    project = toml.get("project") or {}
    own = canonicalize_name(str(project.get("name", ""))) if project.get("name") else None
    texts: List[str] = list(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        texts.extend(group)
    for group in (toml.get("dependency-groups") or {}).values():
        texts.extend(t for t in group if isinstance(t, str))
    data = ManifestData()
    for text in texts:
        req = _parse_requirement(str(text))
        if req is not None and canonicalize_name(req.name) != own:
            data.add(req, path, 0)
    poetry = ((toml.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    for name, spec in poetry.items():
        if name.lower() == "python":
            continue
        version = spec.get("version", "") if isinstance(spec, dict) else str(spec)
        if re.fullmatch(r"=?=?\s*\d[\w.+-]*", version.strip()):
            data.deps.append(Dependency("PyPI", name, version.strip().lstrip("="), path))
        else:
            data.unpinned += 1
    return data


_EXACT_NPM = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


def _package_json(path: str) -> Tuple[List[Dependency], int]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    deps, unpinned = [], 0
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec).lstrip("=v")
            if _EXACT_NPM.match(spec):
                deps.append(Dependency("npm", name, spec, path))
            else:
                unpinned += 1
    return deps, unpinned


def _package_lock(path: str) -> Tuple[List[Dependency], int]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    deps: Dict[Tuple[str, str], Dependency] = {}
    for key, info in (data.get("packages") or {}).items():
        if not key or not isinstance(info, dict) or "version" not in info or info.get("link"):
            continue
        name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
        deps[(name, info["version"])] = Dependency("npm", name, info["version"], path)
    if not deps:  # lockfileVersion 1: dependencias anidadas, sin la clave "packages"
        stack = list((data.get("dependencies") or {}).items())
        while stack:
            name, info = stack.pop()
            if isinstance(info, dict) and info.get("version"):
                deps[(name, info["version"])] = Dependency("npm", name, info["version"], path)
                stack.extend((info.get("dependencies") or {}).items())
    return list(deps.values()), 0


_POETRY_PKG = re.compile(r'^\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', re.M)


def _poetry_lock(path: str) -> Tuple[List[Dependency], int]:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    return [Dependency("PyPI", n, v, path) for n, v in _POETRY_PKG.findall(text)], 0


def _pipfile_lock(path: str) -> Tuple[List[Dependency], int]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    deps = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            version = str((info or {}).get("version", ""))
            if version.startswith("=="):
                deps.append(Dependency("PyPI", name, version[2:], path))
    return deps, 0


@dataclass
class ManifestData:
    deps: List["Dependency"] = field(default_factory=list)
    unpinned: int = 0
    constraints: List[Constraint] = field(default_factory=list)

    def add(self, req: Requirement, path: str, line: int) -> None:
        pinned = _exact_pin(req)
        if pinned:
            self.deps.append(Dependency("PyPI", req.name, pinned, path, line))
        else:
            self.unpinned += 1
        # Un pin exacto no es una restricción que "impida" corregir: el consejo es actualizarlo.
        # Solo cuentan los rangos, que pueden dejar fuera la versión corregida (`<13`).
        if str(req.specifier) and not pinned:
            self.constraints.append((canonicalize_name(req.name), str(req.specifier), path))


def _wrap(reader: Callable[[str], Tuple[List["Dependency"], int]]) -> Callable[[str], ManifestData]:
    def read(path: str) -> ManifestData:
        deps, unpinned = reader(path)
        return ManifestData(deps, unpinned)
    return read


def manifest_reader(filename: str) -> Optional[Callable[[str], ManifestData]]:
    low = filename.lower()
    if low.startswith("requirements") and low.endswith(".txt"):
        return _requirements
    if low == "pyproject.toml":
        return _pyproject
    reader = {
        "package.json": _package_json,
        "package-lock.json": _package_lock,
        "poetry.lock": _poetry_lock,
        "pipfile.lock": _pipfile_lock,
    }.get(low)
    return _wrap(reader) if reader else None


def read_manifest_data(path: str) -> ManifestData:
    reader = manifest_reader(os.path.basename(path))
    if reader is None:
        raise ValueError(f"No es un manifiesto de dependencias conocido: {path}")
    return reader(path)


def read_manifest(path: str) -> Tuple[List["Dependency"], int]:
    """(dependencias con versión exacta, número de dependencias sin versión exacta)."""
    data = read_manifest_data(path)
    return data.deps, data.unpinned


# --- Entornos instalados ----------------------------------------------------------

def find_environments(root: str) -> List[str]:
    """Entornos virtuales del proyecto: la propia raíz o sus subcarpetas directas con pyvenv.cfg."""
    if not os.path.isdir(root):
        return []
    candidates = [root] + [os.path.join(root, d) for d in sorted(os.listdir(root))]
    return [c for c in candidates if os.path.isfile(os.path.join(c, "pyvenv.cfg"))]


def installed_packages(env: str) -> List["Dependency"]:
    """Paquetes instalados en un entorno virtual, con su versión exacta."""
    from importlib import metadata

    site_dirs = glob.glob(os.path.join(env, "lib", "python*", "site-packages"))
    site_dirs += glob.glob(os.path.join(env, "Lib", "site-packages"))
    deps: Dict[str, Dependency] = {}
    for dist in metadata.distributions(path=site_dirs):
        name, version = dist.metadata.get("Name"), dist.version
        if name and version:
            deps[canonicalize_name(name)] = Dependency("PyPI", name, version, env)
    return list(deps.values())


# --- Consulta a OSV -------------------------------------------------------------

def _fixed_version(vuln: Dict, dep: Dependency) -> Optional[str]:
    """La menor versión corregida posterior a la instalada, para este paquete."""
    fixes: List[str] = []
    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem") != dep.ecosystem or _norm(dep.ecosystem, pkg.get("name", "")) != _norm(dep.ecosystem, dep.name):
            continue
        for rng in affected.get("ranges") or []:
            fixes.extend(ev["fixed"] for ev in rng.get("events") or [] if "fixed" in ev)
    try:
        current = Version(dep.version)
        later = sorted({Version(f) for f in fixes if Version(f) > current})
        return str(later[0]) if later else None
    except InvalidVersion:
        return sorted(fixes)[0] if fixes else None


def _level(vuln: Dict) -> str:
    sev = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    # Sin severidad publicada se trata como alta: es una vulnerabilidad conocida.
    return _GHSA_LEVELS.get(sev, "ALTO")


def _dedupe(vulns: Sequence[Dict]) -> List[Dict]:
    """OSV devuelve el mismo fallo con varios identificadores (GHSA, PYSEC, CVE). Se deja uno."""
    ordered = sorted(vulns, key=lambda v: (not v.get("id", "").startswith("GHSA-"), v.get("id", "")))
    seen: set = set()
    unique = []
    for vuln in ordered:
        ids = {vuln.get("id", "")} | set(vuln.get("aliases") or [])
        if ids & seen:
            continue
        seen |= ids
        unique.append(vuln)
    return unique


def _post_json(url: str, payload: Dict, timeout: float) -> Dict:
    try:
        return http_get_json(url, timeout=timeout, data=json.dumps(payload).encode("utf-8"))
    except (IndexUnavailable, PackageNotFound) as exc:
        raise VulnDBUnavailable(str(exc)) from exc


def query_osv(deps: Iterable[Dependency], *, timeout: float = 15.0) -> Dict[Tuple[str, str, str], List[Vulnerability]]:
    """
    Vulnerabilidades de cada dependencia. VulnDBUnavailable si OSV no responde.

    Primero una consulta por lotes (hasta 500 dependencias por petición) dice cuáles están
    afectadas; después, solo para esas, una consulta individual trae los avisos completos.
    """
    unique = list({d.key: d for d in deps}.values())
    if not unique:
        return {}
    affected: List[Dependency] = []
    for start in range(0, len(unique), _BATCH_SIZE):
        chunk = unique[start:start + _BATCH_SIZE]
        queries = [{"package": {"ecosystem": d.ecosystem, "name": d.name}, "version": d.version} for d in chunk]
        results = _post_json(OSV_BATCH_URL, {"queries": queries}, timeout).get("results") or []
        affected.extend(dep for dep, res in zip(chunk, results) if (res or {}).get("vulns"))

    def details(dep: Dependency) -> List[Dict]:
        payload = {"package": {"ecosystem": dep.ecosystem, "name": dep.name}, "version": dep.version}
        return _post_json(OSV_QUERY_URL, payload, timeout).get("vulns") or []

    with ThreadPoolExecutor(max_workers=8) as pool:
        raw_by_dep = dict(zip((d.key for d in affected), pool.map(details, affected)))

    out: Dict[Tuple[str, str, str], List[Vulnerability]] = {d.key: [] for d in unique}
    for dep in affected:
        out[dep.key] = [
            Vulnerability(
                id=raw.get("id", ""),
                aliases=list(raw.get("aliases") or []),
                summary=str(raw.get("summary") or "").strip().rstrip("."),
                level=_level(raw),
                fixed=_fixed_version(raw, dep),
            )
            for raw in _dedupe(raw_by_dep.get(dep.key, []))
        ]
    return out


def _blocking_constraint(dep: "Dependency", fixed: Optional[str], constraints: Sequence[Constraint]) -> Optional[Constraint]:
    """La restricción declarada que impide instalar la versión corregida, si la hay."""
    if not fixed or dep.ecosystem != "PyPI":
        return None
    name = canonicalize_name(dep.name)
    for constraint in constraints:
        if constraint[0] != name:
            continue
        try:
            if not SpecifierSet(constraint[1]).contains(fixed, prereleases=True):
                return constraint
        except (InvalidSpecifier, InvalidVersion):
            continue
    return None


def to_findings(
    deps: Sequence["Dependency"],
    results: Dict[Tuple[str, str, str], List["Vulnerability"]],
    constraints: Sequence[Constraint] = (),
    root: str = "",
) -> List[Finding]:
    findings = []
    for dep in deps:
        for vuln in results.get(dep.key, []):
            fix = f" Corregido en {vuln.fixed}." if vuln.fixed else " Sin versión corregida publicada."
            summary = f": {vuln.summary}" if vuln.summary else ""
            where = ""
            if dep.line == 0 and os.path.isfile(os.path.join(dep.file, "pyvenv.cfg")):
                where = f" (instalado en {os.path.relpath(dep.file, root) if root else dep.file})"
            blocking = _blocking_constraint(dep, vuln.fixed, constraints)
            note = ""
            if blocking:
                origin = os.path.relpath(blocking[2], root) if root else blocking[2]
                note = f" La restricción '{dep.name}{blocking[1]}' de {origin} impide instalar esa versión."
            findings.append(Finding(
                dep.file, dep.line, vuln.level,
                f"{dep.name} {dep.version}{where} — {vuln.display_id}{summary}.{fix}{note}",
                f"VULN-{vuln.id}",
            ))
    return findings


@dataclass
class VulnScan:
    findings: List[Finding]
    manifests: List[str]
    checked: int        # dependencias con versión exacta consultadas (manifiestos + entornos)
    unpinned: int       # dependencias declaradas sin versión exacta
    error: Optional[str] = None
    environments: List[str] = field(default_factory=list)
    installed: int = 0  # paquetes leídos de los entornos instalados
    blocked_fixes: List[Tuple[str, str, str, str]] = field(default_factory=list)  # (paquete, restricción, archivo, corrección)

    @property
    def unchecked(self) -> bool:
        """No se ha podido comprobar nada: decir "0 vulnerabilidades" sería engañoso."""
        return self.error is None and self.checked == 0


def scan(manifests: Sequence[str], *, environments: Sequence[str] = (), timeout: float = 15.0,
         root: str = "") -> VulnScan:
    """
    Lee los manifiestos y los entornos instalados y consulta OSV. No lanza: un fallo de red
    queda en .error. Las versiones instaladas son las más fiables: son las que se ejecutan.
    """
    deps: List[Dependency] = []
    constraints: List[Constraint] = []
    unpinned = 0
    errors: List[Tuple[str, str]] = []
    for path in manifests:
        try:
            data = read_manifest_data(path)
        except (OSError, ValueError) as exc:
            errors.append((path, str(exc)))
            continue
        deps.extend(data.deps)
        unpinned += data.unpinned
        constraints.extend(data.constraints)
    installed = 0
    for env in environments:
        try:
            found = installed_packages(env)
        except OSError as exc:
            errors.append((env, str(exc)))
            continue
        installed += len(found)
        deps.extend(found)
    try:
        results = query_osv(deps, timeout=timeout)
    except VulnDBUnavailable as exc:
        return VulnScan([], list(manifests), 0, unpinned, error=str(exc), environments=list(environments))
    findings = to_findings(deps, results, constraints, root)
    blocked: List[Tuple[str, str, str, str]] = []
    for dep in deps:
        for vuln in results.get(dep.key, []):
            c = _blocking_constraint(dep, vuln.fixed, constraints)
            # Solo hay restricción que bloquee si existe una versión corregida (vuln.fixed).
            if c and vuln.fixed and (dep.name, c[1], c[2], vuln.fixed) not in blocked:
                blocked.append((dep.name, c[1], c[2], vuln.fixed))
    # Una restricción se informa una vez, con la mayor versión corregida que bloquea.
    worst: Dict[Tuple[str, str, str], str] = {}
    for name, spec, file, fixed in blocked:
        key = (name, spec, file)
        if key not in worst or Version(fixed) > Version(worst[key]):
            worst[key] = fixed
    findings.extend(Finding(path, 0, "ERROR", f"No se pudo leer: {msg}", "VULN-READ-ERROR") for path, msg in errors)
    return VulnScan(findings, list(manifests), len({d.key for d in deps}), unpinned,
                    environments=list(environments), installed=installed,
                    blocked_fixes=[(n, s, f, v) for (n, s, f), v in worst.items()])
