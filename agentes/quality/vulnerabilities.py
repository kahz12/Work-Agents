"""
Known vulnerabilities in dependencies, looked up in OSV (https://osv.dev).

OSV aggregates advisories from GitHub (GHSA), PyPI (PYSEC), npm and others. The dependencies
checked are those pinned to an exact version in the manifests and, above all, the packages
installed in the project's virtual environment: a range does not say which version gets
installed, whereas what is installed is what actually runs. When a declared constraint
(for example `<13`) prevents installing the fixed version, that is reported too.

Only each dependency's name and version are sent to api.osv.dev. With AGENTES_OFFLINE=1 no
request is made at all.
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

# GitHub advisory severities mapped onto SEVERITY_ORDER ("MODERATE" is GHSA's word for medium).
_GHSA_LEVELS = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"}


class VulnDBUnavailable(RuntimeError):
    """OSV could not be queried."""


@dataclass(frozen=True)
class Dependency:
    ecosystem: str          # "PyPI" or "npm"
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


# --- Reading manifests --------------------------------------------------------

# A constraint declared on a package: (normalised name, specifier, file).
Constraint = Tuple[str, str, str]


def _parse_requirement(text: str) -> Optional[Requirement]:
    try:
        return Requirement(text)
    except InvalidRequirement:
        return None


def _exact_pin(req: Requirement) -> Optional[str]:
    """The version when the requirement pins it exactly (`==1.2.3`), otherwise None."""
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
            raise ValueError("reading pyproject.toml on Python < 3.11 requires 'tomli'") from exc
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def _pyproject(path: str) -> "ManifestData":
    """Dependencies from [project], its extras, [dependency-groups] and Poetry. The project itself is skipped."""
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
    if not deps:  # lockfileVersion 1: nested dependencies and no "packages" key
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
        # An exact pin is not a constraint that "blocks" the fix: the advice there is simply to
        # bump it. Only ranges count, since they can exclude the fixed version (`<13`).
        if str(req.specifier) and not pinned:
            self.constraints.append((canonicalize_name(req.name), str(req.specifier), path))


def _wrap(reader: Callable[[str], Tuple[List["Dependency"], int]]) -> Callable[[str], ManifestData]:
    def read(path: str) -> ManifestData:
        deps, unpinned = reader(path)
        return ManifestData(deps, unpinned)
    return read


def manifest_reader(filename: str) -> Optional[Callable[[str], ManifestData]]:
    """The reader for a manifest or lock file, chosen by file name, or None when it is not one."""
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
        raise ValueError(f"Not a known dependency manifest: {path}")
    return reader(path)


def read_manifest(path: str) -> Tuple[List["Dependency"], int]:
    """(dependencies with an exact version, number of dependencies without one)."""
    data = read_manifest_data(path)
    return data.deps, data.unpinned


# --- Installed environments --------------------------------------------------------

def find_environments(root: str) -> List[str]:
    """The project's virtual environments: the root itself or direct subdirectories that contain pyvenv.cfg."""
    if not os.path.isdir(root):
        return []
    candidates = [root] + [os.path.join(root, d) for d in sorted(os.listdir(root))]
    return [c for c in candidates if os.path.isfile(os.path.join(c, "pyvenv.cfg"))]


def installed_packages(env: str) -> List["Dependency"]:
    """Packages installed in a virtual environment, with their exact versions. Covers POSIX and Windows layouts."""
    from importlib import metadata

    site_dirs = glob.glob(os.path.join(env, "lib", "python*", "site-packages"))
    site_dirs += glob.glob(os.path.join(env, "Lib", "site-packages"))
    deps: Dict[str, Dependency] = {}
    for dist in metadata.distributions(path=site_dirs):
        name, version = dist.metadata.get("Name"), dist.version
        if name and version:
            deps[canonicalize_name(name)] = Dependency("PyPI", name, version, env)
    return list(deps.values())


# --- Querying OSV ---------------------------------------------------------------

def _fixed_version(vuln: Dict, dep: Dependency) -> Optional[str]:
    """The lowest fixed version above the installed one, for this package."""
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
    # An advisory without a published severity is treated as high: it is still a known vulnerability.
    return _GHSA_LEVELS.get(sev, "HIGH")


def _dedupe(vulns: Sequence[Dict]) -> List[Dict]:
    """OSV returns the same issue under several identifiers (GHSA, PYSEC, CVE). Keep one, preferring GHSA."""
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
    Vulnerabilities per dependency. Raises VulnDBUnavailable when OSV does not respond.

    A batch query (up to 500 dependencies per request) first tells which ones are affected;
    then, for those only, an individual query fetches the full advisories, since the batch
    endpoint returns only IDs.
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
    """The declared constraint that prevents installing the fixed version, if any."""
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
    """One finding per (dependency, vulnerability), naming the fix and any constraint that blocks it."""
    findings = []
    for dep in deps:
        for vuln in results.get(dep.key, []):
            fix = f" Fixed in {vuln.fixed}." if vuln.fixed else " No fixed version published."
            summary = f": {vuln.summary}" if vuln.summary else ""
            where = ""
            if dep.line == 0 and os.path.isfile(os.path.join(dep.file, "pyvenv.cfg")):
                where = f" (installed in {os.path.relpath(dep.file, root) if root else dep.file})"
            blocking = _blocking_constraint(dep, vuln.fixed, constraints)
            note = ""
            if blocking:
                origin = os.path.relpath(blocking[2], root) if root else blocking[2]
                note = f" The constraint '{dep.name}{blocking[1]}' in {origin} prevents installing that version."
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
    checked: int        # dependencies with an exact version that were queried (manifests + environments)
    unpinned: int       # declared dependencies without an exact version
    error: Optional[str] = None
    environments: List[str] = field(default_factory=list)
    installed: int = 0  # packages read from the installed environments
    blocked_fixes: List[Tuple[str, str, str, str]] = field(default_factory=list)  # (package, constraint, file, fixed version)

    @property
    def unchecked(self) -> bool:
        """Nothing could be checked, so reporting "0 vulnerabilities" would be misleading."""
        return self.error is None and self.checked == 0


def scan(manifests: Sequence[str], *, environments: Sequence[str] = (), timeout: float = 15.0,
         root: str = "") -> VulnScan:
    """
    Read the manifests and installed environments, then query OSV. Never raises: a network
    failure ends up in .error and an unreadable manifest becomes an ERROR finding.
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
            # A constraint can only block a fix that exists, hence the vuln.fixed check.
            if c and vuln.fixed and (dep.name, c[1], c[2], vuln.fixed) not in blocked:
                blocked.append((dep.name, c[1], c[2], vuln.fixed))
    # Each constraint is reported once, with the highest fixed version it blocks.
    worst: Dict[Tuple[str, str, str], str] = {}
    for name, spec, file, fixed in blocked:
        key = (name, spec, file)
        if key not in worst or Version(fixed) > Version(worst[key]):
            worst[key] = fixed
    findings.extend(Finding(path, 0, "ERROR", f"Could not read: {msg}", "VULN-READ-ERROR") for path, msg in errors)
    return VulnScan(findings, list(manifests), len({d.key for d in deps}), unpinned,
                    environments=list(environments), installed=installed,
                    blocked_fixes=[(n, s, f, v) for (n, s, f), v in worst.items()])
