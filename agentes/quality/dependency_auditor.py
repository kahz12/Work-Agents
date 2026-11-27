import json
import os
import re
import warnings
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from .package_index import (
    IndexUnavailable,
    PackageNotFound,
    VersionIndex,
    best_version,
    cached_index,
    is_offline,
    pypi_versions,
)


def package_dependencies(directory: str) -> Set[str]:
    """
    Normalised names of the dependencies declared by the directory's pyproject.toml
    ([project] dependencies and its extras). Empty when there is none or it cannot be read.

    A requirements.txt that repeats them with ranges is not an oversight: it mirrors the
    package's contract, and pinning exact versions in a library would stop it from being
    installed alongside other packages.
    """
    path = os.path.join(directory, "pyproject.toml")
    if not os.path.isfile(path):
        return set()
    from .vulnerabilities import _load_toml

    try:
        project = _load_toml(path).get("project") or {}
    except (OSError, ValueError):
        return set()
    texts = list(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        texts.extend(group)
    names: Set[str] = set()
    for text in texts:
        try:
            names.add(canonicalize_name(Requirement(str(text)).name))
        except InvalidRequirement:
            continue
    return names


@dataclass
class FixPlan:
    """Proposed changes to a requirements.txt. Nothing is written until apply() is called."""

    filepath: str
    original: List[str]
    fixed: List[str]
    changes: List[Tuple[int, str, str]] = field(default_factory=list)      # (line, before, after)
    unresolved: List[Tuple[int, str, str]] = field(default_factory=list)   # (line, package, reason)

    def apply(self) -> None:
        if self.changes:
            with open(self.filepath, "w", encoding="utf-8") as f:
                f.writelines(self.fixed)


class DependencyAuditor:
    """
    Dependency auditor for requirements.txt and package.json.

    Flags unpinned dependencies and open ranges (>=, ~=), and can pin them to the newest
    version published on PyPI that satisfies the declaration. It never invents a version and
    never pins to the lower bound of a range.
    """

    _REQ_RE = re.compile(
        r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9_,\s-]+\])?)\s*"
        r"(?:(==|>=|<=|~=|!=|>|<)\s*([A-Za-z0-9_.+!*,-]+))?\s*"
        r"(;[^#]*)?$"
    )

    @staticmethod
    def _parse_requirement_line_full(line: str) -> Optional[Tuple[str, Optional[str], Optional[str], str, str]]:
        """
        Split a requirement line into (name, operator, version, environment marker, trailing
        comment). None for blank lines, comments and pip options (-r, -e, --index-url...).
        """
        raw = line.rstrip("\r\n")
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            return None
        cmt_match = re.match(r"^(.*?)(\s+#.*)?$", raw)
        body = cmt_match.group(1) if cmt_match else raw
        comment = (cmt_match.group(2) or "") if cmt_match else ""
        m = DependencyAuditor._REQ_RE.match(body.strip())
        if not m:
            return None
        name, op, ver = m.group(1), m.group(2), m.group(3)
        marker = (m.group(4) or "").strip()
        return name, op, ver, marker, comment

    @staticmethod
    def _parse_requirement_line(line: str) -> Optional[Tuple[str, Optional[str], Optional[str]]]:
        """
        (name, operator, version), or None when the line is not a requirement.
        """
        full = DependencyAuditor._parse_requirement_line_full(line)
        if not full:
            return None
        return full[0], full[1], full[2]

    @staticmethod
    def resolve_package_version(
        package_name: str,
        *,
        specifier: str = "",
        use_pypi: bool = True,
        timeout: float = 10.0,
        index: Optional[VersionIndex] = None,
    ) -> Optional[str]:
        """
        The newest stable, non-yanked version that satisfies specifier.

        None when it cannot be known (no network, use_pypi=False or unknown package). There is
        deliberately no local catalogue: a hardcoded version list goes stale and ends up
        recommending versions with known vulnerabilities.
        """
        if index is None:
            if not use_pypi or is_offline():
                return None
            index = lambda name: pypi_versions(name, timeout=timeout)  # noqa: E731
        try:
            return best_version(index(package_name), specifier)
        except (IndexUnavailable, PackageNotFound):
            return None

    @staticmethod
    def audit_requirements_txt(filepath: str) -> List[Tuple[str, str, str]]:
        """
        Audit a requirements.txt file.
        Returns a list of (package, risk level, recommendation) tuples. Ranges that mirror the
        dependencies declared in a sibling pyproject.toml are not reported.
        """
        findings = []
        if not os.path.exists(filepath):
            return [("N/A", "INFO", f"File {filepath} not found.")]

        declared = package_dependencies(os.path.dirname(os.path.abspath(filepath)))
        with open(filepath, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, 1):
                parsed = DependencyAuditor._parse_requirement_line(line)
                if not parsed:
                    continue
                name, op, ver = parsed
                if op in (">=", "~=") and canonicalize_name(name.split("[", 1)[0]) in declared:
                    continue
                if op is None:
                    findings.append((
                        name,
                        "MEDIUM",
                        f"Line {line_idx}: dependency '{name}' does not pin a version (==x.y.z). Installs can pick up unwanted changes."
                    ))
                elif op == ">=":
                    findings.append((
                        f"{name}{op}{ver}",
                        "LOW",
                        f"Line {line_idx}: dependency '{name}{op}{ver}' uses '>='. Pin the exact version for reproducible environments."
                    ))
                elif op == "~=":
                    findings.append((
                        f"{name}{op}{ver}",
                        "LOW",
                        f"Line {line_idx}: dependency '{name}{op}{ver}' uses '~='. Pin with == for reproducible builds."
                    ))

        if not findings:
            findings.append(("ALL", "OK", "Every dependency is pinned to an exact version."))

        return findings

    @staticmethod
    def plan_requirements_fix(
        filepath: str,
        *,
        pin_ranges: bool = True,
        index: Optional[VersionIndex] = None,
        timeout: float = 10.0,
    ) -> "FixPlan":
        """
        Work out the changes without writing anything.

        - No version: `==` the newest published version.
        - `>=`, `~=` or `>` (with pin_ranges): `==` the newest version that satisfies the range.
        Anything that cannot be resolved (no network, unknown package, no version satisfies
        the range) is left as it is and reported in `unresolved`. Environment markers and
        trailing comments are preserved.
        """
        if index is None:
            if is_offline():
                index = DependencyAuditor._offline_index
            else:
                index = lambda name: pypi_versions(name, timeout=timeout)  # noqa: E731
        lookup = cached_index(index)

        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()

        plan = FixPlan(filepath=filepath, original=lines, fixed=list(lines))
        for idx, line in enumerate(lines):
            parsed = DependencyAuditor._parse_requirement_line_full(line)
            if not parsed:
                continue
            name, op, ver, marker, comment = parsed
            if op is None:
                specifier = ""
            elif pin_ranges and op in (">=", "~=", ">"):
                specifier = f"{op}{ver}"
            else:
                continue
            try:
                new_ver = best_version(lookup(name), specifier)
            except PackageNotFound:
                plan.unresolved.append((idx + 1, name, "not found on PyPI"))
                continue
            except IndexUnavailable as exc:
                plan.unresolved.append((idx + 1, name, str(exc)))
                continue
            if new_ver is None:
                plan.unresolved.append((idx + 1, name, f"no published version satisfies '{specifier}'"))
                continue
            marker_part = f" {marker}" if marker else ""
            newline = "\n" if line.endswith("\n") else ""
            plan.fixed[idx] = f"{name}=={new_ver}{marker_part}{comment}{newline}"
            plan.changes.append((idx + 1, line.rstrip("\r\n"), plan.fixed[idx].rstrip("\r\n")))
        return plan

    @staticmethod
    def _offline_index(name: str) -> List[str]:
        raise IndexUnavailable("offline mode (AGENTES_OFFLINE)")

    @staticmethod
    def auto_fix_requirements_txt(
        filepath: str,
        default_version: Optional[str] = None,
        *,
        pin_ranges: bool = True,
        use_pypi: bool = True,
        index: Optional[VersionIndex] = None,
    ) -> Tuple[str, int]:
        """
        Pin the versions in a requirements.txt and rewrite it. Returns (path, number of changes).

        default_version is accepted so existing callers keep working, but it is ignored (with
        a DeprecationWarning): pinning a made-up version can point at one that does not exist
        or has known vulnerabilities. With use_pypi=False and no index, nothing changes.
        """
        if default_version is not None:
            warnings.warn(
                "default_version has no effect: versions are resolved on PyPI.",
                DeprecationWarning, stacklevel=2,
            )
        if not os.path.exists(filepath):
            return filepath, 0
        if index is None and not use_pypi:
            return filepath, 0
        plan = DependencyAuditor.plan_requirements_fix(filepath, pin_ranges=pin_ranges, index=index)
        plan.apply()
        return filepath, len(plan.changes)

    @staticmethod
    def audit_package_json(filepath: str) -> List[Tuple[str, str, str]]:
        """
        Audit a Node.js package.json: dependencies and devDependencies declared with '^', '~'
        or '*' instead of an exact version.
        """
        findings = []
        if not os.path.exists(filepath):
            return [("N/A", "INFO", f"File {filepath} not found.")]

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})
            all_deps = {**deps, **dev_deps}

            for pkg, ver in all_deps.items():
                if ver.startswith("^") or ver.startswith("~") or ver == "*":
                    findings.append((
                        pkg,
                        "MEDIUM",
                        f"Version '{ver}' of '{pkg}' uses a wildcard ('^', '~', '*'). Pinning the exact version makes builds stable and reproducible."
                    ))

            if not findings:
                findings.append(("ALL", "OK", "Every dependency in package.json has an exact version."))

        except Exception as e:
            findings.append(("PACKAGE.JSON", "ERROR", f"Could not parse the file: {str(e)}"))

        return findings
