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
    Nombres normalizados de las dependencias que declara el pyproject.toml del directorio
    ([project] dependencies y sus extras). Vacío si no hay o no se puede leer.

    Un requirements.txt que las repite con rangos no es un descuido: copia el contrato del
    paquete, y en una biblioteca fijar versiones exactas impediría instalarla junto a otras.
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
    """Cambios propuestos sobre un requirements.txt."""

    filepath: str
    original: List[str]
    fixed: List[str]
    changes: List[Tuple[int, str, str]] = field(default_factory=list)      # (línea, antes, después)
    unresolved: List[Tuple[int, str, str]] = field(default_factory=list)   # (línea, paquete, motivo)

    def apply(self) -> None:
        if self.changes:
            with open(self.filepath, "w", encoding="utf-8") as f:
                f.writelines(self.fixed)


class DependencyAuditor:
    """
    Auditor defensivo de dependencias y paquetes de software.
    Identifica versiones no fijadas (*unpinned*) y rangos abiertos (>=, ~=), y los fija a
    la versión más reciente publicada en PyPI que cumple lo declarado. Nunca inventa una
    versión ni fija al límite inferior de un rango.
    """

    _REQ_RE = re.compile(
        r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9_,\s-]+\])?)\s*"
        r"(?:(==|>=|<=|~=|!=|>|<)\s*([A-Za-z0-9_.+!*,-]+))?\s*"
        r"(;[^#]*)?$"
    )

    @staticmethod
    def _parse_requirement_line_full(line: str) -> Optional[Tuple[str, Optional[str], Optional[str], str, str]]:
        """
        Retorna (nombre, operador, versión, marcador, comentario) o None si no aplica.
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
        Retorna (nombre, operador, versión) o None si no es una línea de requisito.
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
        La versión más reciente, estable y no retirada que cumple specifier.

        None si no se puede saber (sin red, use_pypi=False o paquete inexistente). No hay
        catálogo local: una lista fija de versiones envejece y acaba recomendando versiones
        con vulnerabilidades conocidas.
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
        Audita un archivo requirements.txt.
        Retorna lista de (Nombre_Paquete, Nivel_Riesgo, Recomendación).
        """
        findings = []
        if not os.path.exists(filepath):
            return [("N/A", "INFORMACION", f"Archivo {filepath} no encontrado.")]

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
                        "MEDIO",
                        f"Línea {line_idx}: La dependencia '{name}' no especifica una versión fija (==x.y.z). Esto puede causar cambios no deseados al instalar."
                    ))
                elif op == ">=":
                    findings.append((
                        f"{name}{op}{ver}",
                        "BAJO",
                        f"Línea {line_idx}: La dependencia '{name}{op}{ver}' usa '>='. Se recomienda fijar la versión exacta para entornos reproducibles."
                    ))
                elif op == "~=":
                    findings.append((
                        f"{name}{op}{ver}",
                        "BAJO",
                        f"Línea {line_idx}: La dependencia '{name}{op}{ver}' usa '~='. Se recomienda fijar == para builds reproducibles."
                    ))

        if not findings:
            findings.append(("TODAS", "OK", "Todas las dependencias están correctamente especificadas con versiones fijas."))

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
        Calcula los cambios sin escribir nada.

        - Sin versión: `==` a la versión más reciente publicada.
        - `>=`, `~=` o `>` (con pin_ranges): `==` a la versión más reciente que cumple el rango.
        Lo que no se puede resolver (sin red, paquete inexistente, ninguna versión cumple el
        rango) se deja como está y se informa en unresolved.
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
                plan.unresolved.append((idx + 1, name, "no existe en PyPI"))
                continue
            except IndexUnavailable as exc:
                plan.unresolved.append((idx + 1, name, str(exc)))
                continue
            if new_ver is None:
                plan.unresolved.append((idx + 1, name, f"ninguna versión publicada cumple '{specifier}'"))
                continue
            marker_part = f" {marker}" if marker else ""
            newline = "\n" if line.endswith("\n") else ""
            plan.fixed[idx] = f"{name}=={new_ver}{marker_part}{comment}{newline}"
            plan.changes.append((idx + 1, line.rstrip("\r\n"), plan.fixed[idx].rstrip("\r\n")))
        return plan

    @staticmethod
    def _offline_index(name: str) -> List[str]:
        raise IndexUnavailable("modo sin conexión (AGENTES_OFFLINE)")

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
        Fija las versiones de un requirements.txt y lo reescribe. Retorna (ruta, correcciones).

        default_version se conserva por compatibilidad y no se usa: fijar una versión
        inventada puede apuntar a una que no existe o que tiene vulnerabilidades.
        Con use_pypi=False y sin index no se cambia nada.
        """
        if default_version is not None:
            warnings.warn(
                "default_version ya no tiene efecto: las versiones se resuelven en PyPI.",
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
        Audita un archivo package.json de Node.js.
        """
        findings = []
        if not os.path.exists(filepath):
            return [("N/A", "INFORMACION", f"Archivo {filepath} no encontrado.")]

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
                        "MEDIO",
                        f"La versión '{ver}' de '{pkg}' usa comodines ('^', '~', '*'). Fijar la versión exacta mejora la estabilidad y reproductibilidad."
                    ))

            if not findings:
                findings.append(("TODAS", "OK", "Todas las dependencias en package.json tienen versiones fijas."))

        except Exception as e:
            findings.append(("PACKAGE.JSON", "ERROR", f"Error al parsear el archivo: {str(e)}"))

        return findings
