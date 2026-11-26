"""
Hallazgos silenciados en su propia línea.

    resultado = eval(expr)  # agentes: ignore[dynamic-exec] - la expresión se valida antes
    token = "valor-de-prueba"  # agentes: ignore

`# agentes: ignore` silencia todo lo que se señale en esa línea. Con corchetes silencia solo
las reglas indicadas, separadas por comas. Cada una puede ser:

- el `rule_id` de los informes JSON (SECRET, SOLID-GUARD, DEPS-PIP...) o su prefijo (SAST,
  SOLID, K8S);
- el `ruleId` del informe SARIF, el que muestra GitHub Code Scanning (SAST-SHELL, SAST-TOCTOU);
- el nombre de la regla, de `rules.RULE_NAMES` (broad-except, shell, weak-hash, docstring...).

También se respetan los códigos de ruff/flake8 (`# noqa: BLE001`) y de Bandit (`# nosec B602`)
que equivalen a una regla propia, para no repetir la misma justificación con dos sintaxis:

- `# noqa` sin códigos no silencia nada: suele estar ahí por otra herramienta (una línea larga,
  un import) y ocultaría hallazgos de seguridad sin que nadie lo decidiera.
- `# nosec` sin códigos silencia el análisis estático de la línea (SAST), como hace Bandit,
  pero no los secretos: para eso hay que escribir `# agentes: ignore[SECRET]`.

El marcador tiene que estar en la línea que indica el hallazgo. Los hallazgos sin línea (un
archivo entero, una cabecera HTTP) solo se pueden aceptar con la línea base.
"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Set, TypeVar

from .findings import FindingLike, as_finding
from .rules import rule_names

_AGENTES_RE = re.compile(r"#\s*agentes\s*:\s*ignore\b(?:\[([^\]]*)\])?", re.IGNORECASE)
_NOQA_RE = re.compile(r"#\s*noqa\b(?:\s*:\s*([A-Z]+[0-9]+(?:\s*,\s*[A-Z]+[0-9]+)*))?", re.IGNORECASE)
_NOSEC_RE = re.compile(r"#\s*nosec\b(?:\s*:?\s*(B[0-9]{3}(?:\s*,?\s*B[0-9]{3})*))?", re.IGNORECASE)

# Códigos de Bandit y la regla propia equivalente. Las reglas S de ruff son las de Bandit con
# otra letra (B602 -> S602), así que se derivan de esta tabla.
_BANDIT_EQUIVALENTS: Dict[str, Set[str]] = {
    "B101": {"assert"},
    "B102": {"dynamic-exec"},
    "B105": {"hardcoded-secret"},
    "B106": {"hardcoded-secret"},
    "B107": {"hardcoded-secret"},
    "B110": {"exception-swallow"},
    "B112": {"exception-swallow"},
    "B113": {"no-timeout"},
    "B301": {"pickle"},
    "B303": {"weak-hash"},
    "B307": {"dynamic-exec"},
    "B311": {"insecure-random"},
    "B324": {"weak-hash"},
    "B403": {"pickle"},
    "B501": {"tls-verify"},
    "B506": {"yaml-load"},
    "B602": {"shell"},
    "B604": {"shell"},
    "B605": {"shell"},
    "B608": {"sql"},
    "B701": {"jinja"},
}
_LINT_EQUIVALENTS: Dict[str, Set[str]] = {
    **{"S" + code[1:]: names for code, names in _BANDIT_EQUIVALENTS.items()},
    "BLE001": {"broad-except", "exception-swallow"},
    "E722": {"bare-except"},
    "B006": {"mutable-default"},
    "SIM115": {"open-without-with"},
    "PLR0912": {"too-many-branches"},
    "PLR0913": {"too-many-args"},
    "PLW0603": {"global-state"},
    "D102": {"docstring"},
    "D103": {"docstring"},
}

# Lo que silencia cada marcador sin códigos.
_ALL = "*"
_ALL_SAST = "sast:*"


def _split_codes(text: Optional[str]) -> List[str]:
    return [code.upper() for code in re.split(r"[\s,]+", text or "") if code]


def markers(line: str) -> Set[str]:
    """
    Qué silencia una línea: nombres de regla, rule_id o prefijos en mayúsculas, "*" (todo) o
    "sast:*" (todo el análisis estático). Vacío si la línea no tiene ningún marcador.
    """
    if "#" not in line:
        return set()
    found: Set[str] = set()
    for match in _AGENTES_RE.finditer(line):
        if match.group(1) is None:
            found.add(_ALL)
        else:
            found.update(token.strip().lower() for token in match.group(1).split(",") if token.strip())
    for match in _NOQA_RE.finditer(line):
        for code in _split_codes(match.group(1)):
            found.update(_LINT_EQUIVALENTS.get(code, ()))
    for match in _NOSEC_RE.finditer(line):
        codes = _split_codes(match.group(1))
        if not codes:
            found.add(_ALL_SAST)
        for code in codes:
            found.update(_BANDIT_EQUIVALENTS.get(code, ()))
    return found


def is_suppressed(item: FindingLike, line_markers: Set[str]) -> bool:
    if not line_markers:
        return False
    if _ALL in line_markers:
        return True
    finding = as_finding(item)
    if _ALL_SAST in line_markers and finding.rule_id.upper().startswith("SAST"):
        return True
    return bool(rule_names(finding) & line_markers)


T = TypeVar("T", bound=FindingLike)


class InlineSuppressions:
    """
    Filtra los hallazgos silenciados en su línea y cuenta cuántos. Lee cada archivo una sola
    vez; un archivo que no se puede leer no silencia nada.
    """

    def __init__(self) -> None:
        self.suppressed = 0
        self._lines: Dict[str, List[str]] = {}

    def _source_line(self, path: str, line: int) -> str:
        if path not in self._lines:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    self._lines[path] = fh.read().splitlines()
            except OSError:
                self._lines[path] = []
        lines = self._lines[path]
        return lines[line - 1] if 0 < line <= len(lines) else ""

    def silences(self, item: FindingLike) -> bool:
        """True si el hallazgo está silenciado en su línea. Cada True cuenta en suppressed."""
        finding = as_finding(item)
        if not finding.line or not finding.file or "://" in finding.file:
            return False
        if is_suppressed(finding, markers(self._source_line(finding.file, finding.line))):
            self.suppressed += 1
            return True
        return False

    def filter(self, findings: Iterable[T]) -> List[T]:
        """Devuelve los hallazgos que no están silenciados, en el mismo orden y con su tipo."""
        return [item for item in findings if not self.silences(item)]
