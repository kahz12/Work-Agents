"""
Hallazgo común a todos los agentes y normalización de severidades.

Cada auditor devuelve sus resultados con la forma que le resulta natural (tuplas de
tres o cuatro elementos, con la severidad en posiciones distintas). Este módulo define
el tipo único con el que trabajan el orquestador, los informes y el CLI.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Union

# De más grave a menos grave. Los niveles desconocidos se tratan como MEDIO.
SEVERITY_ORDER = ["CRITICO", "ERROR", "ALTO", "MEDIO", "BAJO", "INFORMACION", "OK"]
BLOCKING_LEVELS = frozenset({"CRITICO", "ERROR", "ALTO"})
SILENT_LEVELS = frozenset({"INFORMACION", "OK"})

_LEVEL_ALIASES = {
    "CRÍTICO": "CRITICO", "CRITICAL": "CRITICO", "HIGH": "ALTO", "MEDIUM": "MEDIO",
    "MODERATE": "MEDIO", "LOW": "BAJO", "INFO": "INFORMACION", "INFORMACIÓN": "INFORMACION",
    "FALLO": "ERROR", "WARNING": "MEDIO", "ADVERTENCIA": "MEDIO",
}


def normalize_level(level: Any) -> str:
    """Unifica las variantes de severidad que devuelven los distintos agentes."""
    text = str(level or "").strip().upper()
    text = _LEVEL_ALIASES.get(text, text)
    return text if text in SEVERITY_ORDER else "MEDIO"


def severity_rank(level: Any) -> int:
    """Posición en SEVERITY_ORDER: menor es más grave."""
    return SEVERITY_ORDER.index(normalize_level(level))


@dataclass
class Finding:
    """
    Un hallazgo de cualquier agente.

    line es 1 o más cuando se conoce la línea y 0 cuando no aplica (una cabecera HTTP,
    un archivo entero). level se normaliza al crear el objeto.
    """

    file: str
    line: int
    level: str
    message: str
    rule_id: str = ""

    def __post_init__(self) -> None:
        self.level = normalize_level(self.level)
        self.line = self.line if isinstance(self.line, int) and self.line > 0 else 0
        self.file = str(self.file)
        self.message = str(self.message)

    @property
    def blocking(self) -> bool:
        return self.level in BLOCKING_LEVELS

    @property
    def silent(self) -> bool:
        return self.level in SILENT_LEVELS

    def to_dict(self) -> Dict[str, Any]:
        """Forma usada en los informes JSON y SARIF (esquema agentes.pipeline.v1)."""
        return {
            "file": self.file,
            "line": self.line,
            "level": self.level,
            "message": self.message,
            "rule_id": self.rule_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Finding":
        return cls(
            file=data.get("file", ""),
            line=data.get("line", 0),
            level=data.get("level", "MEDIO"),
            message=data.get("message", ""),
            rule_id=data.get("rule_id", "") or "",
        )


FindingLike = Union[Finding, Mapping[str, Any]]


def as_finding(item: FindingLike) -> Finding:
    return item if isinstance(item, Finding) else Finding.from_dict(item)


def as_dicts(findings: Iterable[FindingLike]) -> List[Dict[str, Any]]:
    return [as_finding(f).to_dict() for f in findings]


def count_by_level(findings: Iterable[FindingLike]) -> Dict[str, int]:
    """Cuenta por severidad, en orden de gravedad."""
    counts: Dict[str, int] = {}
    for item in findings:
        lvl = as_finding(item).level
        counts[lvl] = counts.get(lvl, 0) + 1
    return {lvl: counts[lvl] for lvl in SEVERITY_ORDER if lvl in counts}


def blocking_count(findings: Iterable[FindingLike]) -> int:
    return sum(1 for f in findings if as_finding(f).blocking)
