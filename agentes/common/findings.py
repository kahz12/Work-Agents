"""
The finding type shared by every agent, and severity normalisation.

Each auditor returns results in whatever shape suits it (three- or four-element tuples, with
the severity in different positions). This module defines the single type that the
orchestrator, the reports and the CLI work with.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Union

# Most to least severe. Unknown levels are treated as MEDIUM.
SEVERITY_ORDER = ["CRITICAL", "ERROR", "HIGH", "MEDIUM", "LOW", "INFO", "OK"]
BLOCKING_LEVELS = frozenset({"CRITICAL", "ERROR", "HIGH"})
SILENT_LEVELS = frozenset({"INFO", "OK"})

# Spellings used by third-party tools (Bandit, OSV, linters) mapped onto SEVERITY_ORDER.
_LEVEL_ALIASES = {
    "MODERATE": "MEDIUM", "WARNING": "MEDIUM", "WARN": "MEDIUM",
    "INFORMATION": "INFO", "FAIL": "ERROR", "FAILED": "ERROR",
}


def normalize_level(level: Any) -> str:
    """Map the severity spellings used by the different agents onto SEVERITY_ORDER."""
    text = str(level or "").strip().upper()
    text = _LEVEL_ALIASES.get(text, text)
    return text if text in SEVERITY_ORDER else "MEDIUM"


def severity_rank(level: Any) -> int:
    """Index in SEVERITY_ORDER: lower means more severe."""
    return SEVERITY_ORDER.index(normalize_level(level))


@dataclass
class Finding:
    """
    A finding reported by any agent.

    line is 1 or greater when the line is known, and 0 when it does not apply (an HTTP
    header, a whole file). level is normalised when the object is created.
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
        """Shape used by the JSON and SARIF reports (schema agentes.pipeline.v1)."""
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
            level=data.get("level", "MEDIUM"),
            message=data.get("message", ""),
            rule_id=data.get("rule_id", "") or "",
        )


FindingLike = Union[Finding, Mapping[str, Any]]


def as_finding(item: FindingLike) -> Finding:
    return item if isinstance(item, Finding) else Finding.from_dict(item)


def as_dicts(findings: Iterable[FindingLike]) -> List[Dict[str, Any]]:
    return [as_finding(f).to_dict() for f in findings]


def count_by_level(findings: Iterable[FindingLike]) -> Dict[str, int]:
    """Count findings per severity, ordered from most to least severe."""
    counts: Dict[str, int] = {}
    for item in findings:
        lvl = as_finding(item).level
        counts[lvl] = counts.get(lvl, 0) + 1
    return {lvl: counts[lvl] for lvl in SEVERITY_ORDER if lvl in counts}


def blocking_count(findings: Iterable[FindingLike]) -> int:
    return sum(1 for f in findings if as_finding(f).blocking)
