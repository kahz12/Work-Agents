"""
Findings suppressed on their own line.

    result = eval(expr)  # agentes: ignore[dynamic-exec] - expr is validated above
    token = "test-value"  # agentes: ignore

`# agentes: ignore` suppresses everything reported on that line. With brackets it only
suppresses the listed rules, separated by commas. Each one can be:

- the `rule_id` from the JSON reports (SECRET, SOLID-GUARD, DEPS-PIP...) or a prefix of it
  (SAST, SOLID, K8S);
- the `ruleId` from the SARIF report, the one GitHub Code Scanning shows (SAST-SHELL,
  SAST-TOCTOU);
- the rule name from `rules.RULE_NAMES` (broad-except, shell, weak-hash, docstring...).

Ruff/flake8 codes (`# noqa: BLE001`) and Bandit codes (`# nosec B602`) that map onto one of
our rules are honoured too, so the same justification does not have to be written twice in
two syntaxes:

- `# noqa` without codes suppresses nothing: it is usually there for another tool (a long
  line, an import), and honouring it would hide security findings nobody chose to accept.
- `# nosec` without codes suppresses static analysis (SAST) on that line, as Bandit does, but
  not secrets: those need an explicit `# agentes: ignore[SECRET]`.

The marker has to be on the line the finding points at. Findings without a line (a whole
file, an HTTP header) can only be accepted through the baseline.
"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Set, TypeVar

from .findings import FindingLike, as_finding
from .rules import rule_names

_AGENTES_RE = re.compile(r"#\s*agentes\s*:\s*ignore\b(?:\[([^\]]*)\])?", re.IGNORECASE)
_NOQA_RE = re.compile(r"#\s*noqa\b(?:\s*:\s*([A-Z]+[0-9]+(?:\s*,\s*[A-Z]+[0-9]+)*))?", re.IGNORECASE)
_NOSEC_RE = re.compile(r"#\s*nosec\b(?:\s*:?\s*(B[0-9]{3}(?:\s*,?\s*B[0-9]{3})*))?", re.IGNORECASE)

# Bandit codes and the equivalent rule names of our own. Ruff's S rules are Bandit's rules
# under a different letter (B602 -> S602), so they are derived from this table.
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

# What a marker without codes suppresses.
_ALL = "*"
_ALL_SAST = "sast:*"


def _split_codes(text: Optional[str]) -> List[str]:
    return [code.upper() for code in re.split(r"[\s,]+", text or "") if code]


def markers(line: str) -> Set[str]:
    """
    What a source line suppresses: rule names, rule_ids or prefixes (lowercased), "*" (all) or
    "sast:*" (all static analysis). Empty when the line carries no marker.
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
    Drops findings suppressed on their own line and counts how many were dropped. Each file is
    read once; a file that cannot be read suppresses nothing.
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
        """True when the finding is suppressed on its line. Every True is counted in `suppressed`."""
        finding = as_finding(item)
        if not finding.line or not finding.file or "://" in finding.file:
            return False
        if is_suppressed(finding, markers(self._source_line(finding.file, finding.line))):
            self.suppressed += 1
            return True
        return False

    def filter(self, findings: Iterable[T]) -> List[T]:
        """Return the findings that are not suppressed, in the same order and with the same type."""
        return [item for item in findings if not self.silences(item)]
