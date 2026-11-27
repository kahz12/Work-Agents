"""
Rule names and category of each finding.

Findings carry a coarse `rule_id` (SAST-MEDIUM, SOLID-GUARD, SECRET...) that is part of the
baseline fingerprint, so it should stay stable. On top of that, this module provides:

- **rule names**: the words that can refer to a finding, for example to suppress it on its
  own line. They are its `rule_id` and that id's prefixes (SAST, SOLID), its specific rule
  (shell, docstring...) and the `ruleId` used in the SARIF report (SAST-SHELL), which is what
  GitHub Code Scanning displays;
- **category**: `security` for a security risk and `quality` for a code-quality issue
  (reliability, maintainability or performance). It keeps a security warning from getting
  lost among missing docstrings.
"""
from __future__ import annotations

import re
from typing import Any, Dict, FrozenSet, Iterable, List, Set

from .audits import topic
from .findings import FindingLike, as_finding

# Static-analysis rules that have no merge topic (see audits._TOPICS), recognised by their
# message. The messages come from quality.static_checker and refactor.solid_checker.
_MESSAGE_RULES = [
    ("docstring", re.compile(r"has no docstring", re.I)),
    ("too-many-args", re.compile(r"takes \d+ arguments", re.I)),
    ("open-without-with", re.compile(r"outside a 'with' context manager", re.I)),
    ("toctou", re.compile(r"TOCTOU")),
    ("path-traversal", re.compile(r"path traversal", re.I)),
    ("no-timeout", re.compile(r"without an explicit 'timeout'", re.I)),
    ("tls-verify", re.compile(r"verify=False")),
    ("jinja", re.compile(r"Jinja", re.I)),
    ("insecure-random", re.compile(r"'random' module", re.I)),
    ("hardcoded-secret", re.compile(r"Possible hardcoded secret", re.I)),
    ("shell", re.compile(r"Unsafe command execution with 'os\.", re.I)),
    ("global-state", re.compile(r"global mutable state", re.I)),
    ("too-many-branches", re.compile(r"\[OCP\].*branches", re.I)),
    ("syntax-error", re.compile(r"^Syntax error|^Error during analysis", re.I)),
]

RULE_NAMES: FrozenSet[str] = frozenset(
    ["exception-swallow", "broad-except", "bare-except", "mutable-default", "blocking-async", "weak-hash",
     "dynamic-exec", "shell", "pickle", "yaml-load", "assert", "sql"]
    + [name for name, _ in _MESSAGE_RULES]
)

SECURITY = "security"
QUALITY = "quality"
CATEGORY_LABELS: Dict[str, str] = {SECURITY: "Security", QUALITY: "Code quality"}

# Static-analysis rules that are about code quality rather than security.
_QUALITY_RULES = frozenset({
    "docstring", "too-many-args", "mutable-default", "open-without-with", "broad-except", "bare-except",
    "exception-swallow", "blocking-async", "global-state", "too-many-branches", "syntax-error",
})
# rule_id values (or prefixes) emitted by the quality-oriented agents. Everything else (secrets,
# infrastructure, dependencies, vulnerabilities, HTTP headers, logs) counts as security.
_QUALITY_RULE_IDS = ("SOLID", "PERF", "METRICS", "TEST-QUALITY", "TESTABILITY", "YAML")


def _prefixes(rule_id: str) -> Set[str]:
    parts = rule_id.lower().split("-") if rule_id else []
    return {"-".join(parts[:i]) for i in range(1, len(parts) + 1)}


def rule_names(item: FindingLike) -> Set[str]:
    """Every lowercase name that can be used to refer to a finding."""
    from .reporting import _sarif_rule_id

    finding = as_finding(item)
    names = _prefixes(finding.rule_id) | _prefixes(_sarif_rule_id(finding.to_dict()))
    name = topic(finding)
    if name:
        names.add(name)
    names.update(rule for rule, pattern in _MESSAGE_RULES if pattern.search(finding.message))
    return names


def category(item: FindingLike) -> str:
    """`security` or `quality`. Anything not recognised as quality counts as security."""
    finding = as_finding(item)
    rule_id = finding.rule_id.upper()
    if any(rule_id == prefix or rule_id.startswith(prefix + "-") for prefix in _QUALITY_RULE_IDS):
        return QUALITY
    if finding.message.startswith("[bandit]") and not topic(finding):
        return SECURITY
    names = {topic(finding)} | {rule for rule, pattern in _MESSAGE_RULES if pattern.search(finding.message)}
    return QUALITY if names & _QUALITY_RULES else SECURITY


def annotate(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Add a `category` key to each finding dict in place. Returns the same list."""
    for item in items:
        item["category"] = category(item)
    return items


def count_by_category(items: Iterable[FindingLike]) -> Dict[str, int]:
    counts = {SECURITY: 0, QUALITY: 0}
    for item in items:
        counts[category(item)] += 1
    return counts
