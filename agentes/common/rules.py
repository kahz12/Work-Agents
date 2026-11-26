"""
Nombres de regla y categoría de cada hallazgo.

Los hallazgos llevan un `rule_id` amplio (SAST-MEDIO, SOLID-GUARD, SECRET...) que forma parte de
la huella de la línea base y no conviene cambiar. Este módulo les da además:

- **nombres de regla**: con qué palabras se puede referir a un hallazgo, por ejemplo para
  silenciarlo en su línea. Son su `rule_id` y sus prefijos (SAST, SOLID), su regla concreta
  (shell, docstring...) y el `ruleId` del informe SARIF (SAST-SHELL), que es el que se ve en
  GitHub Code Scanning;
- **categoría**: `security` si es un riesgo de seguridad y `quality` si es de calidad del código
  (fiabilidad, mantenibilidad o rendimiento). Sirve para que un aviso de seguridad no quede
  escondido entre docstrings que faltan.
"""
from __future__ import annotations

import re
from typing import Any, Dict, FrozenSet, Iterable, List, Set

from .audits import topic
from .findings import FindingLike, as_finding

# Reglas del análisis estático que no tienen tema de fusión (ver audits._TOPICS), reconocidas
# por su mensaje.
_MESSAGE_RULES = [
    ("docstring", re.compile(r"carece de docstring", re.I)),
    ("too-many-args", re.compile(r"recibe \d+ argumentos", re.I)),
    ("open-without-with", re.compile(r"fuera de un context manager", re.I)),
    ("toctou", re.compile(r"TOCTOU")),
    ("path-traversal", re.compile(r"Path Traversal", re.I)),
    ("no-timeout", re.compile(r"sin 'timeout'", re.I)),
    ("tls-verify", re.compile(r"verify=False")),
    ("jinja", re.compile(r"Jinja", re.I)),
    ("insecure-random", re.compile(r"m[oó]dulo 'random'", re.I)),
    ("hardcoded-secret", re.compile(r"Posible secreto hardcodeado", re.I)),
    ("shell", re.compile(r"Ejecuci[oó]n insegura de comandos con 'os\.", re.I)),
    ("global-state", re.compile(r"estado mutable global", re.I)),
    ("too-many-branches", re.compile(r"\[OCP\].*bifurcaciones", re.I)),
    ("syntax-error", re.compile(r"^Error de sintaxis|^Error durante el an[aá]lisis", re.I)),
]

RULE_NAMES: FrozenSet[str] = frozenset(
    ["exception-swallow", "broad-except", "bare-except", "mutable-default", "blocking-async", "weak-hash",
     "dynamic-exec", "shell", "pickle", "yaml-load", "assert", "sql"]
    + [name for name, _ in _MESSAGE_RULES]
)

SECURITY = "security"
QUALITY = "quality"
CATEGORY_LABELS: Dict[str, str] = {SECURITY: "Seguridad", QUALITY: "Calidad del código"}

# Reglas del análisis estático que son de calidad y no de seguridad.
_QUALITY_RULES = frozenset({
    "docstring", "too-many-args", "mutable-default", "open-without-with", "broad-except", "bare-except",
    "exception-swallow", "blocking-async", "global-state", "too-many-branches", "syntax-error",
})
# rule_id (o su prefijo) de los agentes de calidad. Todo lo demás (secretos, infraestructura,
# dependencias, vulnerabilidades, cabeceras HTTP, logs) es de seguridad.
_QUALITY_RULE_IDS = ("SOLID", "PERF", "METRICS", "TEST-QUALITY", "TESTABILITY", "YAML")


def _prefixes(rule_id: str) -> Set[str]:
    parts = rule_id.lower().split("-") if rule_id else []
    return {"-".join(parts[:i]) for i in range(1, len(parts) + 1)}


def rule_names(item: FindingLike) -> Set[str]:
    """Nombres con los que se puede referir a un hallazgo, en minúsculas."""
    from .reporting import _sarif_rule_id

    finding = as_finding(item)
    names = _prefixes(finding.rule_id) | _prefixes(_sarif_rule_id(finding.to_dict()))
    name = topic(finding)
    if name:
        names.add(name)
    names.update(rule for rule, pattern in _MESSAGE_RULES if pattern.search(finding.message))
    return names


def category(item: FindingLike) -> str:
    """`security` o `quality`. Lo que no se reconoce como calidad cuenta como seguridad."""
    finding = as_finding(item)
    rule_id = finding.rule_id.upper()
    if any(rule_id == prefix or rule_id.startswith(prefix + "-") for prefix in _QUALITY_RULE_IDS):
        return QUALITY
    if finding.message.startswith("[bandit]") and not topic(finding):
        return SECURITY
    names = {topic(finding)} | {rule for rule, pattern in _MESSAGE_RULES if pattern.search(finding.message)}
    return QUALITY if names & _QUALITY_RULES else SECURITY


def annotate(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Añade la clave `category` a cada hallazgo en forma de diccionario. Devuelve la misma lista."""
    for item in items:
        item["category"] = category(item)
    return items


def count_by_category(items: Iterable[FindingLike]) -> Dict[str, int]:
    counts = {SECURITY: 0, QUALITY: 0}
    for item in items:
        counts[category(item)] += 1
    return counts
