"""
Línea base: hallazgos aceptados a conciencia que no deben hacer fallar el pipeline.

Sirve para adoptar la herramienta en un proyecto que ya tiene hallazgos (o datos de prueba
que lo parecen, como un corpus de secretos falsos) y que el CI falle solo con los nuevos.

Cada hallazgo se identifica por una huella de su regla, su archivo (relativo a la raíz
analizada) y su mensaje sin números de línea, de modo que la línea base sigue valiendo
aunque el código se desplace. Si un mismo hallazgo aparece más veces de las registradas,
las apariciones de más se tratan como nuevas.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from typing import Any, Dict, Iterable, List, Mapping, Tuple

from .findings import as_finding

SCHEMA = "agentes.baseline.v1"


def _relative(path: str, root: str) -> str:
    if not path or "://" in path:
        return path
    full = os.path.abspath(path)
    root_abs = os.path.abspath(root)
    if full == root_abs or full.startswith(root_abs.rstrip(os.sep) + os.sep):
        return os.path.relpath(full, root_abs).replace(os.sep, "/")
    return path.replace(os.sep, "/")


def _normalize_message(message: str) -> str:
    text = re.sub(r"L[ií]nea\s+\d+", "Línea N", message)
    return re.sub(r"\s+", " ", text).strip()


def fingerprint(finding: Mapping[str, Any], root: str) -> str:
    f = as_finding(finding)
    raw = f"{f.rule_id}|{_relative(f.file, root)}|{_normalize_message(f.message)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


class Baseline:
    """Conjunto de huellas aceptadas, con cuántas veces se acepta cada una."""

    def __init__(self, counts: Mapping[str, int], root: str, path: str = "") -> None:
        self._remaining = Counter(counts)
        self.root = root
        self.path = path
        self.suppressed = 0

    @classmethod
    def load(cls, path: str, root: str) -> "Baseline":
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError as exc:
            raise ValueError(f"No existe la línea base {path}") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"No se pudo leer la línea base {path}: {exc}") from exc
        if not isinstance(data, dict) or data.get("schema") != SCHEMA:
            raise ValueError(f"{path} no es una línea base de agentes ({SCHEMA}).")
        counts = Counter(entry["fingerprint"] for entry in data.get("entries", []) if "fingerprint" in entry)
        return cls(counts, root, path)

    def filter(self, findings: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        """Devuelve los hallazgos nuevos; los aceptados se descuentan y se cuentan en suppressed."""
        kept = []
        for item in findings:
            fp = fingerprint(item, self.root)
            if self._remaining[fp] > 0:
                self._remaining[fp] -= 1
                self.suppressed += 1
            else:
                kept.append(dict(item))
        return kept

    def unused(self) -> int:
        """Entradas de la línea base que ya no aparecen: conviene regenerarla para retirarlas."""
        return sum(n for n in self._remaining.values() if n > 0)


def write_baseline(path: str, findings: Iterable[Mapping[str, Any]], root: str, *, version: str = "") -> Tuple[int, int]:
    """
    Guarda como aceptados los hallazgos que harían fallar el pipeline (altos, críticos,
    errores y secretos). Los medios y bajos no hacen fallar, así que no hace falta guardarlos.
    Devuelve (guardados, omitidos).
    """
    entries, skipped = [], 0
    for item in findings:
        f = as_finding(item)
        if f.blocking or f.rule_id.startswith("SECRET"):
            entries.append({
                "fingerprint": fingerprint(item, root),
                "rule_id": f.rule_id,
                "file": _relative(f.file, root),
                "level": f.level,
                "message": _normalize_message(f.message),
            })
        else:
            skipped += 1
    entries.sort(key=lambda e: (e["file"], e["rule_id"], e["message"]))
    data = {
        "schema": SCHEMA,
        "generated_by": f"agentes {version}".strip(),
        "note": "Hallazgos revisados y aceptados. Regenera con: agentes pipeline . --write-baseline <archivo>",
        "entries": entries,
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    return len(entries), skipped
