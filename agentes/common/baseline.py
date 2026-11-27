"""
Baseline: findings that were reviewed and deliberately accepted, so they do not fail the pipeline.

It lets a project adopt the tool while it still has findings (or test data that looks like
findings, such as a corpus of fake secrets), so that CI only fails on new ones.

Each finding is identified by a fingerprint of its rule, its file (relative to the analysed
root) and its message with line numbers stripped, so the baseline stays valid when code moves
around. If the same finding shows up more times than were recorded, the extra occurrences are
treated as new.
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
    # Messages that embed "Line 12" would change fingerprint whenever code above them moves.
    text = re.sub(r"Line\s+\d+", "Line N", message)
    return re.sub(r"\s+", " ", text).strip()


def fingerprint(finding: Mapping[str, Any], root: str) -> str:
    f = as_finding(finding)
    raw = f"{f.rule_id}|{_relative(f.file, root)}|{_normalize_message(f.message)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


class Baseline:
    """Accepted fingerprints, each with the number of occurrences it covers."""

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
            raise ValueError(f"Baseline {path} does not exist") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Could not read baseline {path}: {exc}") from exc
        if not isinstance(data, dict) or data.get("schema") != SCHEMA:
            raise ValueError(f"{path} is not an agentes baseline ({SCHEMA}).")
        counts = Counter(entry["fingerprint"] for entry in data.get("entries", []) if "fingerprint" in entry)
        return cls(counts, root, path)

    def filter(self, findings: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        """Return the new findings; accepted ones are consumed and counted in `suppressed`."""
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
        """Baseline entries that no longer match anything; regenerating the baseline drops them."""
        return sum(n for n in self._remaining.values() if n > 0)


def write_baseline(path: str, findings: Iterable[Mapping[str, Any]], root: str, *, version: str = "") -> Tuple[int, int]:
    """
    Record as accepted the findings that would fail the pipeline (high, critical, errors and
    secrets). Medium and low findings never fail it, so they are not stored.
    Returns (stored, skipped).
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
        "note": "Reviewed and accepted findings. Regenerate with: agentes pipeline . --write-baseline <file>",
        "entries": entries,
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    return len(entries), skipped
