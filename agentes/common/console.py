"""
Terminal output for the CLI: optional colour, severity tags, tables and finding lists.

Colour is only enabled when the output is a terminal. NO_COLOR and FORCE_COLOR are honoured.
"""
from __future__ import annotations

import os
import shutil
import sys
import textwrap
from typing import Any, Dict, Optional, Sequence

from .findings import (  # noqa: F401 - re-exported for callers that import them from here
    BLOCKING_LEVELS,
    SEVERITY_ORDER,
    SILENT_LEVELS,
    FindingLike,
    as_finding,
    count_by_level,
    normalize_level,
    severity_rank,
)

_CODES = {
    "bold": "1", "dim": "2", "underline": "4",
    "red": "31", "green": "32", "yellow": "33", "blue": "34", "magenta": "35", "cyan": "36",
}

_LEVEL_STYLES = {
    "CRITICAL": ("red", "bold"), "ERROR": ("red", "bold"), "HIGH": ("red",),
    "MEDIUM": ("yellow",), "LOW": ("cyan",), "INFO": ("dim",), "OK": ("green",),
}
_LEVEL_NAMES = {
    "CRITICAL": ("critical", "critical"), "ERROR": ("error", "errors"), "HIGH": ("high", "high"),
    "MEDIUM": ("medium", "medium"), "LOW": ("low", "low"),
    "INFO": ("informational", "informational"), "OK": ("passed", "passed"),
}


def describe_counts(counts: Dict[str, int]) -> str:
    """Turn {'HIGH': 2, 'ERROR': 1} into '2 high, 1 error'."""
    parts = []
    for lvl, n in counts.items():
        singular, plural = _LEVEL_NAMES.get(lvl, (lvl.lower(), lvl.lower()))
        parts.append(f"{n} {singular if n == 1 else plural}")
    return ", ".join(parts)


def _supports_color(stream: Any) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("TERM") == "dumb":
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


class Console:
    """Writes human-readable output to stdout and errors to stderr."""

    def __init__(self, color: Optional[bool] = None, stream: Any = None, err: Any = None) -> None:
        self._stream = stream
        self._err = err
        self._color = color

    @property
    def stream(self) -> Any:
        return self._stream if self._stream is not None else sys.stdout

    @property
    def err(self) -> Any:
        return self._err if self._err is not None else sys.stderr

    @property
    def color(self) -> bool:
        return _supports_color(self.stream) if self._color is None else self._color

    def set_color(self, enabled: Optional[bool]) -> None:
        self._color = enabled

    @property
    def width(self) -> int:
        return max(60, min(shutil.get_terminal_size((100, 24)).columns, 120))

    def style(self, text: str, *styles: str) -> str:
        if not self.color or not styles:
            return text
        codes = ";".join(_CODES[s] for s in styles if s in _CODES)
        return f"\033[{codes}m{text}\033[0m" if codes else text

    # --- Basic lines ---------------------------------------------------

    def out(self, text: str = "") -> None:
        print(text, file=self.stream)

    def title(self, text: str) -> None:
        self.out(self.style(text, "bold"))
        self.out(self.style("=" * len(text), "dim"))

    def section(self, text: str) -> None:
        self.out()
        self.out(self.style(text, "bold"))

    def ok(self, text: str) -> None:
        self.out(f"{self.style('[OK]', 'green', 'bold')} {text}")

    def warn(self, text: str) -> None:
        self.out(f"{self.style('[WARN]', 'yellow', 'bold')} {text}")

    def fail(self, text: str) -> None:
        self.out(f"{self.style('[FAIL]', 'red', 'bold')} {text}")

    def error(self, text: str, hint: Optional[str] = None) -> None:
        """A usage or environment error. It goes to stderr so it never pollutes useful output."""
        label = "Error:"
        if self._err is None and _supports_color(self.err) and self._color is not False:
            label = "\033[31;1mError:\033[0m"
        print(f"{label} {text}", file=self.err)
        if hint:
            print(f"  {hint}", file=self.err)

    def hint(self, text: str) -> None:
        self.out(self.style(text, "dim"))

    def bullet(self, text: str, indent: int = 2) -> None:
        prefix = " " * indent + "- "
        self.out(textwrap.fill(text, width=self.width, initial_indent=prefix,
                               subsequent_indent=" " * len(prefix)))

    def kv(self, pairs: Sequence[Sequence[Any]], indent: int = 2) -> None:
        """Aligned key/value list."""
        if not pairs:
            return
        key_w = max(len(str(k)) for k, _ in pairs)
        for key, value in pairs:
            self.out(f"{' ' * indent}{str(key).ljust(key_w)}  {value}")

    # --- Tags ----------------------------------------------------------

    def level_tag(self, level: Any, pad: int = 0) -> str:
        lvl = normalize_level(level)
        tag = f"[{lvl}]"
        return self.style(tag.ljust(pad), *_LEVEL_STYLES.get(lvl, ()))

    def status_tag(self, ok: Optional[bool], pad: int = 0, labels: Sequence[str] = ("OK", "FAILED")) -> str:
        if ok is None:
            return self.style("--".ljust(pad), "dim")
        return self.style(labels[0].ljust(pad), "green") if ok else self.style(labels[1].ljust(pad), "red", "bold")

    # --- Tables and findings -------------------------------------------

    def table(self, headers: Sequence[str], rows: Sequence[Sequence[Any]], indent: int = 2,
              right: Sequence[int] = ()) -> None:
        """
        Plain-text table. The last column wraps over several lines when it does not fit.
        A cell may be a tuple (text, style, ...) so it can be coloured without the escape codes
        counting towards the column width.
        """
        def plain(cell: Any) -> str:
            return str(cell[0]) if isinstance(cell, tuple) else str(cell)

        def paint(cell: Any, text: str) -> str:
            return self.style(text, *cell[1:]) if isinstance(cell, tuple) else text

        if not rows:
            return
        ncols = len(headers)
        widths = [len(h) for h in headers]
        for row in rows:
            for i in range(ncols - 1):
                widths[i] = max(widths[i], len(plain(row[i])))
        used = indent + sum(widths[:-1]) + 2 * (ncols - 1)
        last_w = max(20, self.width - used)
        pad = " " * indent

        head = "  ".join(h.rjust(widths[i]) if i in right else h.ljust(widths[i]) for i, h in enumerate(headers[:-1]))
        head = (head + "  " if head else "") + headers[-1]
        self.out(pad + self.style(head, "bold"))
        for row in rows:
            cells = []
            for i in range(ncols - 1):
                text = plain(row[i])
                text = text.rjust(widths[i]) if i in right else text.ljust(widths[i])
                cells.append(paint(row[i], text))
            left = "  ".join(cells)
            left = left + "  " if cells else ""
            wrapped = textwrap.wrap(plain(row[-1]), width=last_w) or [""]
            self.out(pad + left + paint(row[-1], wrapped[0]))
            for extra in wrapped[1:]:
                self.out(" " * used + paint(row[-1], extra))

    def findings(self, findings: Sequence[FindingLike], limit: int = 20) -> None:
        """List findings ordered by severity. limit=0 shows all of them."""
        items = [as_finding(f) for f in findings]
        ordered = sorted(items, key=lambda f: (severity_rank(f.level), f.file, f.line))
        shown = ordered if limit <= 0 else ordered[:limit]
        tag_w = max((len(f.level) for f in shown), default=4) + 2
        for item in shown:
            where = f"{item.file}:{item.line}" if item.file and item.line else item.file
            head = f"  {self.level_tag(item.level, tag_w)} "
            body_indent = " " * (2 + tag_w + 1)
            if where:
                self.out(head + self.style(where, "bold"))
                self.out(textwrap.fill(item.message, width=self.width,
                                       initial_indent=body_indent, subsequent_indent=body_indent))
            else:
                text = textwrap.fill(item.message, width=self.width,
                                     initial_indent=body_indent, subsequent_indent=body_indent)
                self.out(head + text[len(body_indent):])
        hidden = len(ordered) - len(shown)
        if hidden > 0:
            self.hint(f"  ... and {hidden} more. Use --limit 0 to show them all.")


ui = Console()
