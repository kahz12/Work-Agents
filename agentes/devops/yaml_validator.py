"""
YAML syntax validation.

PyYAML decides what is valid; this module only turns its error into a message that carries
the line number. Tabs are not searched for separately: YAML forbids them in indentation but
allows them in comments, inside quotes and in literal blocks, and PyYAML already tells those
cases apart.
"""
from typing import Any, List, Optional, Tuple

import yaml

# PyYAML reports a tab in a forbidden position using the character's repr: '\t'.
_TAB_PROBLEM = "'\\t'"


def _describe(exc: yaml.YAMLError) -> str:
    """The error message, prefixed with 'Line N:' when the parser says where it happened."""
    # audits._line_from_message reads the line number back from this "Line N" prefix.
    mark = getattr(exc, "problem_mark", None)
    where = f"Line {mark.line + 1}: " if mark is not None else ""
    problem = str(getattr(exc, "problem", None) or exc)
    if _TAB_PROBLEM in problem:
        return f"{where}Tab character where YAML does not allow one: in indentation or as a separator. Use spaces."
    return f"{where}YAML parse error: {problem}"


class YAMLValidator:
    """PyYAML-based syntax validator that supports multi-document files (---)."""

    @staticmethod
    def load_documents(filepath: str) -> Tuple[Optional[List[Any]], List[str]]:
        """
        Load every document in the file. Returns (documents, errors); documents is None when
        the file could not be read or is not valid YAML.
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
        except FileNotFoundError:
            return None, [f"File '{filepath}' does not exist."]
        except (OSError, UnicodeDecodeError) as exc:
            return None, [f"Could not read '{filepath}': {exc}"]
        try:
            return list(yaml.safe_load_all(content)), []
        except yaml.YAMLError as exc:
            return None, [_describe(exc)]

    @staticmethod
    def validate_yaml_syntax(filepath: str) -> Tuple[bool, List[str]]:
        """Validate a YAML file. Returns (is_valid, errors)."""
        docs, errors = YAMLValidator.load_documents(filepath)
        return docs is not None, errors
