import html
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..common.schema import matches_schema_type, validate_typed_schema


class InputSanitizer:
    """
    Validation and sanitisation of untrusted input.

    Guards against the usual suspects: cross-site scripting (XSS), path traversal, malformed
    formats and unexpected shapes in JSON payloads.
    """

    @staticmethod
    def sanitize_html(text: str) -> str:
        """
        Escape HTML special characters (quotes included) to prevent cross-site scripting.
        Non-string input yields an empty string.
        """
        if not isinstance(text, str):
            return ""
        return html.escape(text.strip(), quote=True)

    @staticmethod
    def validate_email(email: str) -> bool:
        """
        Check that the string looks like a plausible e-mail address. This is a format check
        only; it says nothing about whether the mailbox exists.
        """
        pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        return bool(re.match(pattern, email.strip())) if email else False

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Reduce a user-supplied file name to a safe base name, defeating path traversal
        (../../etc/passwd becomes "passwd"). Anything outside [A-Za-z0-9_.-] becomes "_".
        """
        if not isinstance(filename, str) or not filename:
            return "file_default"

        filename = os.path.basename(filename)
        cleaned = re.sub(r'[^a-zA-Z0-9_\.-]', '_', filename)
        cleaned = cleaned.replace("..", "_")
        if cleaned in ("", "."):
            return "file_default"
        return cleaned

    @staticmethod
    def validate_safe_path(base_dir: str, user_path: str) -> Optional[str]:
        """
        Resolve `user_path` against `base_dir` with Path.resolve() (following symlinks and
        "..") and return it only when the result stays inside `base_dir`. None otherwise,
        including for NUL bytes, which some APIs would silently truncate at.
        """
        if not isinstance(base_dir, str) or not isinstance(user_path, str):
            return None
        if "\x00" in base_dir or "\x00" in user_path:
            return None
        try:
            resolved_base = Path(base_dir).resolve()
            candidate = Path(user_path)
            resolved_target = (candidate if candidate.is_absolute() else resolved_base / candidate).resolve()
        except (OSError, ValueError, RuntimeError):
            return None
        if resolved_target == resolved_base or resolved_target.is_relative_to(resolved_base):
            return str(resolved_target)
        return None

    @staticmethod
    def validate_string_whitelist(text: str, allowed_chars: str = r"a-zA-Z0-9_\-\s") -> bool:
        """
        Check that the text contains only allow-listed characters. allowed_chars is the body
        of a regular-expression character class.

        fullmatch is used rather than `^...$`: in Python `$` also matches just before a
        trailing newline, so "admin\n" would pass a letters-only allow-list.
        """
        if not isinstance(text, str):
            return False
        return re.fullmatch(f"[{allowed_chars}]*", text) is not None

    @staticmethod
    def sanitize_integer(value: Any, min_val: Optional[int] = None, max_val: Optional[int] = None) -> Optional[int]:
        """
        Convert the value to int and check it against the optional bounds. Returns None when
        conversion fails or the value is out of range. bool is rejected even though it is an
        int subclass.
        """
        try:
            if isinstance(value, bool):
                return None
            val = int(value)
            if min_val is not None and val < min_val:
                return None
            if max_val is not None and val > max_val:
                return None
            return val
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _matches_schema_type(value: Any, expected_type: type) -> bool:
        return matches_schema_type(value, expected_type)

    @staticmethod
    def validate_json_schema(
        payload: Any,
        expected_schema: Dict[str, Any],
        *,
        reject_extra_keys: bool = False,
    ) -> Tuple[bool, List[str]]:
        """
        Validate a JSON object against a (flat or nested) type schema.
        Delegates to agentes.common.schema.
        """
        return validate_typed_schema(payload, expected_schema, reject_extra_keys=reject_extra_keys)
