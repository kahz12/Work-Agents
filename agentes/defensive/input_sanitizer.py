import html
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..common.schema import matches_schema_type, validate_typed_schema


class InputSanitizer:
    """
    Módulo para validación y sanitización defensiva de datos de entrada.
    Evita vulnerabilidades comunes como Cross-Site Scripting (XSS),
    Path Traversal, Formatos Inválidos e inyecciones en estructuras JSON.
    """

    @staticmethod
    def sanitize_html(text: str) -> str:
        """
        Escapa caracteres HTML especiales para prevenir Cross-Site Scripting (XSS).
        """
        if not isinstance(text, str):
            return ""
        return html.escape(text.strip(), quote=True)

    @staticmethod
    def validate_email(email: str) -> bool:
        """
        Valida que la cadena proporcione un formato de correo electrónico legítimo.
        """
        pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        return bool(re.match(pattern, email.strip())) if email else False

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitiza nombres de archivos evitando Path Traversal (ej. ../../etc/passwd).
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
        Resuelve canónicamente `user_path` respecto a `base_dir` con Path.resolve()
        y retorna la ruta segura solo si permanece dentro de `base_dir`.
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
        Valida que el texto contenga únicamente caracteres permitidos mediante lista blanca.
        allowed_chars es el contenido de una clase de caracteres de una expresión regular.

        Se usa fullmatch y no `^...$`: en Python `$` también coincide antes de un salto de
        línea final, y "admin\n" pasaría una lista de solo letras.
        """
        if not isinstance(text, str):
            return False
        return re.fullmatch(f"[{allowed_chars}]*", text) is not None

    @staticmethod
    def sanitize_integer(value: Any, min_val: Optional[int] = None, max_val: Optional[int] = None) -> Optional[int]:
        """
        Convierte y valida números enteros dentro de un rango seguro.
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
        Valida un objeto/diccionario JSON contra un esquema de tipos (plano o anidado).
        Delega en agentes.common.schema.
        """
        return validate_typed_schema(payload, expected_schema, reject_extra_keys=reject_extra_keys)
