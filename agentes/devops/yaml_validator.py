"""
Validación de sintaxis YAML.

PyYAML decide qué es válido; aquí solo se traduce su error a un mensaje con el número de
línea. No se buscan tabulaciones por cuenta propia: YAML las prohíbe en la indentación, pero
las admite en comentarios, entre comillas y dentro de los bloques literales, y PyYAML ya
distingue un caso del otro.
"""
from typing import Any, List, Optional, Tuple

import yaml

# PyYAML describe una tabulación donde no la admite con el repr del carácter: '\t'.
_TAB_PROBLEM = "'\\t'"


def _describe(exc: yaml.YAMLError) -> str:
    """Mensaje del error con 'Línea N:' delante cuando el parser indica dónde ocurrió."""
    mark = getattr(exc, "problem_mark", None)
    where = f"Línea {mark.line + 1}: " if mark is not None else ""
    problem = str(getattr(exc, "problem", None) or exc)
    if _TAB_PROBLEM in problem:
        return f"{where}Tabulación (Tab) donde YAML no la admite: en la indentación o como separador. Usa espacios."
    return f"{where}Error de parseo YAML: {problem}"


class YAMLValidator:
    """Validador de sintaxis YAML basado en PyYAML, con soporte de varios documentos (---)."""

    @staticmethod
    def load_documents(filepath: str) -> Tuple[Optional[List[Any]], List[str]]:
        """
        Lee todos los documentos del archivo. Devuelve (documentos, errores): documentos es
        None si el archivo no se pudo leer o no es YAML válido.
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
        except FileNotFoundError:
            return None, [f"El archivo '{filepath}' no existe."]
        except (OSError, UnicodeDecodeError) as exc:
            return None, [f"No se pudo leer '{filepath}': {exc}"]
        try:
            return list(yaml.safe_load_all(content)), []
        except yaml.YAMLError as exc:
            return None, [_describe(exc)]

    @staticmethod
    def validate_yaml_syntax(filepath: str) -> Tuple[bool, List[str]]:
        """Valida un archivo YAML. Devuelve (es_válido, errores)."""
        docs, errors = YAMLValidator.load_documents(filepath)
        return docs is not None, errors
