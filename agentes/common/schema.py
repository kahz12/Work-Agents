"""
Validador de esquemas tipados compartido (agentes defensivo + QA).
"""
from typing import Any, Dict, List, Tuple


def matches_schema_type(value: Any, expected_type: type) -> bool:
    """
    Comparación estricta de tipos. bool no cuenta como int/float.
    """
    if expected_type is int:
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type is float:
        return isinstance(value, float) and not isinstance(value, bool)
    return isinstance(value, expected_type)


def validate_typed_schema(
    payload: Any,
    expected_schema: Dict[str, Any],
    *,
    reject_extra_keys: bool = False,
) -> Tuple[bool, List[str]]:
    """
    Valida un dict contra un esquema de tipos.

    El esquema admite:
      - tipos planos: {"age": int}
      - anidados: {"user": {"name": str, "age": int}}
      - listas homogéneas: {"tags": [str]}  (lista de un solo tipo)

    Retorna (es_válido, lista_de_errores).
    """
    errors: List[str] = []
    if not isinstance(payload, dict):
        return False, ["El payload recibido no es un objeto JSON (diccionario)."]

    def _validate(node: Any, schema: Any, path: str) -> None:
        if isinstance(schema, dict):
            if not isinstance(node, dict):
                errors.append(f"'{path or '$'}' debe ser un objeto, se recibió {type(node).__name__}")
                return
            for key, expected in schema.items():
                child = f"{path}.{key}" if path else key
                if key not in node:
                    errors.append(f"Falta el campo requerido: '{child}'")
                else:
                    _validate(node[key], expected, child)
            if reject_extra_keys:
                for key in node:
                    if key not in schema:
                        child = f"{path}.{key}" if path else key
                        errors.append(f"Campo no permitido: '{child}'")
            return

        if isinstance(schema, list) and len(schema) == 1:
            item_schema = schema[0]
            if not isinstance(node, list):
                errors.append(f"'{path}' debe ser una lista, se recibió {type(node).__name__}")
                return
            for i, item in enumerate(node):
                _validate(item, item_schema, f"{path}[{i}]")
            return

        if isinstance(schema, type):
            if not matches_schema_type(node, schema):
                errors.append(
                    f"El campo '{path}' debe ser de tipo {schema.__name__}, "
                    f"se recibió {type(node).__name__}"
                )
            return

        errors.append(f"Esquema no soportado en '{path}': {schema!r}")

    _validate(payload, expected_schema, "")
    return len(errors) == 0, errors
