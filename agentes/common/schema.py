"""
Typed schema validator shared by the defensive and QA agents.
"""
from typing import Any, Dict, List, Tuple


def matches_schema_type(value: Any, expected_type: type) -> bool:
    """
    Strict type check. bool is a subclass of int in Python, but here it never counts as int
    or float: a JSON `true` where a number is expected is a contract violation.
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
    Validate a dict against a type schema.

    The schema supports:
      - plain types: {"age": int}
      - nested objects: {"user": {"name": str, "age": int}}
      - homogeneous lists: {"tags": [str]}  (a one-element list holding the item schema)

    Returns (is_valid, errors).
    """
    errors: List[str] = []
    if not isinstance(payload, dict):
        return False, ["The payload is not a JSON object (dict)."]

    def _validate(node: Any, schema: Any, path: str) -> None:
        if isinstance(schema, dict):
            if not isinstance(node, dict):
                errors.append(f"'{path or '$'}' must be an object, got {type(node).__name__}")
                return
            for key, expected in schema.items():
                child = f"{path}.{key}" if path else key
                if key not in node:
                    errors.append(f"Missing required field: '{child}'")
                else:
                    _validate(node[key], expected, child)
            if reject_extra_keys:
                for key in node:
                    if key not in schema:
                        child = f"{path}.{key}" if path else key
                        errors.append(f"Unexpected field: '{child}'")
            return

        if isinstance(schema, list) and len(schema) == 1:
            item_schema = schema[0]
            if not isinstance(node, list):
                errors.append(f"'{path}' must be a list, got {type(node).__name__}")
                return
            for i, item in enumerate(node):
                _validate(item, item_schema, f"{path}[{i}]")
            return

        if isinstance(schema, type):
            if not matches_schema_type(node, schema):
                errors.append(
                    f"Field '{path}' must be of type {schema.__name__}, "
                    f"got {type(node).__name__}"
                )
            return

        errors.append(f"Unsupported schema at '{path}': {schema!r}")

    _validate(payload, expected_schema, "")
    return len(errors) == 0, errors
