"""
Código compartido por los agentes: orquestador, informes, hallazgos, consola y esquemas.
"""
from .schema import matches_schema_type, validate_typed_schema

__all__ = ["validate_typed_schema", "matches_schema_type"]
