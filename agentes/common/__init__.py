"""
Code shared by the agents: orchestrator, reports, findings, console output and schemas.
"""
from .schema import matches_schema_type, validate_typed_schema

__all__ = ["validate_typed_schema", "matches_schema_type"]
