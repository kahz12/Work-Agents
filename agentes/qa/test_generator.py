"""
Public facade of the QA agent: unit test generation, testability audit and scenario matrices.

The private static methods below delegate to the modules the generator was split into. They
stay on the class because existing callers and tests reach them through QATestGenerator.
"""
from __future__ import annotations

import ast
from typing import Dict, List, Optional, Tuple

from .ast_inspector import (
    UnitTestGenerator,
    _attr_chain,
    _extract_raises_and_flags,
    _regex_literal,
    read_and_parse,
)
from .emitters import (
    RAISES_COMMENT,
    RECORDED_HEADER,
    SOURCE_COMMENT,
    _PytestCase,
    absorb_blocked,
    io_called_expr,
    io_targets,
    is_float_literal,
    outcome_for,
    patch_clause,
    recording_calls,
    write_suite,
)
from .expected_values import Outcome, record_outcomes
from .sample_values import (
    ANNOTATION_SAMPLES,
    INVALID_BY_NAME,
    SAMPLE_BY_NAME,
    annotation_sample,
    boundary_samples_for_param,
    build_scenario_matrix,
    sample_for_arg,
    sample_for_arg_node,
    samples_from_arginfo,
)
from .side_effects import ImportMap
from .testability import TestabilityAuditor, audit_testability

__all__ = [
    "ImportMap",
    "QATestGenerator",
    "TestabilityAuditor",
    "UnitTestGenerator",
    "_PytestCase",
    "_attr_chain",
    "_extract_raises_and_flags",
    "_regex_literal",
]


class QATestGenerator:
    """
    Generates unit test suites (unittest, and adversarial pytest), audits testability and builds
    QA scenario matrices.
    """

    SAMPLE_BY_NAME: Dict[str, str] = SAMPLE_BY_NAME
    INVALID_BY_NAME: Dict[str, str] = INVALID_BY_NAME
    _ANNOTATION_SAMPLES: Dict[str, str] = ANNOTATION_SAMPLES
    _SOURCE_COMMENT = SOURCE_COMMENT
    _RAISES_COMMENT = RAISES_COMMENT
    _RECORDED_HEADER = RECORDED_HEADER

    @staticmethod
    def _read_and_parse(source_filepath: str) -> ast.Module:
        return read_and_parse(source_filepath)

    @staticmethod
    def audit_testability(source_filepath: str) -> List[Tuple[int, str, str, str]]:
        """
        Look for testability blockers in the source through its AST: concrete coupling, mutable
        global state, direct I/O and non-determinism.
        """
        return audit_testability(source_filepath)

    @staticmethod
    def _boundary_samples_for_param(arg_name: str, ann: Optional[str], nominal: str) -> List[Tuple[str, str]]:
        return boundary_samples_for_param(arg_name, ann, nominal)

    @staticmethod
    def build_scenario_matrix(source_filepath: str) -> List[Dict[str, str]]:
        """
        Build the structured matrix of test scenarios, with at least three boundary, hostile or
        concurrency cases for every nominal path.
        """
        return build_scenario_matrix(source_filepath)

    @staticmethod
    def _annotation_sample(annotation: Optional[ast.AST]) -> Optional[str]:
        return annotation_sample(annotation)

    @staticmethod
    def _sample_for_arg_node(arg: ast.arg, default_node: Optional[ast.AST] = None) -> str:
        return sample_for_arg_node(arg, default_node)

    @staticmethod
    def _samples_from_arginfo(arginfo: Optional[ast.arguments], arg_names: List[str]) -> Tuple[List[str], List[str]]:
        return samples_from_arginfo(arginfo, arg_names)

    @staticmethod
    def _io_targets(io_calls: List[str]) -> List[str]:
        return io_targets(io_calls)

    @staticmethod
    def _absorb_blocked(outcome: Optional[Outcome], targets: List[str]) -> Tuple[Optional[Outcome], List[str]]:
        return absorb_blocked(outcome, targets)

    @staticmethod
    def _patch_clause(targets: List[str]) -> str:
        return patch_clause(targets)

    @staticmethod
    def _io_called_expr(targets: List[str]) -> str:
        return io_called_expr(targets)

    @staticmethod
    def _recording_calls(visitor: UnitTestGenerator) -> Dict[str, str]:
        return recording_calls(visitor)

    @staticmethod
    def _outcome_for(
        key: str,
        func_node: Optional[ast.AST],
        kept_args: List[str],
        samples: List[str],
        recorded: Optional[Dict[str, Outcome]],
    ) -> Tuple[Optional[Outcome], str]:
        return outcome_for(key, func_node, kept_args, samples, recorded)

    @staticmethod
    def _is_float_literal(text: str) -> bool:
        return is_float_literal(text)

    @staticmethod
    def _sample_for_arg(arg_name: str) -> str:
        return sample_for_arg(arg_name)

    @staticmethod
    def _visit(source_filepath: str, record: bool) -> Optional[Tuple[UnitTestGenerator, Dict[str, Outcome]]]:
        try:
            tree = read_and_parse(source_filepath)
        except (FileNotFoundError, IsADirectoryError, SyntaxError, UnicodeDecodeError, OSError):
            return None
        visitor = UnitTestGenerator(source_filepath)
        visitor.visit(tree)
        recorded = record_outcomes(source_filepath, recording_calls(visitor)) if record else {}
        return visitor, recorded

    @staticmethod
    def generate_test_suite(source_filepath: str, output_test_filepath: str, *, record: bool = False) -> str:
        """
        Generate a unittest suite for the functions and classes in the source file.

        With record=True the module is imported and executed to record real results (see
        expected_values.record_outcomes). Returns "" when the source cannot be read.
        """
        return write_suite(source_filepath, output_test_filepath, framework="unittest", record=record)

    @staticmethod
    def generate_pytest_suite(source_filepath: str, output_test_filepath: str, *, record: bool = False) -> str:
        """
        Generate a pytest suite with parametrisation and descriptive IDs, fixtures with yield
        teardown, autospec=True doubles, async tests and Hypothesis properties.

        With record=True the module is imported and executed to record real results.
        """
        return write_suite(source_filepath, output_test_filepath, framework="pytest", record=record)
