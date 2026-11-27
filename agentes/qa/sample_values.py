"""
Sample values, boundary cases and the scenario matrix used to generate tests.
"""
from __future__ import annotations

import ast
from typing import Any, Dict, List, Optional, Tuple

from .ast_inspector import UnitTestGenerator, read_and_parse

# Sample argument values (as source literals) keyed by parameter name. Spanish names are listed
# next to their English equivalents because the generator is also run on Spanish codebases.
SAMPLE_BY_NAME: Dict[str, str] = dict((
    ("a", "2"),
    ("b", "3"),
    ("x", "1"),
    ("y", "1"),
    ("n", "5"),
    ("i", "1"),
    ("precio", "100.0"),
    ("porcentaje", "10.0"),
    ("price", "100.0"),
    ("percent", "10.0"),
    ("descuento", "10.0"),
    ("name", '"alice"'),
    ("nombre", '"alice"'),
    ("email", '"user@example.com"'),
    ("user", '"admin"'),
    ("username", '"admin"'),
    ("password", '"Secret1!"'),
    ("text", '"hello"'),
    ("msg", '"hello"'),
    ("message", '"hello"'),
    ("path", '"/tmp/test.txt"'),
    ("filename", '"report.pdf"'),
    ("url", '"https://example.com"'),
    ("uid", "1"),
    ("id", "1"),
    ("count", "3"),
    ("limit", "10"),
    ("offset", "0"),
))

# A hostile value per parameter name, for the "invalid input" scenarios.
INVALID_BY_NAME: Dict[str, str] = {
    "porcentaje": "-1",
    "percent": "-1",
    "email": '"not-an-email"',
    "path": '"../../etc/passwd"',
}

ANNOTATION_SAMPLES: Dict[str, str] = {
    "str": '"sample"',
    "bool": "True",
    "int": "1",
    "float": "1.0",
    "list": "[]",
    "dict": "{}",
    "set": "set()",
    "tuple": "()",
}

_CONTAINER_SAMPLES: Dict[str, str] = {
    "list": "[]", "List": "[]",
    "dict": "{}", "Dict": "{}",
    "set": "set()", "Set": "set()",
    "tuple": "()", "Tuple": "()",
}


def annotation_sample(annotation: Optional[ast.AST]) -> Optional[str]:
    """A sample literal inferred from a type annotation, or None when the type is not recognised."""
    if annotation is None:
        return None
    if isinstance(annotation, ast.Name):
        return ANNOTATION_SAMPLES.get(annotation.id)
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        return ANNOTATION_SAMPLES.get(annotation.value)
    if isinstance(annotation, ast.Subscript) and isinstance(annotation.value, ast.Name):
        root = annotation.value.id
        if root in _CONTAINER_SAMPLES:
            return _CONTAINER_SAMPLES[root]
        if root == "Optional":
            return annotation_sample(annotation.slice)
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        for branch in (annotation.left, annotation.right):
            if not (isinstance(branch, ast.Constant) and branch.value is None):
                res = annotation_sample(branch)
                if res is not None:
                    return res
    return None


def sample_for_arg(arg_name: str) -> str:
    """A heuristic sample value based on the parameter name alone."""
    key = arg_name.lower()
    if key in SAMPLE_BY_NAME:
        return SAMPLE_BY_NAME[key]
    if key.endswith("_id") or key.endswith("id"):
        return "1"
    if any(k in key for k in ("name", "nombre", "user", "text", "msg", "title")):
        return '"sample"'
    if any(k in key for k in ("count", "num", "size", "len", "qty", "amount")):
        return "1"
    return "1"


def sample_for_arg_node(arg: ast.arg, default_node: Optional[ast.AST] = None) -> str:
    """A sample value for a parameter: known name first, then its default value, then its annotation."""
    key = arg.arg.lower()
    if key in SAMPLE_BY_NAME:
        return SAMPLE_BY_NAME[key]
    if isinstance(default_node, ast.Constant) and default_node.value is not None:
        return repr(default_node.value)
    ann_sample = annotation_sample(arg.annotation)
    if ann_sample is not None:
        return ann_sample
    return sample_for_arg(arg.arg)


def samples_from_arginfo(arginfo: Optional[ast.arguments], arg_names: List[str]) -> Tuple[List[str], List[str]]:
    """(sample values, parameter names) for a signature, skipping self and cls."""
    if arginfo is None:
        return [sample_for_arg(a) for a in arg_names], arg_names
    all_args = arginfo.args
    defaults_offset = len(all_args) - len(arginfo.defaults)
    samples: List[str] = []
    kept: List[str] = []
    for idx, arg_node in enumerate(all_args):
        if arg_node.arg in ("self", "cls"):
            continue
        d_idx = idx - defaults_offset
        default_node = arginfo.defaults[d_idx] if d_idx >= 0 else None
        samples.append(sample_for_arg_node(arg_node, default_node))
        kept.append(arg_node.arg)
    return samples, kept


def boundary_samples_for_param(arg_name: str, ann: Optional[str], nominal: str) -> List[Tuple[str, str]]:
    """Representative boundary cases for a parameter, by type or by name."""
    key = arg_name.lower()
    t = (ann or "").lower()
    if t == "str" or nominal.startswith(('"', "'")):
        return [
            ("empty_str", '""'),
            ("unicode_null", '"áéíóú_🔥\\x00"'),
            ("giant_str", '"A" * 2048'),
        ]
    if t in ("list", "list[int]", "list[str]") or nominal == "[]":
        return [
            ("empty_list", "[]"),
            ("single_elem", "[1]"),
            ("none_item", "[None]"),
        ]
    if t in ("dict", "dict[str, int]") or nominal == "{}":
        return [
            ("empty_dict", "{}"),
            ("single_kv", '{"k": 1}'),
            ("unicode_kv", '{"key_ñ": None}'),
        ]
    if key in ("porcentaje", "percent", "descuento"):
        return [
            ("zero_percent", "0"),
            ("hundred_percent", "100"),
            ("float_precision", "0.5"),
        ]
    return [
        ("zero", "0"),
        ("negative_one", "-1"),
        ("large_num", "10**6"),
    ]


def first_invalid_argument(kept_args: List[str]) -> Optional[Tuple[int, str]]:
    """(index, invalid value) of the first parameter that has a known hostile value (INVALID_BY_NAME)."""
    for i, a in enumerate(kept_args):
        if a.lower() in INVALID_BY_NAME:
            return i, INVALID_BY_NAME[a.lower()]
    return None


def _boundary_scenarios(
    target: str,
    kept_args: List[str],
    samples: List[str],
    param_types: Dict[str, Optional[str]],
) -> List[Dict[str, str]]:
    if not kept_args:
        return [
            {
                "target": target,
                "category": "[BOUNDARY / EDGE CASE]",
                "scenario": "idempotent_repeated_calls",
                "input_summary": "consecutive calls without arguments",
                "expected": "Consistent output and no leaked shared state.",
            },
            {
                "target": target,
                "category": "[BOUNDARY / EDGE CASE]",
                "scenario": "unexpected_extra_arg",
                "input_summary": "*extra_args",
                "expected": "Raises TypeError when the signature accepts no extra arguments.",
            },
        ]

    scenarios: List[Dict[str, str]] = []
    p0 = kept_args[0]
    for b_id, b_val in boundary_samples_for_param(p0, param_types.get(p0), samples[0])[:2]:
        b_vals = list(samples)
        b_vals[0] = b_val
        scenarios.append({
            "target": target,
            "category": "[BOUNDARY / EDGE CASE]",
            "scenario": f"boundary_{b_id}",
            "input_summary": ", ".join(f"{k}={v}" for k, v in zip(kept_args, b_vals)),
            "expected": "Handles the extreme boundary (0, -1, empty or Unicode) without failing silently.",
        })
    last_idx = len(kept_args) - 1
    if samples[last_idx] not in ('""', "[]", "{}", "set()", "()", "True"):
        ext_vals = list(samples)
        ext_vals[last_idx] = "float('nan')"
        scenarios.append({
            "target": target,
            "category": "[BOUNDARY / EDGE CASE]",
            "scenario": "boundary_extreme_nan_or_inf",
            "input_summary": ", ".join(f"{k}={v}" for k, v in zip(kept_args, ext_vals)),
            "expected": "Rejects float('nan')/inf or responds deterministically.",
        })
    return scenarios


def _adversarial_scenario(
    target: str,
    kept_args: List[str],
    samples: List[str],
    raises: List[Tuple[str, Optional[str]]],
) -> Dict[str, str]:
    exc_desc = (
        f"Raises {raises[0][0]} (match={raises[0][1]!r})"
        if raises and raises[0][1]
        else (f"Raises {raises[0][0]}" if raises else "Fails in a controlled way with TypeError/ValueError")
    )
    inv_summary = "None / hostile or out-of-range payload"
    invalid = first_invalid_argument(kept_args)
    if invalid is not None:
        i, invalid_val = invalid
        bad = list(samples)
        bad[i] = invalid_val
        inv_summary = ", ".join(f"{k}={v}" for k, v in zip(kept_args, bad))
    return {
        "target": target,
        "category": "[ADVERSARIAL / ERROR]",
        "scenario": "invalid_or_null_input",
        "input_summary": inv_summary,
        "expected": exc_desc,
    }


def _fault_scenario(target: str, is_async: bool, io_calls: List[str]) -> Dict[str, str]:
    fault_desc = (
        "TimeoutError, asyncio.CancelledError and parallel asyncio.gather"
        if is_async
        else f"autospec=True mock of {', '.join(io_calls)} simulating OSError/TimeoutError"
    )
    return {
        "target": target,
        "category": "[CONCURRENCY / I/O FAULT]",
        "scenario": "async_timeout_or_io_isolation" if is_async else "isolated_io_fault",
        "input_summary": fault_desc,
        "expected": "No real I/O; the expected failure propagates after cleanup.",
    }


def _scenarios_for_target(
    target: str,
    arginfo: Optional[ast.arguments],
    arg_names: List[str],
    meta: Dict[str, Any],
) -> List[Dict[str, str]]:
    samples, kept_args = samples_from_arginfo(arginfo, arg_names)
    is_async = bool(meta.get("is_async"))
    raises: List[Tuple[str, Optional[str]]] = meta.get("raises", [])
    io_calls: List[str] = meta.get("io_calls", [])
    param_types: Dict[str, Optional[str]] = meta.get("param_types", {})

    nominal_repr = ", ".join(f"{k}={v}" for k, v in zip(kept_args, samples)) or "no arguments"
    scenarios = [{
        "target": target,
        "category": "[HAPPY PATH]",
        "scenario": "nominal_valid",
        "input_summary": nominal_repr,
        "expected": "Runs without raising and returns exactly the contracted output.",
    }]
    scenarios.extend(_boundary_scenarios(target, kept_args, samples, param_types))
    scenarios.append(_adversarial_scenario(target, kept_args, samples, raises))
    if is_async or io_calls:
        scenarios.append(_fault_scenario(target, is_async, io_calls))
    return scenarios


def build_scenario_matrix(source_filepath: str) -> List[Dict[str, str]]:
    """
    Build the structured matrix of test scenarios, with at least three boundary, hostile or
    concurrency cases for every nominal path.
    """
    try:
        tree = read_and_parse(source_filepath)
    except (OSError, SyntaxError, UnicodeDecodeError):
        return []

    visitor = UnitTestGenerator(source_filepath)
    visitor.visit(tree)

    targets: List[Tuple[str, Optional[ast.arguments], List[str]]] = []
    for fname, fargs, farginfo in visitor.functions:
        targets.append((fname, farginfo, fargs))
    for cname, _, methods in visitor.classes:
        for mname, margs, marginfo in methods:
            targets.append((f"{cname}.{mname}", marginfo, margs))

    scenarios: List[Dict[str, str]] = []
    for target, arginfo, arg_names in targets:
        scenarios.extend(_scenarios_for_target(target, arginfo, arg_names, visitor.function_meta.get(target, {})))
    return scenarios
