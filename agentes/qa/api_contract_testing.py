import json
import math
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from .. import __version__
from ..common.schema import validate_typed_schema


class APIContractTester:
    """
    API contract testing: checks HTTP status, response schema, headers and latency SLA, either
    on a response you already have or by making the request; also generates adversarial
    payloads for a schema.
    """

    @staticmethod
    def _nominal_for_schema(schema: Dict[str, Any]) -> Dict[str, Any]:
        """A valid example payload for the schema, with one plain value per field."""
        out: Dict[str, Any] = {}
        for k, t in schema.items():
            if t is bool:
                out[k] = True
            elif t is int:
                out[k] = 1
            elif t is float:
                out[k] = 1.0
            elif t is str:
                out[k] = "sample"
            elif t is list or isinstance(t, list):
                out[k] = []
            elif isinstance(t, dict):
                out[k] = APIContractTester._nominal_for_schema(t)
            else:
                out[k] = {}
        return out

    @staticmethod
    def generate_adversarial_payloads(schema: Dict[str, Any]) -> List[Tuple[str, Any]]:
        """
        Adversarial and boundary payloads derived from a typed schema, to check how robust
        contract validators and JSON parsers are. Returns (case name, payload) pairs.
        """
        nominal = APIContractTester._nominal_for_schema(schema)
        zero_payload: Dict[str, Any] = {}
        neg_unicode_payload: Dict[str, Any] = {}
        extreme_payload: Dict[str, Any] = {}
        bool_trap_payload: Dict[str, Any] = {}

        for k, t in schema.items():
            if t is bool:
                zero_payload[k] = False
                neg_unicode_payload[k] = True
                extreme_payload[k] = False
                bool_trap_payload[k] = "true"
            elif t is int:
                zero_payload[k] = 0
                neg_unicode_payload[k] = -1
                extreme_payload[k] = 10**18
                # bool is a subclass of int in Python, so isinstance(True, int) is true; this value
                # checks that the validator rejects booleans where it expects a real integer.
                bool_trap_payload[k] = True
            elif t is float:
                zero_payload[k] = 0.0
                neg_unicode_payload[k] = -1.0
                extreme_payload[k] = float("nan")
                bool_trap_payload[k] = float("inf")
            elif t is str:
                zero_payload[k] = ""
                neg_unicode_payload[k] = "áéíóú_🔥<script>alert(1)</script>\x00"
                extreme_payload[k] = "A" * 10000
                bool_trap_payload[k] = 12345
            elif t is list or isinstance(t, list):
                zero_payload[k] = []
                neg_unicode_payload[k] = [None]
                extreme_payload[k] = list(range(100))
                bool_trap_payload[k] = {}
            elif isinstance(t, dict):
                zero_payload[k] = {}
                neg_unicode_payload[k] = {sub_k: None for sub_k in t}
                extreme_payload[k] = APIContractTester._nominal_for_schema(t)
                bool_trap_payload[k] = []
            else:
                zero_payload[k] = {}
                neg_unicode_payload[k] = None
                extreme_payload[k] = {}
                bool_trap_payload[k] = None

        return [
            ("empty_payload", {}),
            ("non_dict_null", None),
            ("null_fields", {k: None for k in schema}),
            ("boundary_zero_or_empty", zero_payload),
            ("boundary_negative_unicode", neg_unicode_payload),
            ("extreme_nan_giant", extreme_payload),
            ("bool_as_int_or_type_trap", bool_trap_payload),
            ("unexpected_extra_key", {**nominal, "__unexpected_extra__": "adversarial"}),
        ]

    @staticmethod
    def validate_api_response(
        endpoint: str,
        response_status: int,
        response_data: Any,
        response_headers: Dict[str, str],
        elapsed_ms: float,
        expected_status: int = 200,
        expected_schema: Optional[Dict[str, Any]] = None,
        max_sla_ms: float = 500.0,
        *,
        reject_extra_keys: bool = False,
        expected_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Validate an API response against its contract: status code, latency SLA, expected
        headers (substring match, case-insensitive names) and JSON schema.
        Returns {"endpoint", "passed", "elapsed_ms", "assertions"}; each assertion is a
        (check, "OK" | "FAILED", detail) tuple.
        """
        assertions = []
        passed = True

        if response_status == expected_status:
            assertions.append(("Status Code", "OK", f"Status code {response_status} as expected."))
        else:
            passed = False
            assertions.append(("Status Code", "FAILED", f"Expected {expected_status}, got {response_status}."))

        if (
            isinstance(elapsed_ms, bool)
            or not isinstance(elapsed_ms, (int, float))
            or math.isnan(elapsed_ms)
            or math.isinf(elapsed_ms)
            or elapsed_ms < 0
        ):
            passed = False
            assertions.append(("Latency SLA", "FAILED", f"Invalid or out-of-range latency ({elapsed_ms})."))
        elif elapsed_ms <= max_sla_ms:
            assertions.append(("Latency SLA", "OK", f"Response time {elapsed_ms}ms within the SLA limit ({max_sla_ms}ms)."))
        else:
            passed = False
            assertions.append(("Latency SLA", "FAILED", f"Response time {elapsed_ms}ms exceeds the SLA ({max_sla_ms}ms)."))

        if expected_headers:
            actual_hdrs = {str(k).lower(): str(v) for k, v in (response_headers or {}).items()}
            hdr_errors = []
            for h_name, h_val in expected_headers.items():
                actual_val = actual_hdrs.get(str(h_name).lower())
                if actual_val is None:
                    hdr_errors.append(f"Missing required header '{h_name}'")
                elif str(h_val) not in actual_val:
                    hdr_errors.append(f"Header '{h_name}' expected '{h_val}', got '{actual_val}'")
            if hdr_errors:
                passed = False
                for herr in hdr_errors:
                    assertions.append(("HTTP Headers", "FAILED", herr))
            else:
                assertions.append(("HTTP Headers", "OK", "Expected HTTP headers are present."))

        if expected_schema:
            ok, errs = validate_typed_schema(
                response_data,
                expected_schema,
                reject_extra_keys=reject_extra_keys,
            )
            if ok:
                assertions.append(("JSON Schema", "OK", "The response structure matches the contract."))
            else:
                passed = False
                for err in errs:
                    assertions.append(("JSON Schema", "FAILED", err))

        return {
            "endpoint": endpoint,
            "passed": passed,
            "elapsed_ms": elapsed_ms,
            "assertions": assertions,
        }

    @staticmethod
    def request_and_validate(
        url: str,
        *,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Any] = None,
        expected_status: int = 200,
        expected_schema: Optional[Dict[str, Any]] = None,
        max_sla_ms: float = 500.0,
        timeout: float = 5.0,
        reject_extra_keys: bool = False,
        expected_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Make a real HTTP request and validate the response contract and SLA.

        An HTTP error status is still a response and is validated like any other; only a
        transport failure (no connection, timeout) short-circuits into a failed result.
        """
        req_headers = {"User-Agent": f"agentes-qa-contract/{__version__}", "Accept": "application/json"}
        if headers:
            req_headers.update(headers)

        data_bytes = None
        if body is not None:
            if isinstance(body, (dict, list)):
                data_bytes = json.dumps(body).encode("utf-8")
                req_headers.setdefault("Content-Type", "application/json")
            elif isinstance(body, str):
                data_bytes = body.encode("utf-8")
            else:
                data_bytes = body

        start = time.time()
        status = 0
        resp_headers: Dict[str, str] = {}
        resp_data: Any = {}
        error = None

        try:
            req = urllib.request.Request(url, data=data_bytes, headers=req_headers, method=method.upper())
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = getattr(resp, "status", 200)
                resp_headers = {k: v for k, v in resp.headers.items()}
                raw = resp.read()
                if raw:
                    try:
                        resp_data = json.loads(raw.decode("utf-8"))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        resp_data = {"_raw": raw[:500].decode("utf-8", errors="replace")}
        except urllib.error.HTTPError as exc:
            status = exc.code
            resp_headers = {k: v for k, v in (exc.headers.items() if exc.headers else [])}
            raw = exc.read() if hasattr(exc, "read") else b""
            try:
                resp_data = json.loads(raw.decode("utf-8")) if raw else {}
            except (json.JSONDecodeError, UnicodeDecodeError):
                resp_data = {"_error": str(exc)}
            error = str(exc)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            elapsed_ms = round((time.time() - start) * 1000, 2)
            return {
                "endpoint": url,
                "passed": False,
                "elapsed_ms": elapsed_ms,
                "error": str(exc),
                "assertions": [("HTTP Request", "FAILED", f"The request could not be completed: {exc}")],
            }

        elapsed_ms = round((time.time() - start) * 1000, 2)
        result = APIContractTester.validate_api_response(
            endpoint=url,
            response_status=status,
            response_data=resp_data if isinstance(resp_data, dict) else {"_value": resp_data},
            response_headers=resp_headers,
            elapsed_ms=elapsed_ms,
            expected_status=expected_status,
            expected_schema=expected_schema,
            max_sla_ms=max_sla_ms,
            reject_extra_keys=reject_extra_keys,
            expected_headers=expected_headers,
        )
        if error:
            result["transport_error"] = error
        result["response_data"] = resp_data
        return result
