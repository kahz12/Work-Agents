#!/usr/bin/env python3
"""
End-to-end check of the 8 agents.

Calls each agent's public functions and methods with sample data, runs their demos in a
temporary directory and exercises the CLI end to end. It complements pytest: this script checks
that the pieces work together, while tests/ checks each rule on its own. Exits with code 1 if
any check fails. CI runs it after pytest.
"""
import json
import os
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from agentes import __version__ as AGENTES_VERSION
from agentes.defensive.auth_manager import AuthManager, RateLimiter
from agentes.defensive.config_manager import ConfigManager
from agentes.defensive.input_sanitizer import InputSanitizer
from agentes.devops.docker_compose_generator import DockerComposeGenerator
from agentes.devops.github_actions_generator import GitHubActionsGenerator
from agentes.devops.gitlab_ci_generator import GitLabCIGenerator
from agentes.devops.helm_generator import HelmGenerator
from agentes.devops.yaml_validator import YAMLValidator
from agentes.docs.markdown_doc_generator import MarkdownDocGenerator
from agentes.docs.openapi_generator import OpenAPIGenerator
from agentes.docs.swagger_ui_generator import SwaggerUIGenerator
from agentes.hardening.container_hardening import ContainerHardening
from agentes.hardening.k8s_hardening import K8sHardening
from agentes.hardening.service_hardening import ServiceHardening
from agentes.hardening.webserver_hardening import WebServerHardening
from agentes.qa.api_contract_testing import APIContractTester
from agentes.qa.qa_reporter import QAReporter
from agentes.qa.test_generator import QATestGenerator
from agentes.qa.test_runner import QATestRunner
from agentes.quality.dependency_auditor import DependencyAuditor
from agentes.quality.linter_config import LinterConfigGenerator
from agentes.quality.static_checker import StaticCodeAnalyzer
from agentes.refactor.architecture_diagram import ArchitectureDiagramGenerator
from agentes.refactor.code_metrics import CodeMetricsCalculator
from agentes.refactor.refactor_suggester import RefactorSuggester
from agentes.refactor.solid_checker import SOLIDChecker
from agentes.sre.alerting_engine import AlertingEngine
from agentes.sre.health_checker import SystemHealthChecker
from agentes.sre.log_anomaly_auditor import LogAnomalyAuditor
from agentes.sre.prometheus_exporter import PrometheusExporter
from agentes.sre.structured_logger import StructuredLogger

AGENTS_DIR = os.path.dirname(os.path.abspath(__file__))

# The checks never depend on the network: PyPI and OSV lookups are disabled, in subprocesses too.
os.environ["AGENTES_OFFLINE"] = "1"

passed = 0
failed = 0
errors_list = []

def test(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [OK]    {name}")
    else:
        failed += 1
        msg = f"  [FAIL]  {name}" + (f" -> {detail}" if detail else "")
        print(msg)
        errors_list.append(msg)

def header(title):
    print(f"\n{'='*70}")
    print(f" {title}")
    print(f"{'='*70}")

# =================================================================
# Defensive security controls: sanitisation, authentication, CSRF and configuration
# =================================================================
header("AGENT 1: DEFENSIVE SECURITY CONTROLS")

print("\n--- InputSanitizer ---")
# Dangerous tags are neutralised and non-string input yields an empty string.
test("sanitize_html: escapes script tags", "&lt;script&gt;" in InputSanitizer.sanitize_html("<script>alert(1)</script>"))
test("sanitize_html: escapes quotes", "&quot;" in InputSanitizer.sanitize_html('"hello"'))
test("sanitize_html: non-string returns empty", InputSanitizer.sanitize_html(123) == "")
test("sanitize_html: empty string ok", InputSanitizer.sanitize_html("") == "")

# Basic syntactic validation of e-mail addresses.
test("validate_email: valid email", InputSanitizer.validate_email("user@domain.com"))
test("validate_email: invalid email (no @)", not InputSanitizer.validate_email("userdomain"))
test("validate_email: empty email", not InputSanitizer.validate_email(""))

# Path traversal is contained in file names, with a safe fallback for empty strings.
test("sanitize_filename: path traversal ../../etc/passwd", InputSanitizer.sanitize_filename("../../etc/passwd") == "passwd")
test("sanitize_filename: only double dots", "_" in InputSanitizer.sanitize_filename(".."))
test("sanitize_filename: empty returns the default", InputSanitizer.sanitize_filename("") == "file_default")
test("sanitize_filename: ordinary name ok", InputSanitizer.sanitize_filename("report.pdf") == "report.pdf")

# Strict character allow-listing, and rejection of non-text input.
test("whitelist: alphanumeric text ok", InputSanitizer.validate_string_whitelist("hello world"))
test("whitelist: non-string returns False", not InputSanitizer.validate_string_whitelist(12345))

# Safe integer parsing with inclusive lower and upper bounds.
test("sanitize_integer: valid number", InputSanitizer.sanitize_integer("42") == 42)
test("sanitize_integer: below the minimum", InputSanitizer.sanitize_integer(5, min_val=10) is None)
test("sanitize_integer: above the maximum", InputSanitizer.sanitize_integer(100, max_val=50) is None)
test("sanitize_integer: not a number", InputSanitizer.sanitize_integer("abc") is None)

# Recursive JSON schemas, booleans rejected as integers, and extra keys blocked.
ok, errs = InputSanitizer.validate_json_schema({"name": "Alice", "age": 30}, {"name": str, "age": int})
test("json_schema: valid payload", ok and len(errs) == 0)

bad, errs2 = InputSanitizer.validate_json_schema({"name": 123}, {"name": str, "age": int})
test("json_schema: wrong type and missing field", not bad and len(errs2) == 2)

not_dict, errs3 = InputSanitizer.validate_json_schema("not a dict", {"x": int})
test("json_schema: non-dict payload fails", not not_dict)

bool_as_int, errs_bool = InputSanitizer.validate_json_schema({"age": True}, {"age": int})
test("json_schema: bool does not count as int", not bool_as_int and len(errs_bool) == 1)

nested_ok, _ = InputSanitizer.validate_json_schema(
    {"user": {"name": "Ada", "age": 36}},
    {"user": {"name": str, "age": int}},
)
test("json_schema: valid nested object", nested_ok)
extra_ok, extra_errs = InputSanitizer.validate_json_schema(
    {"name": "x", "extra": 1},
    {"name": str},
    reject_extra_keys=True,
)
test("json_schema: reject_extra_keys", not extra_ok and any("Unexpected field" in e for e in extra_errs))

print("\n--- AuthManager ---")
# The available crypto backend is detected.
backend = AuthManager.get_available_crypto_backend()
test("get_backend: returns a valid backend", backend in ["argon2", "bcrypt", "pbkdf2:sha256"])

# Password strength heuristics: composition and well-known weaknesses.
score, fb = AuthManager.evaluate_password_strength("Abc123!@#Secure")
test("password_strength: strong password >= 5", score >= 5)
score2, fb2 = AuthManager.evaluate_password_strength("abc")
test("password_strength: weak password < 3", score2 < 3 and len(fb2) > 0)

# Salted hashes and constant-time verification.
h = AuthManager.hash_password("MyPa$$word2024")
test("hash_password: produces a non-empty hash", len(h) > 10)
test("verify_password: correct password", AuthManager.verify_password("MyPa$$word2024", h))
test("verify_password: wrong password", not AuthManager.verify_password("WrongXYZ", h))
test("verify_password: corrupt hash", not AuthManager.verify_password("x", "invalid_hash"))

# HMAC-signed anti-CSRF tokens, including session IDs that contain ':'.
csrf = AuthManager.create_csrf_token("csrf_secret", "sess_001")
test("csrf_token: contains the session_id", "sess_001" in csrf)
test("verify_csrf: valid token", AuthManager.verify_csrf_token(csrf, "csrf_secret", "sess_001"))
test("verify_csrf: wrong session", not AuthManager.verify_csrf_token(csrf, "csrf_secret", "sess_WRONG"))
test("verify_csrf: wrong secret", not AuthManager.verify_csrf_token(csrf, "wrong_secret", "sess_001"))
test("verify_csrf: corrupt token", not AuthManager.verify_csrf_token("a:b:c", "csrf_secret", "sess_001"))
csrf_colons = AuthManager.create_csrf_token("csrf_secret", "sess:with:colons")
test("verify_csrf: session_id with colons", AuthManager.verify_csrf_token(csrf_colons, "csrf_secret", "sess:with:colons"))

# Signed tokens round-trip, and wrong keys or formats are rejected.
tok = AuthManager.create_secure_token({"user": "admin"}, "jwt_secret_key")
valid, payload, msg = AuthManager.verify_secure_token(tok, "jwt_secret_key")
test("secure_token: valid signature", valid and payload["user"] == "admin")
bad_valid, _, bad_msg = AuthManager.verify_secure_token(tok, "wrong_key")
test("secure_token: invalid signature with the wrong key", not bad_valid)
test("secure_token: invalid token format", not AuthManager.verify_secure_token("xyz", "k")[0])

# RBAC with an admin wildcard and restricted roles.
perms = {"admin": ["*"], "editor": ["read", "write"], "viewer": ["read"]}
test("rbac: admin has every permission", AuthManager.check_permission(["admin"], "delete", perms))
test("rbac: editor has write", AuthManager.check_permission(["editor"], "write", perms))
test("rbac: viewer does not have write", not AuthManager.check_permission(["viewer"], "write", perms))

print("\n--- RateLimiter ---")
rl = RateLimiter(max_requests=3, window_seconds=60)
test("rate_limiter: 1st request allowed", rl.is_allowed("ip_test"))
test("rate_limiter: 2nd request allowed", rl.is_allowed("ip_test"))
test("rate_limiter: 3rd request allowed", rl.is_allowed("ip_test"))
test("rate_limiter: 4th request BLOCKED", not rl.is_allowed("ip_test"))
test("rate_limiter: another IP allowed", rl.is_allowed("ip_other"))

print("\n--- ConfigManager ---")
cfg = {"SECRET_KEY": "123456", "DEBUG": "True", "SAFE_VAR": "hello"}
findings = ConfigManager.audit_config_dict(cfg)
test("audit_config: flags the insecure SECRET_KEY", any("SECRET_KEY" in f[0] for f in findings))
test("audit_config: flags DEBUG enabled", any("DEBUG" in f[0] for f in findings))

# =================================================================
# Code quality, dependency auditing and SAST/SARIF static analysis
# =================================================================
header("AGENT 2: CODE QUALITY AND SAST")

print("\n--- LinterConfigGenerator ---")
with tempfile.TemporaryDirectory() as td:
    f8 = LinterConfigGenerator.generate_flake8_config(td)
    test("generate_flake8_config: creates .flake8", os.path.exists(f8))
    toml = LinterConfigGenerator.generate_pyproject_toml(td)
    test("generate_pyproject_toml: creates pyproject.toml", os.path.exists(toml))
    eslint = LinterConfigGenerator.generate_eslint_config(td)
    test("generate_eslint_config: creates .eslintrc.json", os.path.exists(eslint))

print("\n--- DependencyAuditor ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
    f.write("requests\nflask>=2.0\nnumpy==1.24.0\n")
    req_p = f.name
audit = DependencyAuditor.audit_requirements_txt(req_p)
test("audit_req: flags unpinned 'requests'", any("requests" in a[0] for a in audit))
test("audit_req: flags >= on flask", any("flask" in a[0] for a in audit))

# Pinning with a simulated index: the latest version that satisfies each requirement, never the lower bound.
_index = {"requests": ["2.31.0", "2.32.3"], "flask": ["2.0.0", "2.3.3", "3.1.0"], "numpy": ["1.24.0"]}
_, fixes = DependencyAuditor.auto_fix_requirements_txt(req_p, pin_ranges=True, index=lambda n: _index[n])
test("auto_fix: fixes at least 2 packages (unpinned + range)", fixes >= 2)
with open(req_p) as rf:
    fixed_req = rf.read()
test("auto_fix: requests pinned to the latest version", "requests==2.32.3" in fixed_req)
test("auto_fix: flask>=2.0 pinned to the latest match", "flask==3.1.0" in fixed_req)
test("auto_fix: does not pin to the lower bound", "flask==2.0\n" not in fixed_req)
os.unlink(req_p)

with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
    json.dump({"dependencies": {"express": "^4.18.0"}, "devDependencies": {"jest": "~29.0"}}, f)
    pkg_p = f.name
pkg_audit = DependencyAuditor.audit_package_json(pkg_p)
test("audit_pkg: flags ^ on express", any("express" in a[0] for a in pkg_audit))
os.unlink(pkg_p)

print("\n--- StaticCodeAnalyzer (Bandit SAST) ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write("import subprocess, pickle\ndef foo(x):\n    eval(x)\n    pickle.loads(x)\n    subprocess.Popen('ls', shell=True)\ntry:\n    pass\nexcept:\n    pass\n")
    code_p = f.name
issues = StaticCodeAnalyzer.analyze_python_file(code_p)
test("SAST: detects eval()", any("eval" in i[2] for i in issues))
test("SAST: detects pickle.loads()", any("pickle.loads" in i[2] for i in issues))
test("SAST: detects subprocess shell=True", any("shell=True" in i[2] for i in issues))
test("SAST: detects bare except", any("except" in i[2].lower() for i in issues))
test("SAST: detects a missing docstring", any("docstring" in i[2].lower() for i in issues))

# SARIF 2.1.0 output with results filled in.
with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as sf:
    sarif_p = sf.name
StaticCodeAnalyzer.export_to_sarif(code_p, issues, sarif_p)
with open(sarif_p) as srf:
    sarif = json.load(srf)
test("SARIF: version 2.1.0", sarif.get("version") == "2.1.0")
test("SARIF: contains results", len(sarif["runs"][0]["results"]) > 0)
os.unlink(code_p)
os.unlink(sarif_p)

# =================================================================
# Hardening of web servers, containers, services and clusters
# =================================================================
header("AGENT 3: INFRASTRUCTURE HARDENING")

print("\n--- WebServerHardening ---")
nginx = WebServerHardening.generate_nginx_config("example.com")
test("nginx: contains TLSv1.3", "TLSv1.3" in nginx)
test("nginx: contains server_tokens off", "server_tokens off" in nginx)
test("nginx: contains HSTS", "Strict-Transport-Security" in nginx)

# Modern TLS directives and no server fingerprint in the Caddyfile.
caddy = WebServerHardening.generate_caddy_config("example.com", "default-src 'self';")
test("caddy: contains tls1.3", "tls1.3" in caddy)
test("caddy: protocols inside the tls block", "tls {" in caddy and "protocols tls1.2 tls1.3" in caddy)
test("caddy: hides Server (-Server)", "-Server" in caddy)
test("caddy: contains X-Frame-Options", "X-Frame-Options" in caddy)

# Every security header present versus none at all.
all_h = {k: v for k, v in WebServerHardening.DEFAULT_HTTP_HEADERS.items()}
test("audit_headers: all present = OK", WebServerHardening.audit_http_headers(all_h)[0][1] == "OK")
missing = WebServerHardening.audit_http_headers({})
test("audit_headers: no headers = several findings", len(missing) >= 3)

print("\n--- ContainerHardening ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='Dockerfile', delete=False) as f:
    df_p = f.name
ContainerHardening.generate_hardened_dockerfile(df_p)
with open(df_p) as df:
    df_content = df.read()
test("dockerfile: contains a non-root USER", "USER" in df_content)
os.unlink(df_p)

print("\n--- ServiceHardening ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.service', delete=False) as f:
    svc_p = f.name
ServiceHardening.generate_hardened_service(svc_p)
with open(svc_p) as sf:
    svc_content = sf.read()
test("systemd: contains ProtectSystem", "ProtectSystem" in svc_content)
test("systemd: contains PrivateTmp", "PrivateTmp" in svc_content)
os.unlink(svc_p)

print("\n--- K8sHardening ---")
k8s_yaml = K8sHardening.generate_hardened_pod_manifest("test-app", "test-image:1.0")
test("k8s: contains runAsNonRoot: true", "runAsNonRoot: true" in k8s_yaml)
test("k8s: contains readOnlyRootFilesystem: true", "readOnlyRootFilesystem: true" in k8s_yaml)
test("k8s: contains drop ALL", "ALL" in k8s_yaml)

insecure_pod = {"spec": {"containers": [{"name": "app", "image": "nginx"}]}}
k8s_findings = K8sHardening.audit_pod_security_context(insecure_pod)
test("k8s_audit: flags missing runAsNonRoot", any("runAsNonRoot" in f[0] for f in k8s_findings))
test("k8s_audit: flags missing allowPrivilegeEscalation", any("allowPrivilegeEscalation" in f[0] for f in k8s_findings))

secure_pod = {
    "spec": {
        "securityContext": {"runAsNonRoot": True},
        "containers": [{"name": "app", "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}}]
    }
}
secure_findings = K8sHardening.audit_pod_security_context(secure_pod)
test("k8s_audit: secure pod = OK", secure_findings[0][1] == "OK")

# =================================================================
# Refactoring, complexity metrics, SOLID audit and architecture diagrams
# =================================================================
header("AGENT 4: REFACTORING AND ARCHITECTURE")

print("\n--- CodeMetricsCalculator (cognitive complexity) ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write("def complex_func(x):\n    if x > 0:\n        for i in range(x):\n            if i > 5:\n                while True:\n                    break\n    return x\n")
    metrics_p = f.name
metrics = CodeMetricsCalculator.calculate_file_metrics(metrics_p)
test("metrics: total_lines > 0", metrics["total_lines"] > 0)
test("metrics: code_loc > 0", metrics["code_loc"] > 0)
test("metrics: functions_count = 1", metrics["functions_count"] == 1)
test("metrics: avg_cyclomatic > 1", metrics["avg_cyclomatic_complexity"] > 1)
test("metrics: avg_cognitive_complexity present", "avg_cognitive_complexity" in metrics)
test("metrics: avg_cognitive > 0 (nested function)", metrics["avg_cognitive_complexity"] > 0)
test("metrics: function_details has 4 fields (name, line, cyc, cog)", len(metrics["function_details"][0]) == 4)

bad_metrics = CodeMetricsCalculator.calculate_file_metrics("/nonexistent.py")
test("metrics: missing file returns an error", "error" in bad_metrics)
os.unlink(metrics_p)

print("\n--- SOLIDChecker ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write("class BigClass:\n" + "\n".join([f"    def m{i}(self): pass" for i in range(15)]) + "\n")
    solid_p = f.name
solid = SOLIDChecker.audit_file(solid_p)
test("solid: flags SRP (15 methods)", any("SRP" in s[1] for s in solid))
os.unlink(solid_p)

print("\n--- RefactorSuggester ---")
mock_metrics = {"avg_cyclomatic_complexity": 12.0, "comment_ratio": 2.0, "functions_count": 30}
mock_solid = [(1, "SRP", "MEDIUM", "Big class")]
recs = RefactorSuggester.generate_recommendations(mock_metrics, mock_solid)
test("refactor: produces recommendations", len(recs) > 0)

print("\n--- ArchitectureDiagramGenerator ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write("class Animal:\n    def speak(self): pass\nclass Dog(Animal):\n    def bark(self): pass\n")
    arch_p = f.name
diagram = ArchitectureDiagramGenerator.generate_mermaid_diagram(arch_p)
test("mermaid: contains classDiagram", "classDiagram" in diagram)
test("mermaid: contains class Animal", "class Animal" in diagram)
test("mermaid: contains the inheritance Animal <|-- Dog", "Animal <|-- Dog" in diagram)
os.unlink(arch_p)

# =================================================================
# Quality assurance, suite generation and HTTP contract tests
# =================================================================
header("AGENT 5: QA AND TEST AUTOMATION")

print("\n--- QATestGenerator ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write("def add(a, b):\n    return a + b\ndef subtract(a, b):\n    return a - b\n")
    qa_src = f.name
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    qa_test = f.name
QATestGenerator.generate_test_suite(qa_src, qa_test)
with open(qa_test) as tf:
    test_content = tf.read()
test("test_gen: emits the unittest import", "import unittest" in test_content)
test("test_gen: emits test_add", "test_add" in test_content)
test("test_gen: emits test_subtract", "test_subtract" in test_content)
test("test_gen: happy path with assertEqual", "assertEqual" in test_content)
test("test_gen: does not swallow generic exceptions", "isinstance(e, Exception)" not in test_content)

print("\n--- QATestRunner ---")
run_results = QATestRunner.run_unittest_suite(qa_test)
test("test_runner: runs tests (tests_run > 0)", run_results["tests_run"] > 0)
test("test_runner: 100% pass rate", run_results["pass_rate_percentage"] == 100.0)
test("test_runner: duration recorded", run_results["duration_seconds"] > 0)
os.unlink(qa_src)
os.unlink(qa_test)

print("\n--- APIContractTester ---")
ok_api = APIContractTester.validate_api_response("/users", 200, {"id": 1, "name": "test"}, {}, 50.0, 200, {"id": int, "name": str}, 100.0)
test("api_contract: correct response PASSED", ok_api["passed"])

fail_status = APIContractTester.validate_api_response("/err", 500, {}, {}, 50.0, 200)
test("api_contract: status 500 FAILED", not fail_status["passed"])

fail_sla = APIContractTester.validate_api_response("/slow", 200, {}, {}, 600.0, 200, None, 100.0)
test("api_contract: SLA exceeded FAILED", not fail_sla["passed"])

fail_schema = APIContractTester.validate_api_response("/bad", 200, {"id": "wrong"}, {}, 50.0, 200, {"id": int}, 100.0)
test("api_contract: schema type mismatch FAILED", not fail_schema["passed"])

# An ephemeral loopback HTTP server, to check the latency SLA and the schema against a live response.
class _TmpHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): return  # keep the output clean
    def do_GET(self):
        body = b'{"id": 7, "name": "ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
_srv = HTTPServer(("127.0.0.1", 0), _TmpHandler)
_port = _srv.server_address[1]
_th = Thread(target=_srv.serve_forever, daemon=True)
_th.start()
try:
    http_ok = APIContractTester.request_and_validate(
        f"http://127.0.0.1:{_port}/x",
        expected_schema={"id": int, "name": str},
        max_sla_ms=2000.0,
    )
    test("api_http: request_and_validate PASSED", http_ok["passed"])
finally:
    _srv.shutdown()

http_fail = APIContractTester.request_and_validate("http://127.0.0.1:1/nope", max_sla_ms=500.0, timeout=1.0)
test("api_http: unreachable target FAILED", not http_fail["passed"])

print("\n--- QAReporter ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
    md_rpt = f.name
with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
    html_rpt = f.name
QAReporter.generate_markdown_report(run_results, [ok_api], md_rpt)
QAReporter.generate_html_report(run_results, [ok_api], html_rpt)
test("reporter_md: writes a valid Markdown file", os.path.getsize(md_rpt) > 100)
with open(html_rpt) as hf:
    html_c = hf.read()
test("reporter_html: contains the HTML DOCTYPE", "<!DOCTYPE html>" in html_c)
test("reporter_html: contains the QA styling", "metric-card" in html_c)
os.unlink(md_rpt)
os.unlink(html_rpt)

# =================================================================
# SRE observability, structured telemetry, probes and SLA alerts
# =================================================================
header("AGENT 6: SRE AND OBSERVABILITY")

print("\n--- StructuredLogger ---")
logger = StructuredLogger("test-service")
info_log = logger.info("Test message", context={"user_id": 1})
test("logger_info: contains level INFO", '"level": "INFO"' in info_log)
test("logger_info: contains a trace_id", '"trace_id"' in info_log)
test("logger_info: contains an ISO timestamp", '"timestamp"' in info_log)

warn_log = logger.warning("Warn", context={"password": "secret123", "token": "abc"})
test("logger_warn: masks password", "***MASKED***" in warn_log and "secret123" not in warn_log)
test("logger_warn: masks token", "***MASKED***" in warn_log and '"abc"' not in warn_log)

err_log = logger.error("Error occurred")
test("logger_error: level ERROR", '"level": "ERROR"' in err_log)
crit_log = logger.critical("Critical failure")
test("logger_critical: level CRITICAL", '"level": "CRITICAL"' in crit_log)

print("\n--- LogAnomalyAuditor ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
    f.write("2026-01-01 OK normal line\nTraceback (most recent call last):\nHTTP/1.1 503 Service Unavailable\nAuthentication failed for user admin\nOutOfMemoryError: heap exhausted\nConnectionRefusedError: DB connection\n")
    log_p = f.name
anomalies = LogAnomalyAuditor.audit_log_file(log_p)
test("anomaly: detects Traceback", any("Traceback" in a[2] for a in anomalies))
test("anomaly: detects HTTP 5xx", any("5xx" in a[2] for a in anomalies))
test("anomaly: detects Authentication failed", any("authentication" in a[2].lower() for a in anomalies))
test("anomaly: detects OOM", any("memory" in a[2].lower() for a in anomalies))
test("anomaly: detects ConnectionRefused", any("connectivity" in a[2].lower() for a in anomalies))
test("anomaly: 5 anomalies in total", len(anomalies) == 5)
os.unlink(log_p)

test("anomaly: missing file", LogAnomalyAuditor.audit_log_file("/nonexistent.log")[0][1] == "ERROR")

print("\n--- SystemHealthChecker ---")
health = SystemHealthChecker.check_health(min_free_mb=1.0)
test("health: status HEALTHY", health["status"] == "HEALTHY")
test("health: contains python_version", "python_version" in health)
test("health: contains a timestamp", "timestamp" in health)
test("health: includes the disk check", any(c.get("name") == "disk" for c in health.get("checks", [])))
bad_disk = SystemHealthChecker.check_health(min_free_mb=10**12)
test("health: insufficient disk => UNHEALTHY", bad_disk["status"] == "UNHEALTHY")
tcp_fail = SystemHealthChecker.check_tcp("127.0.0.1", 1)
test("health: TCP to a closed port fails", tcp_fail["ok"] is False)

print("\n--- PrometheusExporter ---")
prom = PrometheusExporter.generate_metrics(500, 10, 7200.0)
test("prometheus: contains app_requests_total 500", "app_requests_total 500" in prom)
test("prometheus: contains errors_total 10", "app_requests_errors_total 10" in prom)
test("prometheus: contains uptime 7200.0", "app_uptime_seconds 7200.0" in prom)
test("prometheus: contains HELP and TYPE", "# HELP" in prom and "# TYPE" in prom)

print("\n--- AlertingEngine ---")
alert_yes, msg_yes = AlertingEngine.evaluate_error_rate(100, 10, 5.0)
test("alerting: 10% errors > 5% SLA fires an alert", alert_yes and "ALERT" in msg_yes)

alert_no, msg_no = AlertingEngine.evaluate_error_rate(100, 3, 5.0)
test("alerting: 3% errors < 5% SLA fires no alert", not alert_no and "OK" in msg_no)

alert_zero, msg_zero = AlertingEngine.evaluate_error_rate(0, 0, 5.0)
test("alerting: no traffic fires no alert", not alert_zero)

# =================================================================
# CI/CD pipelines, hardened Docker Compose, Helm charts and YAML validation
# =================================================================
header("AGENT 7: DEVOPS PIPELINES AND CI/CD")

print("\n--- GitHubActionsGenerator ---")
with tempfile.TemporaryDirectory() as td:
    gh = os.path.join(td, "ci.yml")
    GitHubActionsGenerator.generate_workflow(gh)
    with open(gh) as gf:
        gh_content = gf.read()
    test("github: contains DevSecOps", "DevSecOps" in gh_content)
    test("github: contains ruff", "ruff" in gh_content)
    test("github: contains bandit", "bandit" in gh_content)
    test("github: no unnecessary security-events permission", "security-events" not in gh_content)

print("\n--- GitLabCIGenerator ---")
with tempfile.TemporaryDirectory() as td:
    gl = os.path.join(td, ".gitlab-ci.yml")
    GitLabCIGenerator.generate_ci_file(gl)
    with open(gl) as glf:
        gl_content = glf.read()
    test("gitlab: contains stages", "stages:" in gl_content)
    test("gitlab: contains bandit", "bandit" in gl_content)

print("\n--- DockerComposeGenerator ---")
with tempfile.TemporaryDirectory() as td:
    dc = os.path.join(td, "docker-compose.yml")
    DockerComposeGenerator.generate_compose_file(dc)
    with open(dc) as dcf:
        dc_content = dcf.read()
    test("compose: contains read_only: true", "read_only: true" in dc_content)
    test("compose: contains no-new-privileges", "no-new-privileges" in dc_content)
    test("compose: contains a memory limit", "memory:" in dc_content)
    test("compose: contains the Compose v2 mem_limit", "mem_limit:" in dc_content)
    test("compose: documents Swarm vs Compose", "Swarm" in dc_content)

print("\n--- HelmGenerator ---")
with tempfile.TemporaryDirectory() as td:
    helm_dir = os.path.join(td, "chart")
    HelmGenerator.generate_helm_chart(helm_dir, "test-svc", "myorg/myapp")
    test("helm: Chart.yaml exists", os.path.exists(os.path.join(helm_dir, "Chart.yaml")))
    test("helm: values.yaml exists", os.path.exists(os.path.join(helm_dir, "values.yaml")))
    test("helm: templates/deployment.yaml exists", os.path.exists(os.path.join(helm_dir, "templates", "deployment.yaml")))
    with open(os.path.join(helm_dir, "values.yaml")) as vf:
        vals = vf.read()
    test("helm: values contains runAsNonRoot", "runAsNonRoot" in vals)
    test("helm: values contains allowPrivilegeEscalation", "allowPrivilegeEscalation" in vals)
    with open(os.path.join(helm_dir, "templates", "deployment.yaml")) as df:
        dep = df.read()
    test("helm: the deployment drops capabilities", "capabilities" in dep)

print("\n--- YAMLValidator ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
    f.write("key: value\nlist:\n  - item1\n  - item2\n")
    good_yaml = f.name
ok_y, errs_y = YAMLValidator.validate_yaml_syntax(good_yaml)
test("yaml_validator: valid YAML without errors", ok_y and len(errs_y) == 0)
os.unlink(good_yaml)

with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
    f.write("key:\tvalue_with_tab\n")
    bad_yaml = f.name
bad_y, bad_errs = YAMLValidator.validate_yaml_syntax(bad_yaml)
test("yaml_validator: detects forbidden tabs", not bad_y and any("tab" in e.lower() for e in bad_errs))
os.unlink(bad_yaml)

with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
    f.write('ports:\n  - "8080:8080"\nsecurity_opt:\n  - no-new-privileges:true\n')
    compose_like = f.name
ok_compose, errs_compose = YAMLValidator.validate_yaml_syntax(compose_like)
test("yaml_validator: accepts ports and no-new-privileges", ok_compose and len(errs_compose) == 0)
os.unlink(compose_like)

test("yaml_validator: missing file", not YAMLValidator.validate_yaml_syntax("/nonexistent.yaml")[0])

# =================================================================
# OpenAPI 3.0.3 generation, Markdown manuals and Swagger UI
# =================================================================
header("AGENT 8: AUTOMATED DOCUMENTATION AND OPENAPI")

print("\n--- OpenAPIGenerator ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write(
        "def get_users(limit: int = 10):\n    '''Return users.'''\n    pass\n"
        "def post_create_user(name: str):\n    '''Create a user.'''\n    pass\n"
        "def put_update_item(item_id: int, title: str):\n    '''Update an item.'''\n    pass\n"
        "def delete_user(uid: int):\n    '''Delete a user.'''\n    pass\n"
    )
    api_src = f.name
spec = OpenAPIGenerator.generate_openapi_spec(api_src, "Test API", "2.0.0")
test("openapi: version 3.0.3", spec["openapi"] == "3.0.3")
test("openapi: correct title", spec["info"]["title"] == "Test API")
test("openapi: maps /users (get)", "/users" in spec["paths"])
test("openapi: maps /create_user (post)", "/create_user" in spec["paths"])
test("openapi: maps /update_item (put)", "/update_item" in spec["paths"] and "put" in spec["paths"]["/update_item"])
test("openapi: maps /user (delete) without the prefix", "/user" in spec["paths"] and "delete" in spec["paths"]["/user"])
put_op = spec["paths"]["/update_item"]["put"]
test("openapi: put includes requestBody", "requestBody" in put_op)
test("openapi: components.schemas present", bool(spec.get("components", {}).get("schemas")))
get_op = spec["paths"]["/users"]["get"]
test("openapi: get includes parameters", "parameters" in get_op)
test("openapi: delete includes the uid query parameter", any(p.get("name") == "uid" for p in spec["paths"]["/user"]["delete"].get("parameters", [])))

# JSON export keeps the OpenAPI version intact.
with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
    json_out = f.name
OpenAPIGenerator.export_spec_to_json(spec, json_out)
with open(json_out) as jf:
    loaded = json.load(jf)
test("openapi_json: parses back correctly", loaded["openapi"] == "3.0.3")
os.unlink(json_out)

# The equivalent YAML export, without structural loss.
with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
    yaml_out = f.name
OpenAPIGenerator.export_spec_to_yaml(spec, yaml_out)
test("openapi_yaml: writes a YAML file", os.path.getsize(yaml_out) > 50)
os.unlink(yaml_out)
os.unlink(api_src)

print("\n--- MarkdownDocGenerator ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write('"""Test module."""\nclass MyService:\n    """Main service."""\n    def run(self):\n        """Run the service."""\n        pass\n')
    doc_src = f.name
with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
    doc_out = f.name
MarkdownDocGenerator.generate_module_docs(doc_src, doc_out)
with open(doc_out) as df:
    doc_content = df.read()
test("md_doc: contains a title with the file name", "Technical Documentation" in doc_content)
test("md_doc: contains class MyService", "MyService" in doc_content)
test("md_doc: contains method run", "run" in doc_content)
os.unlink(doc_src)
os.unlink(doc_out)

print("\n--- SwaggerUIGenerator ---")
mini_spec = {"openapi": "3.0.3", "info": {"title": "Mini"}, "paths": {}}
with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
    swag_out = f.name
SwaggerUIGenerator.generate_swagger_ui_html(mini_spec, swag_out)
with open(swag_out) as sf:
    swag_html = sf.read()
test("swagger_ui: contains SwaggerUIBundle", "SwaggerUIBundle" in swag_html)
test("swagger_ui: contains the swagger-ui CSS from the CDN", "swagger-ui.css" in swag_html)
test("swagger_ui: contains the embedded spec", "3.0.3" in swag_html)
os.unlink(swag_out)

# =================================================================
# Every agent's demo entry point runs to completion
# =================================================================
header("RUNNING EVERY main.py")

agents_main = [
    ("defensive", "Defensive"),
    ("quality", "Code quality"),
    ("hardening", "Hardening"),
    ("refactor", "Refactoring"),
    ("qa", "QA"),
    ("sre", "SRE observability"),
    ("devops", "DevOps pipelines"),
    ("docs", "Documentation"),
]
prev_workdir = os.environ.get("AGENTES_WORKDIR")
with tempfile.TemporaryDirectory() as demo_workdir:
    if prev_workdir is None:
        os.environ["AGENTES_WORKDIR"] = demo_workdir
    try:
        for agent_pkg, label in agents_main:
            exit_code = os.system(f'cd "{AGENTS_DIR}" && "{sys.executable}" -m agentes.{agent_pkg}.main > /dev/null 2>&1')
            test(f"main.py [{label}] runs without errors (exit 0)", exit_code == 0)
    finally:
        if prev_workdir is None:
            os.environ.pop("AGENTES_WORKDIR", None)

# =================================================================
# The agentes CLI and its pipeline subcommands, end to end
# =================================================================
header("agentes CLI (agentes_cli.py)")
cli_path = os.path.join(AGENTS_DIR, "agentes_cli.py")
cli_list = os.system(f'"{sys.executable}" {cli_path} list > /dev/null 2>&1')
test("cli: list exit 0", cli_list == 0)
cli_help = os.popen(f'"{sys.executable}" {cli_path} list').read()
test("cli: lists the known agents", "defensive" in cli_help and "devops" in cli_help)

# Report artefacts (analyze.json, pipeline.json, SARIF and HTML) are written for minimal projects.
with tempfile.TemporaryDirectory() as td:
    sample = os.path.join(td, "sample.py")
    with open(sample, "w") as sf:
        sf.write("def ok():\n    return 1\n")
    out_dir = os.path.join(td, "reports")
    an_code = os.system(f'"{sys.executable}" {cli_path} analyze {sample} -o {out_dir} > /dev/null 2>&1')
    test("cli: analyze exit 0", an_code == 0)
    test("cli: analyze writes analyze.json", os.path.exists(os.path.join(out_dir, "analyze.json")))

with tempfile.TemporaryDirectory() as td:
    sample = os.path.join(td, "app.py")
    with open(sample, "w") as sf:
        sf.write("def get_health():\n    '''ok'''\n    return {'ok': True}\n")
    out_dir = os.path.join(td, "reports")
    pipe_code = os.system(f'"{sys.executable}" {cli_path} pipeline {td} -o {out_dir} --no-fail > /dev/null 2>&1')
    test("cli: pipeline --no-fail exit 0", pipe_code == 0)
    test("cli: pipeline writes pipeline.json", os.path.exists(os.path.join(out_dir, "pipeline.json")))
    test("cli: pipeline writes pipeline.sarif", os.path.exists(os.path.join(out_dir, "pipeline.sarif")))
    test("cli: pipeline writes pipeline.html", os.path.exists(os.path.join(out_dir, "pipeline.html")))

# AST rules for hardcoded credentials, asserts and interpolated SQL.
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write('PASSWORD = "hardcodedsecret123"\nassert True\ncursor.execute(f"SELECT {x}")\n')
    sast2 = f.name
issues2 = StaticCodeAnalyzer.analyze_python_file(sast2, prefer_bandit=False)
test("SAST: detects a hardcoded secret", any("secret" in i[2].lower() or "PASSWORD" in i[2] for i in issues2))
test("SAST: detects assert", any("assert" in i[2].lower() for i in issues2))
test("SAST: detects SQL built with an f-string", any("sql" in i[2].lower() for i in issues2))
os.unlink(sast2)

# Heuristic function coverage computed from a module and its tests.
with tempfile.TemporaryDirectory() as td:
    src = os.path.join(td, "modx.py")
    tst = os.path.join(td, "test_modx.py")
    with open(src, "w") as f:
        f.write("def alpha(a, b):\n    return a + b\n")
    with open(tst, "w") as f:
        f.write("import unittest\nfrom modx import *\nclass T(unittest.TestCase):\n    def test_alpha_happy_path(self):\n        self.assertEqual(alpha(2, 3), 5)\n")
    cov = QATestRunner.estimate_function_coverage(tst)
    test("qa_coverage: percentage present", "coverage_percentage" in cov)
    test("qa_coverage: alpha covered", cov.get("functions_tested", 0) >= 1)

# OpenAPI extraction from FastAPI/Flask-style route decorators.
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write('app=None\n@app.get("/items")\ndef list_items():\n    """x"""\n    return []\n')
    flask_src = f.name
spec_fw = OpenAPIGenerator.generate_openapi_spec(flask_src)
test("openapi: detects FastAPI/Flask decorators", "/items" in spec_fw["paths"])
os.unlink(flask_src)

# Docker Compose service name, port and memory limit are parameterised.
with tempfile.TemporaryDirectory() as td:
    dc2 = os.path.join(td, "docker-compose.yml")
    DockerComposeGenerator.generate_compose_file(dc2, service_name="api", port=9090, mem_limit="256m")
    with open(dc2) as f:
        c2 = f.read()
    test("compose: parameterised port", "9090:9090" in c2)
    test("compose: parameterised service", "api:" in c2)

# =================================================================
# Summary and exit status
# =================================================================
header(f"END-TO-END CHECK SUMMARY (8 AGENTS v{AGENTES_VERSION})")
total = passed + failed
print(f"\n  Checks run: {total}")
print(f"  Passed: {passed}")
print(f"  Failed: {failed}")
print(f"  Pass rate: {(passed/total*100):.1f}%")

if errors_list:
    print("\n  Failures:")
    for e in errors_list:
        print(f"    {e}")

print("")
sys.exit(0 if failed == 0 else 1)
