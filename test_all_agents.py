#!/usr/bin/env python3
"""
Verificación exhaustiva de los 8 agentes.

Llama a las funciones y métodos públicos de cada agente con datos de ejemplo, ejecuta sus demos
en un directorio temporal y prueba el CLI de punta a punta. Complementa a pytest: aquí se
comprueba que las piezas funcionan juntas, y en tests/ cada regla por separado. Termina con
código 1 si falla alguna comprobación. El CI la ejecuta después de pytest.
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

# La batería no depende de la red: PyPI y OSV quedan desactivados (también en los subprocesos).
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
        msg = f"  [FALLO] {name}" + (f" -> {detail}" if detail else "")
        print(msg)
        errors_list.append(msg)

def header(title):
    print(f"\n{'='*70}")
    print(f" {title}")
    print(f"{'='*70}")

# =================================================================
# Controles defensivos de seguridad: sanitización, autenticación, CSRF y configuración
# =================================================================
header("AGENTE 1: CONTROLES DEFENSIVOS DE SEGURIDAD")

print("\n--- InputSanitizer ---")
# Verificar neutralización de etiquetas peligrosas y preservación de tipos vacíos en HTML.
test("sanitize_html: Escapa script tags", "&lt;script&gt;" in InputSanitizer.sanitize_html("<script>alert(1)</script>"))
test("sanitize_html: Escapa comillas", "&quot;" in InputSanitizer.sanitize_html('"hola"'))
test("sanitize_html: No-string retorna vacío", InputSanitizer.sanitize_html(123) == "")
test("sanitize_html: Cadena vacía ok", InputSanitizer.sanitize_html("") == "")

# Comprobar validación sintáctica básica de direcciones de correo electrónico.
test("validate_email: email válido", InputSanitizer.validate_email("user@domain.com"))
test("validate_email: email inválido (sin @)", not InputSanitizer.validate_email("userdomain"))
test("validate_email: email vacío", not InputSanitizer.validate_email(""))

# Asegurar contención de traversal en nombres de archivo y respaldo seguro ante cadenas vacías.
test("sanitize_filename: path traversal ../../etc/passwd", InputSanitizer.sanitize_filename("../../etc/passwd") == "passwd")
test("sanitize_filename: solo puntos dobles", "_" in InputSanitizer.sanitize_filename(".."))
test("sanitize_filename: vacío retorna default", InputSanitizer.sanitize_filename("") == "file_default")
test("sanitize_filename: nombre normal ok", InputSanitizer.sanitize_filename("report.pdf") == "report.pdf")

# Verificar filtrado estricto por lista blanca de caracteres y rechazo de tipos no textuales.
test("whitelist: texto alfanum ok", InputSanitizer.validate_string_whitelist("hello world"))
test("whitelist: no-string retorna False", not InputSanitizer.validate_string_whitelist(12345))

# Comprobar parseo seguro de enteros con cotas inferior/superior inclusivas.
test("sanitize_integer: número válido", InputSanitizer.sanitize_integer("42") == 42)
test("sanitize_integer: fuera de rango min", InputSanitizer.sanitize_integer(5, min_val=10) is None)
test("sanitize_integer: fuera de rango max", InputSanitizer.sanitize_integer(100, max_val=50) is None)
test("sanitize_integer: no-numérico", InputSanitizer.sanitize_integer("abc") is None)

# Validar esquemas JSON recursivos, rechazo de booleanos como enteros y bloqueo de claves adicionales.
ok, errs = InputSanitizer.validate_json_schema({"name": "Alice", "age": 30}, {"name": str, "age": int})
test("json_schema: payload válido", ok and len(errs) == 0)

bad, errs2 = InputSanitizer.validate_json_schema({"name": 123}, {"name": str, "age": int})
test("json_schema: tipo incorrecto y campo faltante", not bad and len(errs2) == 2)

not_dict, errs3 = InputSanitizer.validate_json_schema("no es dict", {"x": int})
test("json_schema: payload no-dict falla", not not_dict)

bool_as_int, errs_bool = InputSanitizer.validate_json_schema({"age": True}, {"age": int})
test("json_schema: bool no cuenta como int", not bool_as_int and len(errs_bool) == 1)

nested_ok, _ = InputSanitizer.validate_json_schema(
    {"user": {"name": "Ada", "age": 36}},
    {"user": {"name": str, "age": int}},
)
test("json_schema: anidado válido", nested_ok)
extra_ok, extra_errs = InputSanitizer.validate_json_schema(
    {"name": "x", "extra": 1},
    {"name": str},
    reject_extra_keys=True,
)
test("json_schema: reject_extra_keys", not extra_ok and any("no permitido" in e for e in extra_errs))

print("\n--- AuthManager ---")
# Verificar detección del proveedor criptográfico disponible en el entorno de ejecución.
backend = AuthManager.get_available_crypto_backend()
test("get_backend: retorna backend válido", backend in ["argon2", "bcrypt", "pbkdf2:sha256"])

# Evaluar heurística de entropía y complejidad mínima para contraseñas de usuario.
score, fb = AuthManager.evaluate_password_strength("Abc123!@#Seguro")
test("password_strength: contraseña fuerte >= 5", score >= 5)
score2, fb2 = AuthManager.evaluate_password_strength("abc")
test("password_strength: contraseña débil < 3", score2 < 3 and len(fb2) > 0)

# Confirmar generación de hashes con sal y verificación en tiempo constante.
h = AuthManager.hash_password("MiClave$ecreta2024")
test("hash_password: genera hash no vacío", len(h) > 10)
test("verify_password: clave correcta", AuthManager.verify_password("MiClave$ecreta2024", h))
test("verify_password: clave incorrecta", not AuthManager.verify_password("IncorrectaXYZ", h))
test("verify_password: hash corrupto", not AuthManager.verify_password("x", "invalid_hash"))

# Comprobar firma HMAC de tokens anti-CSRF incluyendo identificadores de sesión con delimitadores ':'.
csrf = AuthManager.create_csrf_token("secreto_csrf", "sess_001")
test("csrf_token: generado contiene session_id", "sess_001" in csrf)
test("verify_csrf: token válido", AuthManager.verify_csrf_token(csrf, "secreto_csrf", "sess_001"))
test("verify_csrf: sesión incorrecta", not AuthManager.verify_csrf_token(csrf, "secreto_csrf", "sess_WRONG"))
test("verify_csrf: secreto incorrecto", not AuthManager.verify_csrf_token(csrf, "wrong_secret", "sess_001"))
test("verify_csrf: token corrupto", not AuthManager.verify_csrf_token("a:b:c", "secreto_csrf", "sess_001"))
csrf_colons = AuthManager.create_csrf_token("secreto_csrf", "sess:with:colons")
test("verify_csrf: session_id con dos puntos", AuthManager.verify_csrf_token(csrf_colons, "secreto_csrf", "sess:with:colons"))

# Verificar emisión y validación íntegra de tokens firmados con rechazo ante claves o formatos inválidos.
tok = AuthManager.create_secure_token({"user": "admin"}, "jwt_secret_key")
valid, payload, msg = AuthManager.verify_secure_token(tok, "jwt_secret_key")
test("secure_token: firma válida", valid and payload["user"] == "admin")
bad_valid, _, bad_msg = AuthManager.verify_secure_token(tok, "wrong_key")
test("secure_token: firma inválida con clave incorrecta", not bad_valid)
test("secure_token: token formato inválido", not AuthManager.verify_secure_token("xyz", "k")[0])

# Confirmar evaluación de permisos RBAC con comodín administrativo y roles restringidos.
perms = {"admin": ["*"], "editor": ["read", "write"], "viewer": ["read"]}
test("rbac: admin tiene permiso total", AuthManager.check_permission(["admin"], "delete", perms))
test("rbac: editor tiene write", AuthManager.check_permission(["editor"], "write", perms))
test("rbac: viewer no tiene write", not AuthManager.check_permission(["viewer"], "write", perms))

print("\n--- RateLimiter ---")
rl = RateLimiter(max_requests=3, window_seconds=60)
test("rate_limiter: 1ra petición permitida", rl.is_allowed("ip_test"))
test("rate_limiter: 2da petición permitida", rl.is_allowed("ip_test"))
test("rate_limiter: 3ra petición permitida", rl.is_allowed("ip_test"))
test("rate_limiter: 4ta petición BLOQUEADA", not rl.is_allowed("ip_test"))
test("rate_limiter: otra IP permitida", rl.is_allowed("ip_other"))

print("\n--- ConfigManager ---")
cfg = {"SECRET_KEY": "123456", "DEBUG": "True", "SAFE_VAR": "hello"}
findings = ConfigManager.audit_config_dict(cfg)
test("audit_config: detecta SECRET_KEY inseguro", any("SECRET_KEY" in f[0] for f in findings))
test("audit_config: detecta DEBUG activado", any("DEBUG" in f[0] for f in findings))

# =================================================================
# Calidad de código, auditoría de dependencias y análisis estático SAST/SARIF
# =================================================================
header("AGENTE 2: CALIDAD DE CÓDIGO Y SAST")

print("\n--- LinterConfigGenerator ---")
with tempfile.TemporaryDirectory() as td:
    f8 = LinterConfigGenerator.generate_flake8_config(td)
    test("generate_flake8_config: crea .flake8", os.path.exists(f8))
    toml = LinterConfigGenerator.generate_pyproject_toml(td)
    test("generate_pyproject_toml: crea pyproject.toml", os.path.exists(toml))
    eslint = LinterConfigGenerator.generate_eslint_config(td)
    test("generate_eslint_config: crea .eslintrc.json", os.path.exists(eslint))

print("\n--- DependencyAuditor ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
    f.write("requests\nflask>=2.0\nnumpy==1.24.0\n")
    req_p = f.name
audit = DependencyAuditor.audit_requirements_txt(req_p)
test("audit_req: detecta unpinned 'requests'", any("requests" in a[0] for a in audit))
test("audit_req: detecta >= en flask", any("flask" in a[0] for a in audit))

# Fijación con un índice simulado: la última versión que cumple cada requisito, nunca el límite inferior.
_indice = {"requests": ["2.31.0", "2.32.3"], "flask": ["2.0.0", "2.3.3", "3.1.0"], "numpy": ["1.24.0"]}
_, fixes = DependencyAuditor.auto_fix_requirements_txt(req_p, pin_ranges=True, index=lambda n: _indice[n])
test("auto_fix: corrige al menos 2 paquetes (unpinned+rango)", fixes >= 2)
with open(req_p) as rf:
    fixed_req = rf.read()
test("auto_fix: requests fijado a la última versión", "requests==2.32.3" in fixed_req)
test("auto_fix: flask>=2.0 fijado a la última que cumple el rango", "flask==3.1.0" in fixed_req)
test("auto_fix: no fija al límite inferior", "flask==2.0\n" not in fixed_req)
os.unlink(req_p)

with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
    json.dump({"dependencies": {"express": "^4.18.0"}, "devDependencies": {"jest": "~29.0"}}, f)
    pkg_p = f.name
pkg_audit = DependencyAuditor.audit_package_json(pkg_p)
test("audit_pkg: detecta ^ en express", any("express" in a[0] for a in pkg_audit))
os.unlink(pkg_p)

print("\n--- StaticCodeAnalyzer (Bandit SAST) ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write("import subprocess, pickle\ndef foo(x):\n    eval(x)\n    pickle.loads(x)\n    subprocess.Popen('ls', shell=True)\ntry:\n    pass\nexcept:\n    pass\n")
    code_p = f.name
issues = StaticCodeAnalyzer.analyze_python_file(code_p)
test("SAST: detecta eval()", any("eval" in i[2] for i in issues))
test("SAST: detecta pickle.loads()", any("pickle.loads" in i[2] for i in issues))
test("SAST: detecta subprocess shell=True", any("shell=True" in i[2] for i in issues))
test("SAST: detecta bare except", any("except" in i[2].lower() for i in issues))
test("SAST: detecta falta de docstring", any("docstring" in i[2].lower() for i in issues))

# Confirmar serialización estándar en formato SARIF v2.1.0 con resultados poblados.
with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as sf:
    sarif_p = sf.name
StaticCodeAnalyzer.export_to_sarif(code_p, issues, sarif_p)
with open(sarif_p) as srf:
    sarif = json.load(srf)
test("SARIF: versión 2.1.0", sarif.get("version") == "2.1.0")
test("SARIF: contiene resultados", len(sarif["runs"][0]["results"]) > 0)
os.unlink(code_p)
os.unlink(sarif_p)

# =================================================================
# Endurecimiento de infraestructura web, contenedores, servicios y clústeres
# =================================================================
header("AGENTE 3: HARDENING DE INFRAESTRUCTURA")

print("\n--- WebServerHardening ---")
nginx = WebServerHardening.generate_nginx_config("example.com")
test("nginx: contiene TLSv1.3", "TLSv1.3" in nginx)
test("nginx: contiene server_tokens off", "server_tokens off" in nginx)
test("nginx: contiene HSTS", "Strict-Transport-Security" in nginx)

# Validar directivas TLS modernas y supresión de huella de servidor en Caddyfile.
caddy = WebServerHardening.generate_caddy_config("example.com", "default-src 'self';")
test("caddy: contiene tls1.3", "tls1.3" in caddy)
test("caddy: protocols dentro de bloque tls", "tls {" in caddy and "protocols tls1.2 tls1.3" in caddy)
test("caddy: oculta Server (-Server)", "-Server" in caddy)
test("caddy: contiene X-Frame-Options", "X-Frame-Options" in caddy)

# Verificar contraste entre conjunto completo de cabeceras de seguridad y ausencia total.
all_h = {k: v for k, v in WebServerHardening.DEFAULT_HTTP_HEADERS.items()}
test("audit_headers: todas presentes = OK", WebServerHardening.audit_http_headers(all_h)[0][1] == "OK")
missing = WebServerHardening.audit_http_headers({})
test("audit_headers: sin headers = múltiples hallazgos", len(missing) >= 3)

print("\n--- ContainerHardening ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='Dockerfile', delete=False) as f:
    df_p = f.name
ContainerHardening.generate_hardened_dockerfile(df_p)
with open(df_p) as df:
    df_content = df.read()
test("dockerfile: contiene USER non-root", "USER" in df_content)
os.unlink(df_p)

print("\n--- ServiceHardening ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.service', delete=False) as f:
    svc_p = f.name
ServiceHardening.generate_hardened_service(svc_p)
with open(svc_p) as sf:
    svc_content = sf.read()
test("systemd: contiene ProtectSystem", "ProtectSystem" in svc_content)
test("systemd: contiene PrivateTmp", "PrivateTmp" in svc_content)
os.unlink(svc_p)

print("\n--- K8sHardening ---")
k8s_yaml = K8sHardening.generate_hardened_pod_manifest("test-app", "test-image:1.0")
test("k8s: contiene runAsNonRoot: true", "runAsNonRoot: true" in k8s_yaml)
test("k8s: contiene readOnlyRootFilesystem: true", "readOnlyRootFilesystem: true" in k8s_yaml)
test("k8s: contiene drop ALL", "ALL" in k8s_yaml)

insecure_pod = {"spec": {"containers": [{"name": "app", "image": "nginx"}]}}
k8s_findings = K8sHardening.audit_pod_security_context(insecure_pod)
test("k8s_audit: detecta falta de runAsNonRoot", any("runAsNonRoot" in f[0] for f in k8s_findings))
test("k8s_audit: detecta falta de allowPrivilegeEscalation", any("allowPrivilegeEscalation" in f[0] for f in k8s_findings))

secure_pod = {
    "spec": {
        "securityContext": {"runAsNonRoot": True},
        "containers": [{"name": "app", "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}}]
    }
}
secure_findings = K8sHardening.audit_pod_security_context(secure_pod)
test("k8s_audit: pod seguro = OK", secure_findings[0][1] == "OK")

# =================================================================
# Refactorización, métricas de complejidad, auditoría SOLID y diagramas de arquitectura
# =================================================================
header("AGENTE 4: REFACTORIZACIÓN Y ARQUITECTURA")

print("\n--- CodeMetricsCalculator (Complejidad Cognitiva) ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write("def complex_func(x):\n    if x > 0:\n        for i in range(x):\n            if i > 5:\n                while True:\n                    break\n    return x\n")
    metrics_p = f.name
metrics = CodeMetricsCalculator.calculate_file_metrics(metrics_p)
test("metrics: total_lines > 0", metrics["total_lines"] > 0)
test("metrics: code_loc > 0", metrics["code_loc"] > 0)
test("metrics: functions_count = 1", metrics["functions_count"] == 1)
test("metrics: avg_cyclomatic > 1", metrics["avg_cyclomatic_complexity"] > 1)
test("metrics: avg_cognitive_complexity presente", "avg_cognitive_complexity" in metrics)
test("metrics: avg_cognitive > 0 (función anidada)", metrics["avg_cognitive_complexity"] > 0)
test("metrics: function_details tiene 4 elementos (name, line, cyc, cog)", len(metrics["function_details"][0]) == 4)

bad_metrics = CodeMetricsCalculator.calculate_file_metrics("/nonexistent.py")
test("metrics: archivo inexistente retorna error", "error" in bad_metrics)
os.unlink(metrics_p)

print("\n--- SOLIDChecker ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write("class BigClass:\n" + "\n".join([f"    def m{i}(self): pass" for i in range(15)]) + "\n")
    solid_p = f.name
solid = SOLIDChecker.audit_file(solid_p)
test("solid: detecta SRP (15 métodos)", any("SRP" in s[1] for s in solid))
os.unlink(solid_p)

print("\n--- RefactorSuggester ---")
mock_metrics = {"avg_cyclomatic_complexity": 12.0, "comment_ratio": 2.0, "functions_count": 30}
mock_solid = [(1, "SRP", "MEDIO", "Clase grande")]
recs = RefactorSuggester.generate_recommendations(mock_metrics, mock_solid)
test("refactor: genera recomendaciones", len(recs) > 0)

print("\n--- ArchitectureDiagramGenerator ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write("class Animal:\n    def speak(self): pass\nclass Dog(Animal):\n    def bark(self): pass\n")
    arch_p = f.name
diagram = ArchitectureDiagramGenerator.generate_mermaid_diagram(arch_p)
test("mermaid: contiene classDiagram", "classDiagram" in diagram)
test("mermaid: contiene class Animal", "class Animal" in diagram)
test("mermaid: contiene herencia Animal <|-- Dog", "Animal <|-- Dog" in diagram)
os.unlink(arch_p)

# =================================================================
# Aseguramiento de calidad, generación de suites y pruebas de contrato HTTP
# =================================================================
header("AGENTE 5: AGENTE QA Y AUTOMATIZACIÓN DE PRUEBAS")

print("\n--- QATestGenerator ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write("def suma(a, b):\n    return a + b\ndef resta(a, b):\n    return a - b\n")
    qa_src = f.name
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    qa_test = f.name
QATestGenerator.generate_test_suite(qa_src, qa_test)
with open(qa_test) as tf:
    test_content = tf.read()
test("test_gen: genera unittest import", "import unittest" in test_content)
test("test_gen: genera test_suma", "test_suma" in test_content)
test("test_gen: genera test_resta", "test_resta" in test_content)
test("test_gen: happy path con assertEqual", "assertEqual" in test_content)
test("test_gen: no traga excepciones genéricas", "isinstance(e, Exception)" not in test_content)

print("\n--- QATestRunner ---")
run_results = QATestRunner.run_unittest_suite(qa_test)
test("test_runner: ejecuta pruebas (tests_run > 0)", run_results["tests_run"] > 0)
test("test_runner: tasa de éxito 100%", run_results["pass_rate_percentage"] == 100.0)
test("test_runner: duración registrada", run_results["duration_seconds"] > 0)
os.unlink(qa_src)
os.unlink(qa_test)

print("\n--- APIContractTester ---")
ok_api = APIContractTester.validate_api_response("/users", 200, {"id": 1, "name": "test"}, {}, 50.0, 200, {"id": int, "name": str}, 100.0)
test("api_contract: respuesta correcta PASSED", ok_api["passed"])

fail_status = APIContractTester.validate_api_response("/err", 500, {}, {}, 50.0, 200)
test("api_contract: status 500 FAILED", not fail_status["passed"])

fail_sla = APIContractTester.validate_api_response("/slow", 200, {}, {}, 600.0, 200, None, 100.0)
test("api_contract: SLA excedido FAILED", not fail_sla["passed"])

fail_schema = APIContractTester.validate_api_response("/bad", 200, {"id": "wrong"}, {}, 50.0, 200, {"id": int}, 100.0)
test("api_contract: schema type mismatch FAILED", not fail_schema["passed"])

# Levantar servidor HTTP efímero en loopback para verificar latencia SLA y esquema en vivo.
class _TmpHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): return
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
test("api_http: destino inaccesible FAILED", not http_fail["passed"])

print("\n--- QAReporter ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
    md_rpt = f.name
with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
    html_rpt = f.name
QAReporter.generate_markdown_report(run_results, [ok_api], md_rpt)
QAReporter.generate_html_report(run_results, [ok_api], html_rpt)
test("reporter_md: genera archivo MD válido", os.path.getsize(md_rpt) > 100)
with open(html_rpt) as hf:
    html_c = hf.read()
test("reporter_html: contiene DOCTYPE html", "<!DOCTYPE html>" in html_c)
test("reporter_html: contiene Swagger/QA styling", "metric-card" in html_c)
os.unlink(md_rpt)
os.unlink(html_rpt)

# =================================================================
# Observabilidad SRE, telemetría estructurada, sondas y alertas SLA
# =================================================================
header("AGENTE 6: SRE Y OBSERVABILIDAD")

print("\n--- StructuredLogger ---")
logger = StructuredLogger("test-service")
info_log = logger.info("Test message", context={"user_id": 1})
test("logger_info: contiene level INFO", '"level": "INFO"' in info_log)
test("logger_info: contiene trace_id", '"trace_id"' in info_log)
test("logger_info: contiene timestamp ISO", '"timestamp"' in info_log)

warn_log = logger.warning("Warn", context={"password": "secret123", "token": "abc"})
test("logger_warn: enmascara password", "***MASKED***" in warn_log and "secret123" not in warn_log)
test("logger_warn: enmascara token", "***MASKED***" in warn_log and '"abc"' not in warn_log)

err_log = logger.error("Error occurred")
test("logger_error: level ERROR", '"level": "ERROR"' in err_log)
crit_log = logger.critical("Critical failure")
test("logger_critical: level CRITICAL", '"level": "CRITICAL"' in crit_log)

print("\n--- LogAnomalyAuditor ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
    f.write("2026-01-01 OK normal line\nTraceback (most recent call last):\nHTTP/1.1 503 Service Unavailable\nAuthentication failed for user admin\nOutOfMemoryError: heap exhausted\nConnectionRefusedError: DB connection\n")
    log_p = f.name
anomalies = LogAnomalyAuditor.audit_log_file(log_p)
test("anomaly: detecta Traceback", any("Traceback" in a[2] for a in anomalies))
test("anomaly: detecta HTTP 5xx", any("5xx" in a[2] for a in anomalies))
test("anomaly: detecta Authentication failed", any("autenticación" in a[2].lower() for a in anomalies))
test("anomaly: detecta OOM", any("memoria" in a[2].lower() for a in anomalies))
test("anomaly: detecta ConnectionRefused", any("conectividad" in a[2].lower() for a in anomalies))
test("anomaly: total 5 anomalías", len(anomalies) == 5)
os.unlink(log_p)

test("anomaly: archivo inexistente", LogAnomalyAuditor.audit_log_file("/nonexistent.log")[0][1] == "ERROR")

print("\n--- SystemHealthChecker ---")
health = SystemHealthChecker.check_health(min_free_mb=1.0)
test("health: status HEALTHY", health["status"] == "HEALTHY")
test("health: contiene python_version", "python_version" in health)
test("health: contiene timestamp", "timestamp" in health)
test("health: incluye check de disco", any(c.get("name") == "disk" for c in health.get("checks", [])))
bad_disk = SystemHealthChecker.check_health(min_free_mb=10**12)
test("health: disco insuficiente => UNHEALTHY", bad_disk["status"] == "UNHEALTHY")
tcp_fail = SystemHealthChecker.check_tcp("127.0.0.1", 1)
test("health: TCP a puerto cerrado falla", tcp_fail["ok"] is False)

print("\n--- PrometheusExporter ---")
prom = PrometheusExporter.generate_metrics(500, 10, 7200.0)
test("prometheus: contiene app_requests_total 500", "app_requests_total 500" in prom)
test("prometheus: contiene errors_total 10", "app_requests_errors_total 10" in prom)
test("prometheus: contiene uptime 7200.0", "app_uptime_seconds 7200.0" in prom)
test("prometheus: contiene HELP y TYPE", "# HELP" in prom and "# TYPE" in prom)

print("\n--- AlertingEngine ---")
alert_yes, msg_yes = AlertingEngine.evaluate_error_rate(100, 10, 5.0)
test("alerting: 10% errores > 5% SLA dispara alerta", alert_yes and "ALERTA" in msg_yes)

alert_no, msg_no = AlertingEngine.evaluate_error_rate(100, 3, 5.0)
test("alerting: 3% errores < 5% SLA no dispara alerta", not alert_no and "OK" in msg_no)

alert_zero, msg_zero = AlertingEngine.evaluate_error_rate(0, 0, 5.0)
test("alerting: sin tráfico no dispara alerta", not alert_zero)

# =================================================================
# Pipelines CI/CD, Docker Compose endurecido, Helm Charts y validación YAML
# =================================================================
header("AGENTE 7: DEVOPS PIPELINES Y CI/CD")

print("\n--- GitHubActionsGenerator ---")
with tempfile.TemporaryDirectory() as td:
    gh = os.path.join(td, "ci.yml")
    GitHubActionsGenerator.generate_workflow(gh)
    with open(gh) as gf:
        gh_content = gf.read()
    test("github: contiene DevSecOps", "DevSecOps" in gh_content)
    test("github: contiene ruff", "ruff" in gh_content)
    test("github: contiene bandit", "bandit" in gh_content)
    test("github: sin permiso security-events innecesario", "security-events" not in gh_content)

print("\n--- GitLabCIGenerator ---")
with tempfile.TemporaryDirectory() as td:
    gl = os.path.join(td, ".gitlab-ci.yml")
    GitLabCIGenerator.generate_ci_file(gl)
    with open(gl) as glf:
        gl_content = glf.read()
    test("gitlab: contiene stages", "stages:" in gl_content)
    test("gitlab: contiene bandit", "bandit" in gl_content)

print("\n--- DockerComposeGenerator ---")
with tempfile.TemporaryDirectory() as td:
    dc = os.path.join(td, "docker-compose.yml")
    DockerComposeGenerator.generate_compose_file(dc)
    with open(dc) as dcf:
        dc_content = dcf.read()
    test("compose: contiene read_only: true", "read_only: true" in dc_content)
    test("compose: contiene no-new-privileges", "no-new-privileges" in dc_content)
    test("compose: contiene memory limit", "memory:" in dc_content)
    test("compose: contiene mem_limit Compose v2", "mem_limit:" in dc_content)
    test("compose: documenta Swarm vs Compose", "Swarm" in dc_content)

print("\n--- HelmGenerator ---")
with tempfile.TemporaryDirectory() as td:
    helm_dir = os.path.join(td, "chart")
    HelmGenerator.generate_helm_chart(helm_dir, "test-svc", "myorg/myapp")
    test("helm: Chart.yaml existe", os.path.exists(os.path.join(helm_dir, "Chart.yaml")))
    test("helm: values.yaml existe", os.path.exists(os.path.join(helm_dir, "values.yaml")))
    test("helm: templates/deployment.yaml existe", os.path.exists(os.path.join(helm_dir, "templates", "deployment.yaml")))
    with open(os.path.join(helm_dir, "values.yaml")) as vf:
        vals = vf.read()
    test("helm: values contiene runAsNonRoot", "runAsNonRoot" in vals)
    test("helm: values contiene allowPrivilegeEscalation", "allowPrivilegeEscalation" in vals)
    with open(os.path.join(helm_dir, "templates", "deployment.yaml")) as df:
        dep = df.read()
    test("helm: deployment dropea capabilities", "capabilities" in dep)

print("\n--- YAMLValidator ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
    f.write("key: value\nlist:\n  - item1\n  - item2\n")
    good_yaml = f.name
ok_y, errs_y = YAMLValidator.validate_yaml_syntax(good_yaml)
test("yaml_validator: YAML válido sin errores", ok_y and len(errs_y) == 0)
os.unlink(good_yaml)

with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
    f.write("key:\tvalue_with_tab\n")
    bad_yaml = f.name
bad_y, bad_errs = YAMLValidator.validate_yaml_syntax(bad_yaml)
test("yaml_validator: detecta tabulaciones prohibidas", not bad_y and any("tabulacion" in e.lower() or "Tab" in e for e in bad_errs))
os.unlink(bad_yaml)

with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
    f.write('ports:\n  - "8080:8080"\nsecurity_opt:\n  - no-new-privileges:true\n')
    compose_like = f.name
ok_compose, errs_compose = YAMLValidator.validate_yaml_syntax(compose_like)
test("yaml_validator: acepta puertos y no-new-privileges", ok_compose and len(errs_compose) == 0)
os.unlink(compose_like)

test("yaml_validator: archivo inexistente", not YAMLValidator.validate_yaml_syntax("/nonexistent.yaml")[0])

# =================================================================
# Generación OpenAPI 3.0.3, manuales técnicos Markdown y Swagger UI
# =================================================================
header("AGENTE 8: DOCUMENTACIÓN AUTOMATIZADA Y OPENAPI")

print("\n--- OpenAPIGenerator ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write(
        "def get_users(limit: int = 10):\n    '''Retorna usuarios.'''\n    pass\n"
        "def post_create_user(name: str):\n    '''Crea usuario.'''\n    pass\n"
        "def put_update_item(item_id: int, title: str):\n    '''Actualiza item.'''\n    pass\n"
        "def delete_user(uid: int):\n    '''Elimina usuario.'''\n    pass\n"
    )
    api_src = f.name
spec = OpenAPIGenerator.generate_openapi_spec(api_src, "Test API", "2.0.0")
test("openapi: versión 3.0.3", spec["openapi"] == "3.0.3")
test("openapi: título correcto", spec["info"]["title"] == "Test API")
test("openapi: mapea /users (get)", "/users" in spec["paths"])
test("openapi: mapea /create_user (post)", "/create_user" in spec["paths"])
test("openapi: mapea /update_item (put)", "/update_item" in spec["paths"] and "put" in spec["paths"]["/update_item"])
test("openapi: mapea /user (delete) sin prefijo", "/user" in spec["paths"] and "delete" in spec["paths"]["/user"])
put_op = spec["paths"]["/update_item"]["put"]
test("openapi: put incluye requestBody", "requestBody" in put_op)
test("openapi: components.schemas presente", bool(spec.get("components", {}).get("schemas")))
get_op = spec["paths"]["/users"]["get"]
test("openapi: get incluye parameters", "parameters" in get_op)
test("openapi: delete incluye query uid", any(p.get("name") == "uid" for p in spec["paths"]["/user"]["delete"].get("parameters", [])))

# Validar serialización JSON íntegra preservando la versión del esquema OpenAPI.
with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
    json_out = f.name
OpenAPIGenerator.export_spec_to_json(spec, json_out)
with open(json_out) as jf:
    loaded = json.load(jf)
test("openapi_json: parsea correctamente", loaded["openapi"] == "3.0.3")
os.unlink(json_out)

# Validar exportación equivalente en formato YAML sin pérdida estructural.
with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
    yaml_out = f.name
OpenAPIGenerator.export_spec_to_yaml(spec, yaml_out)
test("openapi_yaml: genera archivo YAML", os.path.getsize(yaml_out) > 50)
os.unlink(yaml_out)
os.unlink(api_src)

print("\n--- MarkdownDocGenerator ---")
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write('"""Módulo de prueba."""\nclass MyService:\n    """Servicio principal."""\n    def run(self):\n        """Ejecuta el servicio."""\n        pass\n')
    doc_src = f.name
with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
    doc_out = f.name
MarkdownDocGenerator.generate_module_docs(doc_src, doc_out)
with open(doc_out) as df:
    doc_content = df.read()
test("md_doc: contiene título con nombre de archivo", "Documentación Técnica" in doc_content)
test("md_doc: contiene clase MyService", "MyService" in doc_content)
test("md_doc: contiene método run", "run" in doc_content)
os.unlink(doc_src)
os.unlink(doc_out)

print("\n--- SwaggerUIGenerator ---")
mini_spec = {"openapi": "3.0.3", "info": {"title": "Mini"}, "paths": {}}
with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
    swag_out = f.name
SwaggerUIGenerator.generate_swagger_ui_html(mini_spec, swag_out)
with open(swag_out) as sf:
    swag_html = sf.read()
test("swagger_ui: contiene SwaggerUIBundle", "SwaggerUIBundle" in swag_html)
test("swagger_ui: contiene CDN de swagger-ui CSS", "swagger-ui.css" in swag_html)
test("swagger_ui: contiene spec embebida", "3.0.3" in swag_html)
os.unlink(swag_out)

# =================================================================
# Comprobación funcional de los ocho puntos de entrada demostrativos
# =================================================================
header("EJECUCIÓN FUNCIONAL DE TODOS LOS main.py")

agents_main = [
    ("defensive", "Defensivo"),
    ("quality", "Calidad de Código"),
    ("hardening", "Hardening"),
    ("refactor", "Refactorización"),
    ("qa", "QA"),
    ("sre", "SRE Observabilidad"),
    ("devops", "DevOps Pipelines"),
    ("docs", "Documentación"),
]
prev_workdir = os.environ.get("AGENTES_WORKDIR")
with tempfile.TemporaryDirectory() as demo_workdir:
    if prev_workdir is None:
        os.environ["AGENTES_WORKDIR"] = demo_workdir
    try:
        for agent_pkg, label in agents_main:
            exit_code = os.system(f'cd "{AGENTS_DIR}" && "{sys.executable}" -m agentes.{agent_pkg}.main > /dev/null 2>&1')
            test(f"main.py [{label}] ejecuta sin errores (exit 0)", exit_code == 0)
    finally:
        if prev_workdir is None:
            os.environ.pop("AGENTES_WORKDIR", None)

# =================================================================
# Verificación integral del CLI unificado y subcomandos de pipeline
# =================================================================
header("CLI UNIFICADO agentes_cli.py")
cli_path = os.path.join(AGENTS_DIR, "agentes_cli.py")
cli_list = os.system(f'"{sys.executable}" {cli_path} list > /dev/null 2>&1')
test("cli: list exit 0", cli_list == 0)
cli_help = os.popen(f'"{sys.executable}" {cli_path} list').read()
test("cli: lista agentes conocidos", "defensive" in cli_help and "devops" in cli_help)

# Validar emisión de artefactos analíticos (analyze.json, pipeline.json, SARIF y HTML) sobre proyectos mínimos.
with tempfile.TemporaryDirectory() as td:
    sample = os.path.join(td, "sample.py")
    with open(sample, "w") as sf:
        sf.write("def ok():\n    return 1\n")
    out_dir = os.path.join(td, "reports")
    an_code = os.system(f'"{sys.executable}" {cli_path} analyze {sample} -o {out_dir} > /dev/null 2>&1')
    test("cli: analyze exit 0", an_code == 0)
    test("cli: analyze escribe analyze.json", os.path.exists(os.path.join(out_dir, "analyze.json")))

with tempfile.TemporaryDirectory() as td:
    sample = os.path.join(td, "app.py")
    with open(sample, "w") as sf:
        sf.write("def get_health():\n    '''ok'''\n    return {'ok': True}\n")
    out_dir = os.path.join(td, "reports")
    pipe_code = os.system(f'"{sys.executable}" {cli_path} pipeline {td} -o {out_dir} --no-fail > /dev/null 2>&1')
    test("cli: pipeline --no-fail exit 0", pipe_code == 0)
    test("cli: pipeline escribe pipeline.json", os.path.exists(os.path.join(out_dir, "pipeline.json")))
    test("cli: pipeline escribe pipeline.sarif", os.path.exists(os.path.join(out_dir, "pipeline.sarif")))
    test("cli: pipeline escribe pipeline.html", os.path.exists(os.path.join(out_dir, "pipeline.html")))

# Comprobar reglas AST extendidas de análisis estático sobre credenciales, aserciones y SQL interpolado.
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write('PASSWORD = "hardcodedsecret123"\nassert True\ncursor.execute(f"SELECT {x}")\n')
    sast2 = f.name
issues2 = StaticCodeAnalyzer.analyze_python_file(sast2, prefer_bandit=False)
test("SAST: detecta secreto hardcodeado", any("secreto" in i[2].lower() or "PASSWORD" in i[2] for i in issues2))
test("SAST: detecta assert", any("assert" in i[2].lower() for i in issues2))
test("SAST: detecta SQL f-string", any("sql" in i[2].lower() for i in issues2))
os.unlink(sast2)

# Verificar cálculo heurístico de cobertura funcional a partir de módulos y pruebas relacionadas.
with tempfile.TemporaryDirectory() as td:
    src = os.path.join(td, "modx.py")
    tst = os.path.join(td, "test_modx.py")
    with open(src, "w") as f:
        f.write("def alfa(a, b):\n    return a + b\n")
    with open(tst, "w") as f:
        f.write("import unittest\nfrom modx import *\nclass T(unittest.TestCase):\n    def test_alfa_happy_path(self):\n        self.assertEqual(alfa(2, 3), 5)\n")
    cov = QATestRunner.estimate_function_coverage(tst)
    test("qa_coverage: porcentaje presente", "coverage_percentage" in cov)
    test("qa_coverage: alfa cubierta", cov.get("functions_tested", 0) >= 1)

# Verificar extracción OpenAPI mediante decoradores de rutas tipo FastAPI y Flask.
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write('app=None\n@app.get("/items")\ndef list_items():\n    """x"""\n    return []\n')
    flask_src = f.name
spec_fw = OpenAPIGenerator.generate_openapi_spec(flask_src)
test("openapi: detecta decorator FastAPI/Flask", "/items" in spec_fw["paths"])
os.unlink(flask_src)

# Confirmar parametrización dinámica de nombre de servicio, puerto y límites de memoria en Docker Compose.
with tempfile.TemporaryDirectory() as td:
    dc2 = os.path.join(td, "docker-compose.yml")
    DockerComposeGenerator.generate_compose_file(dc2, service_name="api", port=9090, mem_limit="256m")
    with open(dc2) as f:
        c2 = f.read()
    test("compose: puerto parametrizado", "9090:9090" in c2)
    test("compose: servicio parametrizado", "api:" in c2)

# =================================================================
# Consolidado de métricas y estado global de salida de la batería
# =================================================================
header(f"RESUMEN GLOBAL DE VERIFICACIÓN EXHAUSTIVA (8 AGENTES v{AGENTES_VERSION})")
total = passed + failed
print(f"\n  Total de pruebas ejecutadas: {total}")
print(f"  Pasaron: {passed}")
print(f"  Fallaron: {failed}")
print(f"  Tasa de éxito: {(passed/total*100):.1f}%")

if errors_list:
    print("\n  Errores detectados:")
    for e in errors_list:
        print(f"    {e}")

print("")
sys.exit(0 if failed == 0 else 1)
