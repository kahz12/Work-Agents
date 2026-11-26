"""
Auditorías unitarias que devuelven Finding.

Es la única capa que conoce la forma de tupla de cada auditor. El orquestador y el CLI
usan estas funciones en lugar de adaptar cada resultado por su cuenta.
"""
from __future__ import annotations

import os
import re
from typing import Callable, Dict, Iterable, List, Optional

from .findings import SILENT_LEVELS, Finding, normalize_level, severity_rank

# Tipos de archivo que sabe auditar audit_file, en el orden en que se muestran.
AUDIT_KINDS = ["docker", "systemd", "deps", "yaml", "env", "logs", "tests"]
INFRA_KINDS = frozenset({"docker", "systemd", "deps", "yaml"})


def _keep(level: object) -> bool:
    return normalize_level(level) not in SILENT_LEVELS


def _line_from_message(msg: str, default: int = 0) -> int:
    match = re.search(r"L[ií]nea\s+(\d+)", msg, re.IGNORECASE)
    return int(match.group(1)) if match else default


def detect_kind(path: str) -> Optional[str]:
    """Deduce el tipo de auditoría por el nombre del archivo. None si no lo reconoce."""
    fn = os.path.basename(path)
    low = fn.lower()
    if fn == "Dockerfile" or fn.startswith("Dockerfile.") or low.endswith(".dockerfile"):
        return "docker"
    if low.endswith(".service"):
        return "systemd"
    if (low.startswith("requirements") and low.endswith(".txt")) or fn == "package.json":
        return "deps"
    if low.endswith((".yml", ".yaml")):
        return "yaml"
    if fn == ".env" or fn.startswith(".env.") or low.endswith(".env"):
        return "env"
    if low.endswith(".log"):
        return "logs"
    if low.endswith(".py") and (low.startswith("test_") or low.endswith("_test.py")):
        return "tests"
    return None


# --- Infraestructura ------------------------------------------------------

def audit_dockerfile(path: str) -> List[Finding]:
    from ..hardening.container_hardening import ContainerHardening
    return [Finding(path, line, level, msg, "DOCKERFILE")
            for line, level, msg in ContainerHardening.audit_dockerfile(path) if _keep(level)]


def audit_systemd(path: str) -> List[Finding]:
    from ..hardening.service_hardening import ServiceHardening
    return [Finding(path, 0, level, f"[{directive}] {msg}", "SYSTEMD")
            for directive, level, msg in ServiceHardening.audit_systemd_service(path) if _keep(level)]


def audit_dependencies(path: str) -> List[Finding]:
    from ..quality.dependency_auditor import DependencyAuditor
    if os.path.basename(path) == "package.json":
        return [Finding(path, 0, level, f"[{pkg}] {msg}", "DEPS-NPM")
                for pkg, level, msg in DependencyAuditor.audit_package_json(path) if _keep(level)]
    return [Finding(path, _line_from_message(msg), level, f"[{pkg}] {msg}", "DEPS-PIP")
            for pkg, level, msg in DependencyAuditor.audit_requirements_txt(path) if _keep(level)]


def audit_yaml(path: str) -> List[Finding]:
    """Sintaxis YAML y, en manifiestos de Pod, el contexto de seguridad."""
    from ..devops.yaml_validator import YAMLValidator
    from ..hardening.k8s_hardening import K8sHardening

    docs, errors = YAMLValidator.load_documents(path)
    if docs is None:
        return [Finding(path, _line_from_message(err), "ALTO", err, "YAML") for err in errors]
    findings: List[Finding] = []
    for doc in docs:
        if isinstance(doc, dict) and doc.get("kind") in K8sHardening.WORKLOAD_KINDS:
            rule_id = "K8S-POD" if doc.get("kind") == "Pod" else "K8S-WORKLOAD"
            for elem, level, msg in K8sHardening.audit_pod_security_context(doc):
                if _keep(level):
                    findings.append(Finding(path, 0, level, f"[{elem}] {msg}", rule_id))
    return findings


# --- Configuración, logs y tests ------------------------------------------

_TEMPLATE_HINTS = ("example", "sample", "template", "dist", "tpl", "defaults")


def is_env_template(path: str) -> bool:
    """`.env.example`, `.env.sample`, `example.env`...: plantillas que documentan variables, no las definen."""
    name = os.path.basename(path).lower()
    return any(hint in name for hint in _TEMPLATE_HINTS)


def audit_env(path: str) -> List[Finding]:
    """
    Opciones inseguras de un .env. Lee el archivo sin exportar nada al entorno.

    En una plantilla los valores de ejemplo (vacíos o "changeme") son lo correcto: solo se
    informa, como BAJO, de las opciones de depuración activadas por defecto. Los secretos
    reales que alguien deje en una plantilla los detecta `secrets`.
    """
    from ..defensive.config_manager import ConfigManager

    config = ConfigManager.parse_env_file(path)
    findings = [Finding(path, 0, level, f"[{key}] {msg}", "ENV")
                for key, level, msg in ConfigManager.audit_config_dict(config) if _keep(level)]
    if not is_env_template(path):
        return findings
    debug_keys = ("[DEBUG]", "[TESTING]")
    return [Finding(f.file, f.line, "BAJO", f.message + " En una plantilla, mejor desactivada por defecto.", f.rule_id)
            for f in findings if f.message.upper().startswith(debug_keys)]


def audit_log(path: str) -> List[Finding]:
    from ..sre.log_anomaly_auditor import LogAnomalyAuditor
    return [Finding(path, line, sev, f"{desc} {snippet}".strip(), "LOG")
            for line, sev, desc, snippet in LogAnomalyAuditor.audit_log_file(path) if _keep(sev)]


def audit_test_suite(path: str) -> List[Finding]:
    from ..qa.test_runner import QATestRunner
    quality = QATestRunner.audit_test_suite_quality(path)
    if quality.get("error"):
        return [Finding(path, 0, "ERROR", quality["error"], "TEST-QUALITY")]
    return [Finding(path, line, level, f"[{rule}] {msg}", "TEST-QUALITY")
            for line, rule, level, msg in quality.get("findings", []) if _keep(level)]


def audit_http_headers(url: str, headers: Dict[str, str]) -> List[Finding]:
    from ..hardening.webserver_hardening import WebServerHardening
    return [Finding(url, 0, level, f"[{name}] {msg}", "HTTP-HEADERS")
            for name, level, msg in WebServerHardening.audit_http_headers(headers) if _keep(level)]


_AUDITORS: Dict[str, Callable[[str], List[Finding]]] = {
    "docker": audit_dockerfile,
    "systemd": audit_systemd,
    "deps": audit_dependencies,
    "yaml": audit_yaml,
    "env": audit_env,
    "logs": audit_log,
    "tests": audit_test_suite,
}


def audit_file(path: str, kind: Optional[str] = None) -> List[Finding]:
    """Audita un archivo. Sin kind, lo deduce del nombre; ValueError si no puede."""
    kind = kind or detect_kind(path)
    if kind not in _AUDITORS:
        raise ValueError(f"Tipo de auditoría no reconocido para {path}: {kind!r}")
    return _AUDITORS[kind](path)


# --- Código Python --------------------------------------------------------

# --- Calibración y fusión ------------------------------------------------------
#
# Bandit, el motor AST propio y el auditor SOLID pueden señalar lo mismo en la misma línea: un
# `except Exception: pass` lo detectan los tres, y dos de ellos como ALTO. Aquí se agrupan por
# tema y se deja un único hallazgo, con una severidad calibrada para ese tema.

_TOPICS = [
    ("exception-swallow", re.compile(r"Try, Except, (Pass|Continue)|silencia|Captura amplia retorna None", re.I)),
    ("broad-except", re.compile(r"Uso de 'except Exception:'|except Exception\b.*concretas", re.I)),
    ("bare-except", re.compile(r"except:'\s*(?:gen[eé]rico|desnuda)", re.I)),
    ("mutable-default", re.compile(r"(?:argumento|par[aá]metro)\s+por\s+defecto\s+mutable", re.I)),
    ("blocking-async", re.compile(r"bloqueante.*async\s+def|async\s+def.*event\s+loop|congela\s+el\s+Event\s+Loop", re.I)),
    ("weak-hash", re.compile(r"\b(md5|sha1)\b|hash criptogr[aá]fico d[eé]bil", re.I)),
    ("dynamic-exec", re.compile(r"\beval\b|\bexec\b", re.I)),
    ("shell", re.compile(r"shell=True|shell injection|start a process with a shell", re.I)),
    ("pickle", re.compile(r"pickle", re.I)),
    ("yaml-load", re.compile(r"yaml\.load|yaml load", re.I)),
    ("assert", re.compile(r"\bassert\b", re.I)),
    ("sql", re.compile(r"\bsql\b", re.I)),
]

# Severidad por tema cuando la de los motores no refleja el riesgo real.
CALIBRATED_LEVELS = {
    # Silenciar excepciones es un problema de fiabilidad, no de seguridad.
    "exception-swallow": "MEDIO",
    # MD5 y SHA-1 se usan mucho para caché, deduplicar o checksums, que no son usos de seguridad.
    "weak-hash": "MEDIO",
    "assert": "BAJO",
}
_ADVICE = {
    "weak-hash": " Si no protege nada (caché, deduplicar, checksums), pásale usedforsecurity=False.",
}


def topic(finding: Finding) -> Optional[str]:
    for name, pattern in _TOPICS:
        if pattern.search(finding.message):
            return name
    return None


def _engine(finding: Finding) -> str:
    if finding.message.startswith("[bandit]"):
        return "bandit"
    if finding.rule_id.startswith("SOLID-"):
        return "SOLID"
    return "AST"


def _relabel(finding: Finding, level: str) -> Finding:
    rule = f"SAST-{level}" if finding.rule_id.startswith("SAST-") else finding.rule_id
    return Finding(finding.file, finding.line, level, finding.message, rule)


def calibrate(finding: Finding) -> Finding:
    """Aplica la severidad del tema, si la tiene, y su recomendación."""
    name = topic(finding)
    if name not in CALIBRATED_LEVELS:
        return finding
    calibrated = _relabel(finding, CALIBRATED_LEVELS[name])
    advice = _ADVICE.get(name, "")
    if advice and advice.strip() not in calibrated.message:
        calibrated.message += advice
    return calibrated


def merge_duplicates(findings: List[Finding]) -> List[Finding]:
    """
    Funde los hallazgos del mismo archivo, línea y tema en uno. Se conserva el mensaje del
    motor propio (más explicativo) y se indica qué otros motores lo detectaron.
    """
    groups: Dict[tuple, List[Finding]] = {}
    order: List[tuple] = []
    for f in findings:
        name = topic(f)
        key = (f.file, f.line, name) if name and f.line else (id(f),)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)
    merged: List[Finding] = []
    for key in order:
        group = groups[key]
        if len(group) == 1:
            merged.append(calibrate(group[0]))
            continue
        # Mensaje: el del motor AST si lo hay, si no el primero. Severidad: la más grave, luego calibrada.
        main = next((f for f in group if _engine(f) == "AST"), group[0])
        worst = min(group, key=lambda f: severity_rank(f.level)).level
        others = sorted({_engine(f) for f in group if f is not main} - {_engine(main)})
        note = f" Detectado también por: {', '.join(others)}." if others else ""
        merged.append(calibrate(Finding(main.file, main.line, worst, main.message + note, main.rule_id)))
    return merged


def drop_covered(items: List[Dict], reference: List[Dict]) -> List[Dict]:
    """Quita de items los hallazgos cuyo archivo, línea y tema ya están en reference."""
    covered = set()
    for ref in reference:
        f = Finding.from_dict(ref)
        name = topic(f)
        if name and f.line:
            covered.add((f.file, f.line, name))
    kept = []
    for item in items:
        f = Finding.from_dict(item)
        if (f.file, f.line, topic(f)) in covered:
            continue
        kept.append(calibrate(f).to_dict())
    return kept


def sast(files: Iterable[str], *, prefer_bandit: bool = True) -> List[Finding]:
    """Análisis estático de seguridad sobre archivos Python, sin duplicados entre motores."""
    from ..quality.static_checker import StaticCodeAnalyzer

    paths = list(files)
    batch = StaticCodeAnalyzer.analyze_python_files(paths, prefer_bandit=prefer_bandit)
    findings: List[Finding] = []
    for path in paths:
        for line, level, msg in batch.get(path, []):
            findings.append(Finding(path, line, level, msg, f"SAST-{normalize_level(level)}"))
    return merge_duplicates(findings)


def scan_secrets(path: str) -> List[Finding]:
    """Secretos en un archivo. Un archivo ilegible genera un hallazgo ERROR, no una lista vacía."""
    from ..defensive.config_manager import ConfigManager

    findings: List[Finding] = []
    try:
        hits = ConfigManager.scan_file_for_secrets(path)
    except Exception as exc:  # noqa: BLE001 - nunca dar por limpio un archivo que no se pudo leer
        return [Finding(path, 0, "ERROR", f"No se pudo escanear en busca de secretos: {exc}", "SECRET-SCAN-ERROR")]
    for line, desc, snippet in hits:
        if line == 0:
            findings.append(Finding(path, 0, "ERROR", f"No se pudo escanear en busca de secretos: {snippet}",
                                    "SECRET-SCAN-ERROR"))
        else:
            findings.append(Finding(path, line, "ALTO", f"{desc}: {str(snippet).strip()}", "SECRET"))
    return findings
