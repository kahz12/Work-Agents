"""
Single-target audits that return Finding objects.

This is the only layer that knows the tuple shape each auditor returns. The orchestrator and
the CLI call these functions instead of adapting every auditor's output themselves.
"""
from __future__ import annotations

import os
import re
from typing import Callable, Dict, Iterable, List, Optional

from .findings import SILENT_LEVELS, Finding, normalize_level, severity_rank

# File kinds audit_file understands, in the order they are listed to the user.
AUDIT_KINDS = ["docker", "systemd", "deps", "yaml", "env", "logs", "tests"]
INFRA_KINDS = frozenset({"docker", "systemd", "deps", "yaml"})


def _keep(level: object) -> bool:
    return normalize_level(level) not in SILENT_LEVELS


def _line_from_message(msg: str, default: int = 0) -> int:
    match = re.search(r"Line\s+(\d+)", msg, re.IGNORECASE)
    return int(match.group(1)) if match else default


def detect_kind(path: str) -> Optional[str]:
    """Infer the audit kind from the file name. None when the name is not recognised."""
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


# --- Infrastructure ------------------------------------------------------

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
    """YAML syntax and, for Pod-bearing Kubernetes manifests, the security context."""
    from ..devops.yaml_validator import YAMLValidator
    from ..hardening.k8s_hardening import K8sHardening

    docs, errors = YAMLValidator.load_documents(path)
    if docs is None:
        return [Finding(path, _line_from_message(err), "HIGH", err, "YAML") for err in errors]
    findings: List[Finding] = []
    for doc in docs:
        if isinstance(doc, dict) and doc.get("kind") in K8sHardening.WORKLOAD_KINDS:
            rule_id = "K8S-POD" if doc.get("kind") == "Pod" else "K8S-WORKLOAD"
            for elem, level, msg in K8sHardening.audit_pod_security_context(doc):
                if _keep(level):
                    findings.append(Finding(path, 0, level, f"[{elem}] {msg}", rule_id))
    return findings


# --- Configuration, logs and tests ---------------------------------------

_TEMPLATE_HINTS = ("example", "sample", "template", "dist", "tpl", "defaults")


def is_env_template(path: str) -> bool:
    """`.env.example`, `.env.sample`, `example.env`...: templates that document variables rather than set them."""
    name = os.path.basename(path).lower()
    return any(hint in name for hint in _TEMPLATE_HINTS)


def audit_env(path: str) -> List[Finding]:
    """
    Insecure settings in a .env file. The file is parsed without exporting anything.

    In a template, sample values (empty or "changeme") are exactly what should be there, so
    only debug switches that are on by default are reported, as LOW. Real secrets left in a
    template are caught by the `secrets` scan instead.
    """
    from ..defensive.config_manager import ConfigManager

    config = ConfigManager.parse_env_file(path)
    findings = [Finding(path, 0, level, f"[{key}] {msg}", "ENV")
                for key, level, msg in ConfigManager.audit_config_dict(config) if _keep(level)]
    if not is_env_template(path):
        return findings
    debug_keys = ("[DEBUG]", "[TESTING]")
    return [Finding(f.file, f.line, "LOW", f.message + " In a template, prefer it disabled by default.", f.rule_id)
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
    """Audit one file. Without kind, it is inferred from the name; ValueError when that fails."""
    kind = kind or detect_kind(path)
    if kind not in _AUDITORS:
        raise ValueError(f"Unrecognised audit kind for {path}: {kind!r}")
    return _AUDITORS[kind](path)


# --- Python code: calibration and merging --------------------------------
#
# Bandit, our AST engine and the SOLID auditor can all report the same problem on the same
# line: an `except Exception: pass` is caught by all three, two of them as HIGH. Findings are
# grouped here by topic and collapsed into one, with a severity calibrated for that topic.
# The patterns match the messages written by quality.static_checker, refactor.solid_checker,
# refactor.code_metrics and Bandit; rewording one of those messages means updating this table.

_TOPICS = [
    ("exception-swallow", re.compile(r"Try, Except, (Pass|Continue)|silences|silently returns None", re.I)),
    ("broad-except", re.compile(r"Use of 'except Exception:'|except Exception\b.*specific", re.I)),
    ("bare-except", re.compile(r"bare 'except:'", re.I)),
    ("mutable-default", re.compile(r"mutable\s+default\s+(?:argument|parameter)", re.I)),
    ("blocking-async", re.compile(r"blocking.*async\s+def|async\s+def.*event\s+loop", re.I)),
    ("weak-hash", re.compile(r"\b(md5|sha1)\b|weak cryptographic hash", re.I)),
    ("dynamic-exec", re.compile(r"\beval\b|\bexec\b", re.I)),
    ("shell", re.compile(r"shell=True|shell injection|start a process with a shell", re.I)),
    ("pickle", re.compile(r"pickle", re.I)),
    ("yaml-load", re.compile(r"yaml\.load|yaml load", re.I)),
    ("assert", re.compile(r"\bassert\b", re.I)),
    ("sql", re.compile(r"\bsql\b", re.I)),
]

# Severity per topic, for topics where the engines' own severity overstates the real risk.
CALIBRATED_LEVELS = {
    # Swallowing exceptions is a reliability problem, not a security one.
    "exception-swallow": "MEDIUM",
    # MD5 and SHA-1 are widely used for caching, deduplication and checksums, none of which
    # are security uses.
    "weak-hash": "MEDIUM",
    "assert": "LOW",
}
_ADVICE = {
    "weak-hash": " If it protects nothing (caching, deduplication, checksums), pass usedforsecurity=False.",
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
    """Apply the topic's calibrated severity and advice, when the topic has them."""
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
    Collapse findings that share file, line and topic into one. The AST engine's message is
    kept (it is the most explanatory) and the other engines that reported it are listed.
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
        # Message: the AST engine's if present, otherwise the first one. Severity: the worst
        # in the group, then calibrated for the topic.
        main = next((f for f in group if _engine(f) == "AST"), group[0])
        worst = min(group, key=lambda f: severity_rank(f.level)).level
        others = sorted({_engine(f) for f in group if f is not main} - {_engine(main)})
        note = f" Also detected by: {', '.join(others)}." if others else ""
        merged.append(calibrate(Finding(main.file, main.line, worst, main.message + note, main.rule_id)))
    return merged


def drop_covered(items: List[Dict], reference: List[Dict]) -> List[Dict]:
    """Drop from items the findings whose file, line and topic are already in reference."""
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
    """Static security analysis of Python files, with duplicates across engines merged."""
    from ..quality.static_checker import StaticCodeAnalyzer

    paths = list(files)
    batch = StaticCodeAnalyzer.analyze_python_files(paths, prefer_bandit=prefer_bandit)
    findings: List[Finding] = []
    for path in paths:
        for line, level, msg in batch.get(path, []):
            findings.append(Finding(path, line, level, msg, f"SAST-{normalize_level(level)}"))
    return merge_duplicates(findings)


def scan_secrets(path: str) -> List[Finding]:
    """Secrets in one file. An unreadable file yields an ERROR finding, never an empty list."""
    from ..defensive.config_manager import ConfigManager

    findings: List[Finding] = []
    try:
        hits = ConfigManager.scan_file_for_secrets(path)
    except Exception as exc:  # noqa: BLE001 - a file we could not read must never be reported as clean
        return [Finding(path, 0, "ERROR", f"Could not scan for secrets: {exc}", "SECRET-SCAN-ERROR")]
    for line, desc, snippet in hits:
        if line == 0:
            findings.append(Finding(path, 0, "ERROR", f"Could not scan for secrets: {snippet}",
                                    "SECRET-SCAN-ERROR"))
        else:
            findings.append(Finding(path, line, "HIGH", f"{desc}: {str(snippet).strip()}", "SECRET"))
    return findings
