"""
Report writers shared by every agent: JSON, HTML summary and SARIF 2.1.0.
"""
from __future__ import annotations

import html
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .. import __version__

SEVERITY_SARIF = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "ERROR": "error",
    "OK": "none",
}

# The pipeline reports static-analysis and secret findings under coarse rule_ids (SAST-HIGH,
# SECRET). SARIF consumers group alerts by ruleId, so each finding is given a specific rule
# derived from its message. The patterns match the messages written by
# quality.static_checker, defensive.config_manager and Bandit; the first match wins.
_SAST_SARIF_RULES: Tuple[Tuple[str, re.Pattern[str], str], ...] = (
    ("SAST-EVAL", re.compile(r"\beval\(\)|\bexec\(\)|dynamic code execution|possibly insecure function", re.I),
     "Dangerous dynamic code execution (eval/exec)."),
    ("SAST-PICKLE", re.compile(r"pickle", re.I),
     "Unsafe deserialisation with pickle."),
    ("SAST-SHELL", re.compile(r"shell=True|command injection|start a process with a shell|subprocess call", re.I),
     "Command execution at risk of shell injection."),
    ("SAST-SQLI", re.compile(r"SQL injection|sql_injection", re.I),
     "SQL query built dynamically (SQL injection)."),
    ("SAST-YAML", re.compile(r"yaml\.load", re.I),
     "YAML loaded without SafeLoader."),
    ("SAST-WEAK-HASH", re.compile(r"\b(?:md5|sha1)\b|weak cryptographic hash", re.I),
     "Weak cryptographic hash function (MD5/SHA-1)."),
    ("SAST-BARE-EXCEPT", re.compile(r"bare 'except:'", re.I),
     "Bare except clause with no exception type."),
    ("SAST-BROAD-EXCEPT", re.compile(r"Use of 'except Exception:'", re.I),
     "Broad catch of Exception without narrowing the type."),
    ("SAST-EXCEPT-PASS", re.compile(r"Try, Except, (?:Pass|Continue)|silences", re.I),
     "Exception caught and silently discarded."),
    ("SAST-TOCTOU", re.compile(r"\bTOCTOU\b", re.I),
     "Possible race between an existence check and opening the file (TOCTOU)."),
    ("SAST-HARDCODED-SECRET", re.compile(r"hardcoded secret|hardcoded password", re.I),
     "Possible credential or secret embedded in code."),
    ("SAST-BLOCKING-ASYNC", re.compile(r"Blocking synchronous call inside an 'async def' function", re.I),
     "Blocking synchronous call inside an async coroutine."),
    ("SAST-URLOPEN-TIMEOUT", re.compile(r"urlopen\(\)' without an explicit 'timeout'", re.I),
     "Call to urlopen() without an explicit timeout."),
    ("SAST-UNMANAGED-OPEN", re.compile(r"open\(\)' outside a 'with' context manager", re.I),
     "File opened with open() outside a context manager."),
    ("SAST-MUTABLE-DEFAULT", re.compile(r"mutable default argument", re.I),
     "Function with a mutable default argument."),
    ("SAST-TLS-VERIFY", re.compile(r"verify=False|TLS verification disabled", re.I),
     "TLS certificate verification disabled."),
    ("SAST-ASSERT", re.compile(r"\bassert\b", re.I),
     "Use of assert in production code."),
    ("SAST-DOCSTRING", re.compile(r"has no docstring", re.I),
     "Public function or method without a docstring."),
)

_SECRET_SARIF_RULES: Tuple[Tuple[str, re.Pattern[str], str], ...] = (
    ("SECRET-AWS", re.compile(r"\bAWS (?:temporary )?(?:access|secret) key|\bAKIA\b|\bASIA\b", re.I),
     "Exposed AWS key or credential."),
    ("SECRET-GITHUB", re.compile(r"GitHub token", re.I),
     "Exposed GitHub access token."),
    ("SECRET-SLACK", re.compile(r"Slack (?:token|webhook)", re.I),
     "Exposed Slack token or webhook."),
    ("SECRET-STRIPE", re.compile(r"Stripe API key", re.I),
     "Exposed Stripe API key."),
    ("SECRET-GOOGLE", re.compile(r"Google API key", re.I),
     "Exposed Google API key."),
    ("SECRET-ANTHROPIC", re.compile(r"Anthropic API key", re.I),
     "Exposed Anthropic API key."),
    ("SECRET-OPENAI", re.compile(r"OpenAI API key", re.I),
     "Exposed OpenAI API key."),
    ("SECRET-SENDGRID", re.compile(r"SendGrid API key", re.I),
     "Exposed SendGrid API key."),
    ("SECRET-NPM", re.compile(r"\bnpm token", re.I),
     "Exposed npm access token."),
    ("SECRET-PYPI", re.compile(r"PyPI token", re.I),
     "Exposed PyPI access token."),
    ("SECRET-GITLAB", re.compile(r"GitLab token", re.I),
     "Exposed GitLab access token."),
    ("SECRET-PRIVATE-KEY", re.compile(r"Embedded private key", re.I),
     "Embedded PEM/SSH private key."),
    ("SECRET-JWT", re.compile(r"JSON Web Token|\bJWT\b", re.I),
     "Embedded JSON Web Token (JWT)."),
    ("SECRET-URL-CREDENTIALS", re.compile(r"Credential inside a connection URL", re.I),
     "Credentials embedded in a connection URL."),
    ("SECRET-AUTH-HEADER", re.compile(r"Authorization header", re.I),
     "Credential hardcoded in an Authorization header."),
)

_SARIF_RULE_DESCRIPTIONS: Dict[str, str] = dict((
    *((rule_id, desc) for rule_id, _, desc in _SAST_SARIF_RULES),
    *((rule_id, desc) for rule_id, _, desc in _SECRET_SARIF_RULES),
    ("SECRET-GENERIC", "Possible embedded secret, detected by its key name."),
    ("DOCKERFILE", "Security or best-practice issue in a Dockerfile."),
    ("SYSTEMD", "Missing or weak hardening directive in a systemd unit."),
    ("K8S-POD", "Missing securityContext hardening in a Kubernetes Pod."),
    ("K8S-WORKLOAD", "Missing securityContext hardening in a Kubernetes workload."),
    ("DEPS-PIP", "Python dependency that is unpinned or loosely specified."),
    ("DEPS-NPM", "npm dependency without an exact version or with a risky setting."),
    ("ENV", "Sensitive value or insecure debug setting in a .env file."),
    ("LOG", "Anomaly, critical error or sensitive data found in a log."),
    ("PERF", "Suboptimal performance pattern (Big-O, memory or I/O)."),
    ("YAML", "Syntax or format error in a YAML file."),
))


def _sarif_rule_id(item: Dict[str, Any]) -> str:
    """
    SARIF ruleId of a finding. SAST and SECRET findings, which carry a coarse rule_id, get a
    specific one derived from the message (SAST-SHELL, SECRET-AWS); every other finding keeps
    its own rule_id.
    """
    raw_rule = str(item.get("rule_id") or "")
    msg = str(item.get("message") or "")
    if raw_rule == "SECRET":
        for rule_id, pat, _ in _SECRET_SARIF_RULES:
            if pat.search(msg):
                return rule_id
        return "SECRET-GENERIC"
    if not raw_rule or raw_rule.startswith(("SAST-", "RULE-")):
        for rule_id, pat, _ in _SAST_SARIF_RULES:
            if pat.search(msg):
                return rule_id
    return raw_rule or f"RULE-{item.get('level', 'MEDIUM')}"


# GitHub Code Scanning treats a rule tagged "security" as a security alert and reads its
# severity from security-severity: 9.0 or above is critical, from 7.0 high, from 4.0 medium.
_SECURITY_SEVERITY = {"CRITICAL": "9.5", "ERROR": "8.0", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "2.0"}


def _sarif_rule_meta(rule_id: str, level: str, item: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    from .rules import SECURITY, category

    desc = _SARIF_RULE_DESCRIPTIONS.get(rule_id, f"Finding reported by rule {rule_id}.")
    meta: Dict[str, Any] = {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": desc},
        "defaultConfiguration": {"level": level},
    }
    if item is not None:
        if category(item) == SECURITY:
            meta["properties"] = {"tags": ["security"]}
            severity = _SECURITY_SEVERITY.get(str(item.get("level", "MEDIUM")).upper())
            if severity:
                meta["properties"]["security-severity"] = severity
        else:
            meta["properties"] = {"tags": ["maintainability"]}
    return meta


def ensure_reports_dir(base: str = ".") -> str:
    path = os.path.join(os.path.abspath(base), "reports")
    os.makedirs(path, exist_ok=True)
    return path


def write_json_report(data: Dict[str, Any], output_path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return output_path


def _format_finding_uri(raw_file: Any, base_dir: Optional[str] = None) -> str:
    """A readable path, relative to base_dir and with '/' separators whenever possible."""
    raw = str(raw_file or "unknown")
    if base_dir is not None and os.path.isabs(raw):
        rel = os.path.relpath(raw, os.path.abspath(base_dir))
        if rel != ".." and not rel.startswith(".." + os.sep):
            return rel.replace(os.sep, "/")
        return os.path.basename(raw)
    if os.path.isabs(raw):
        return os.path.basename(raw)
    return raw.replace(os.sep, "/")


def findings_to_sarif(
    tool_name: str,
    findings: List[Dict[str, Any]],
    output_path: str,
    *,
    base_dir: Optional[str] = None,
) -> str:
    """
    Write findings as a SARIF 2.1.0 log and return output_path.

    findings: [{file, line, level, message, rule_id?}, ...]. Absolute paths are made relative
    to base_dir so the log stays portable between machines.
    """
    results = []
    rules_by_id: Dict[str, Dict[str, Any]] = {}
    for item in findings:
        level = SEVERITY_SARIF.get(str(item.get("level", "MEDIUM")).upper(), "warning")
        uri = _format_finding_uri(item.get("file", "unknown"), base_dir=base_dir)
        rule_id = _sarif_rule_id(item)
        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = _sarif_rule_meta(rule_id, level, item)
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": item.get("message", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": int(item.get("line") or 1)},
                }
            }],
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": __version__,
                    "informationUri": "https://github.com/kahz12/Work-Agents",
                    "rules": list(rules_by_id.values()),
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }],
        }],
    }
    return write_json_report(sarif, output_path)


def _esc(value: Any) -> str:
    """Escape a value for HTML. Findings quote third-party code, so nothing is trusted."""
    return html.escape(str(value), quote=True)


def write_html_summary(report: Dict[str, Any], output_path: str) -> str:
    stages = report.get("stages", [])
    rows = []
    for stage in stages:
        status = str(stage.get("status", "?"))
        color = "#16a34a" if status == "ok" else ("#dc2626" if status == "fail" else "#ca8a04")
        rows.append(
            f"<tr><td>{_esc(stage.get('name'))}</td>"
            f"<td style='color:{color};font-weight:600'>{_esc(status)}</td>"
            f"<td>{_esc(stage.get('summary', ''))}</td>"
            f"<td>{_esc(stage.get('findings_count', 0))}</td></tr>"
        )

    findings = report.get("findings") or []
    target = report.get("target")
    base_dir: Optional[str] = None
    if target:
        target_str = str(target)
        base_dir = os.path.dirname(target_str) if os.path.isfile(target_str) else target_str

    findings_section = ""
    if findings:
        from .rules import CATEGORY_LABELS, category

        f_rows = []
        for item in findings:
            lvl = str(item.get("level", "")).upper()
            lvl_color = "#dc2626" if lvl in ("CRITICAL", "HIGH", "ERROR") else ("#ca8a04" if lvl == "MEDIUM" else "#94a3b8")
            file_disp = _format_finding_uri(item.get("file", "unknown"), base_dir=base_dir)
            f_rows.append(
                f"<tr><td>{_esc(file_disp)}</td>"
                f"<td>{_esc(item.get('line', 0))}</td>"
                f"<td style='color:{lvl_color};font-weight:600'>{_esc(lvl)}</td>"
                f"<td>{_esc(CATEGORY_LABELS.get(category(item), ''))}</td>"
                f"<td>{_esc(item.get('rule_id', ''))}</td>"
                f"<td>{_esc(item.get('message', ''))}</td></tr>"
            )
        findings_section = (
            f"<h2>Findings ({len(findings)})</h2>"
            "<table><thead><tr><th>File</th><th>Line</th><th>Level</th><th>Category</th><th>Rule</th>"
            "<th>Message</th></tr></thead>"
            f"<tbody>{''.join(f_rows)}</tbody></table>"
        )

    document = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<title>AGENTES Pipeline Report</title>
<style>
body{{font-family:ui-sans-serif,system-ui,sans-serif;margin:2rem;background:#0f172a;color:#e2e8f0}}
h1,h2{{color:#38bdf8}} h2{{margin-top:2rem;font-size:1.2rem}}
table{{border-collapse:collapse;width:100%;margin-top:1rem}}
th,td{{border:1px solid #334155;padding:.6rem;text-align:left}} th{{background:#1e293b}}
.meta{{color:#94a3b8;font-size:.9rem}}
</style></head><body>
<h1>AGENTES pipeline</h1>
<p class="meta">Target: {_esc(report.get('target',''))} · {_esc(report.get('timestamp',''))} · status={_esc(report.get('status'))}</p>
<table><thead><tr><th>Stage</th><th>Status</th><th>Summary</th><th>Findings</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
{findings_section}
</body></html>
"""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(document)
    return output_path


def build_pipeline_report(
    target: str,
    stages: List[Dict[str, Any]],
    *,
    exit_code: int = 0,
) -> Dict[str, Any]:
    status = "ok" if exit_code == 0 else "fail"
    return {
        "schema": "agentes.pipeline.v1",
        "target": os.path.abspath(target),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": status,
        "exit_code": exit_code,
        "stages": stages,
    }
