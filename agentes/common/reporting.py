"""
Reportes unificados del ecosistema AGENTES (JSON / HTML / SARIF).
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
    "CRITICO": "error",
    "ALTO": "error",
    "MEDIO": "warning",
    "BAJO": "note",
    "ERROR": "error",
    "OK": "none",
}

_SAST_SARIF_RULES: Tuple[Tuple[str, re.Pattern[str], str], ...] = (
    ("SAST-EVAL", re.compile(r"\beval\(\)|\bexec\(\)|riesgo din[aá]mico|possibly insecure function", re.I),
     "Uso de ejecución dinámica peligrosa (eval/exec)."),
    ("SAST-PICKLE", re.compile(r"pickle", re.I),
     "Deserialización insegura con pickle."),
    ("SAST-SHELL", re.compile(r"shell=True|Command Injection|start a process with a shell|subprocess call", re.I),
     "Ejecución de comandos con riesgo de inyección de shell."),
    ("SAST-SQLI", re.compile(r"SQL injection|sql_injection", re.I),
     "Construcción dinámica de consultas SQL (SQL Injection)."),
    ("SAST-YAML", re.compile(r"yaml\.load", re.I),
     "Carga de YAML sin SafeLoader."),
    ("SAST-WEAK-HASH", re.compile(r"\b(?:md5|sha1)\b|hash criptogr[aá]fico d[eé]bil", re.I),
     "Uso de función hash criptográfica débil (MD5/SHA-1)."),
    ("SAST-BARE-EXCEPT", re.compile(r"except:'\s*(?:gen[eé]rico|desnuda)", re.I),
     "Cláusula except genérica sin tipo especificado."),
    ("SAST-BROAD-EXCEPT", re.compile(r"Uso de 'except Exception:'", re.I),
     "Captura amplia de Exception sin acotar el tipo."),
    ("SAST-EXCEPT-PASS", re.compile(r"Try, Except, (?:Pass|Continue)|silencia", re.I),
     "Excepción capturada y silenciada sin manejo."),
    ("SAST-TOCTOU", re.compile(r"\bTOCTOU\b", re.I),
     "Posible condición de carrera entre comprobación y apertura (TOCTOU)."),
    ("SAST-HARDCODED-SECRET", re.compile(r"secreto hardcodeado|hardcoded password", re.I),
     "Posible credencial o secreto incrustado en código."),
    ("SAST-BLOCKING-ASYNC", re.compile(r"bloqueante dentro de funci[oó]n 'async def'", re.I),
     "Llamada síncrona bloqueante dentro de una corrutina async."),
    ("SAST-URLOPEN-TIMEOUT", re.compile(r"urlopen\(\)' sin 'timeout'", re.I),
     "Llamada a urlopen() sin timeout explícito."),
    ("SAST-UNMANAGED-OPEN", re.compile(r"open\(\)' fuera de un context manager", re.I),
     "Apertura de archivo con open() fuera de un context manager."),
    ("SAST-MUTABLE-DEFAULT", re.compile(r"argumento por defecto mutable", re.I),
     "Uso de argumento por defecto mutable en función."),
    ("SAST-TLS-VERIFY", re.compile(r"verify=False|Verificaci[oó]n TLS desactivada", re.I),
     "Verificación de certificados TLS desactivada."),
    ("SAST-ASSERT", re.compile(r"\bassert\b", re.I),
     "Uso de assert en código de producción."),
    ("SAST-DOCSTRING", re.compile(r"carece de docstring", re.I),
     "Función o método público sin docstring explicativo."),
)

_SECRET_SARIF_RULES: Tuple[Tuple[str, re.Pattern[str], str], ...] = (
    ("SECRET-AWS", re.compile(r"de AWS\b|\bAKIA\b|\bASIA\b", re.I),
     "Clave o credencial de AWS expuesta."),
    ("SECRET-GITHUB", re.compile(r"Token de GitHub", re.I),
     "Token de acceso de GitHub expuesto."),
    ("SECRET-SLACK", re.compile(r"de Slack\b", re.I),
     "Token o webhook de Slack expuesto."),
    ("SECRET-STRIPE", re.compile(r"de Stripe\b", re.I),
     "Clave de API de Stripe expuesta."),
    ("SECRET-GOOGLE", re.compile(r"de Google\b", re.I),
     "Clave de API de Google expuesta."),
    ("SECRET-ANTHROPIC", re.compile(r"de Anthropic\b", re.I),
     "Clave de API de Anthropic expuesta."),
    ("SECRET-OPENAI", re.compile(r"de OpenAI\b", re.I),
     "Clave de API de OpenAI expuesta."),
    ("SECRET-SENDGRID", re.compile(r"de SendGrid\b", re.I),
     "Clave de API de SendGrid expuesta."),
    ("SECRET-NPM", re.compile(r"Token de npm\b", re.I),
     "Token de acceso de npm expuesto."),
    ("SECRET-PYPI", re.compile(r"Token de PyPI\b", re.I),
     "Token de acceso de PyPI expuesto."),
    ("SECRET-GITLAB", re.compile(r"Token de GitLab\b", re.I),
     "Token de acceso de GitLab expuesto."),
    ("SECRET-PRIVATE-KEY", re.compile(r"Clave privada incrustada", re.I),
     "Clave privada PEM/SSH incrustada."),
    ("SECRET-JWT", re.compile(r"JSON Web Token|\bJWT\b", re.I),
     "JSON Web Token (JWT) incrustado."),
    ("SECRET-URL-CREDENTIALS", re.compile(r"Credencial dentro de una URL", re.I),
     "Credenciales embebidas en una URL de conexión."),
    ("SECRET-AUTH-HEADER", re.compile(r"cabecera Authorization", re.I),
     "Credencial codificada en cabecera Authorization."),
)

_SARIF_RULE_DESCRIPTIONS: Dict[str, str] = dict((
    *((rule_id, desc) for rule_id, _, desc in _SAST_SARIF_RULES),
    *((rule_id, desc) for rule_id, _, desc in _SECRET_SARIF_RULES),
    ("SECRET-GENERIC", "Posible secreto incrustado detectado por nombre de clave."),
    ("DOCKERFILE", "Problema de seguridad o buenas prácticas en Dockerfile."),
    ("SYSTEMD", "Directiva de endurecimiento faltante o débil en unidad systemd."),
    ("K8S-POD", "Falta endurecimiento SecurityContext en Pod de Kubernetes."),
    ("K8S-WORKLOAD", "Falta endurecimiento SecurityContext en workload de Kubernetes."),
    ("DEPS-PIP", "Dependencia Python sin fijar o con especificación insegura."),
    ("DEPS-NPM", "Dependencia npm sin versión exacta o con configuración de riesgo."),
    ("ENV", "Configuración sensible o de depuración insegura en archivo .env."),
    ("LOG", "Anomalía, error crítico o dato sensible detectado en logs."),
    ("PERF", "Patrón de rendimiento subóptimo (Big-O, memoria o I/O)."),
    ("YAML", "Error de sintaxis o formato en archivo YAML."),
))


def _sarif_rule_id(item: Dict[str, Any]) -> str:
    """
    ruleId del SARIF. Los hallazgos SAST y SECRET, que llevan un rule_id amplio, reciben uno
    concreto deducido del mensaje (SAST-SHELL, SECRET-AWS); el resto conserva su rule_id.
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
    return raw_rule or f"RULE-{item.get('level', 'MEDIO')}"


# GitHub Code Scanning clasifica como alerta de seguridad la regla con la etiqueta "security" y
# toma su gravedad de security-severity: 9,0 o más es crítica, desde 7,0 alta, desde 4,0 media.
_SECURITY_SEVERITY = {"CRITICO": "9.5", "ERROR": "8.0", "ALTO": "8.0", "MEDIO": "5.5", "BAJO": "2.0"}


def _sarif_rule_meta(rule_id: str, level: str, item: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    from .rules import SECURITY, category

    desc = _SARIF_RULE_DESCRIPTIONS.get(rule_id, f"Hallazgo reportado por la regla {rule_id}.")
    meta: Dict[str, Any] = {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": desc},
        "defaultConfiguration": {"level": level},
    }
    if item is not None:
        if category(item) == SECURITY:
            meta["properties"] = {"tags": ["security"]}
            severity = _SECURITY_SEVERITY.get(str(item.get("level", "MEDIO")).upper())
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
    """Devuelve una ruta relativa legible (separadores '/') cuando es posible."""
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
    findings: [{file, line, level, message, rule_id?}, ...]
    """
    results = []
    rules_by_id: Dict[str, Dict[str, Any]] = {}
    for item in findings:
        level = SEVERITY_SARIF.get(str(item.get("level", "MEDIO")).upper(), "warning")
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
    """Escapa un valor para insertarlo en HTML (los hallazgos vienen de código ajeno)."""
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
            lvl_color = "#dc2626" if lvl in ("CRITICO", "ALTO", "ERROR") else ("#ca8a04" if lvl == "MEDIO" else "#94a3b8")
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
            f"<h2>Hallazgos ({len(findings)})</h2>"
            "<table><thead><tr><th>Archivo</th><th>Línea</th><th>Nivel</th><th>Tipo</th><th>Regla</th><th>Mensaje</th></tr></thead>"
            f"<tbody>{''.join(f_rows)}</tbody></table>"
        )

    document = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"/>
<title>AGENTES Pipeline Report</title>
<style>
body{{font-family:ui-sans-serif,system-ui,sans-serif;margin:2rem;background:#0f172a;color:#e2e8f0}}
h1,h2{{color:#38bdf8}} h2{{margin-top:2rem;font-size:1.2rem}}
table{{border-collapse:collapse;width:100%;margin-top:1rem}}
th,td{{border:1px solid #334155;padding:.6rem;text-align:left}} th{{background:#1e293b}}
.meta{{color:#94a3b8;font-size:.9rem}}
</style></head><body>
<h1>Pipeline AGENTES</h1>
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
