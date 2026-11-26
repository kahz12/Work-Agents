"""
Constantes compartidas, manejo de errores y utilidades de ruta/salida del CLI.
"""
from __future__ import annotations

import os
from contextvars import ContextVar, Token
from typing import Any, Dict, List, Optional, Sequence, Tuple, TypeVar

from ..common.console import describe_counts, ui
from ..common.findings import Finding, FindingLike, as_finding, count_by_level

T = TypeVar("T", bound=FindingLike)

AGENTS = {
    "defensive": ("agentes.defensive", "Seguridad defensiva (XSS, hashing, CSRF, RBAC)"),
    "quality": ("agentes.quality", "Calidad de código y SAST / SARIF"),
    "hardening": ("agentes.hardening", "Hardening Nginx/Caddy/Docker/K8s/systemd"),
    "refactor": ("agentes.refactor", "Métricas, SOLID y diagramas Mermaid"),
    "qa": ("agentes.qa", "Generación de tests, runner y contratos API"),
    "sre": ("agentes.sre", "Logs, anomalías, health, Prometheus, alertas"),
    "devops": ("agentes.devops", "GitHub Actions, GitLab CI, Compose, Helm"),
    "docs": ("agentes.docs", "OpenAPI, Swagger UI y docs Markdown"),
}

# Fuente única del resumen de comandos: alimenta la pantalla inicial y la ayuda de cada uno.
COMMAND_GROUPS: List[Tuple[str, List[Tuple[str, str, str]]]] = [
    ("Analizar un proyecto", [
        ("pipeline", "RUTA", "Auditoría completa: SAST, secretos, métricas, OpenAPI e infraestructura"),
        ("analyze", "RUTA", "Solo análisis estático de Python, infraestructura y dependencias"),
        ("secrets", "RUTA", "Busca claves y contraseñas en código y configuración"),
        ("vulns", "RUTA", "Vulnerabilidades conocidas en las dependencias (consulta OSV)"),
        ("audit", "RUTA|URL", "Audita un Dockerfile, YAML, .env, log, suite de tests o las cabeceras de una URL"),
        ("metrics", "RUTA", "Complejidad, SOLID, rendimiento y recomendaciones de refactor"),
    ]),
    ("Generar y corregir", [
        ("generate", "TIPO", "Genera configuraciones endurecidas, documentación, diagramas y tests"),
        ("fix", "ARCHIVO", "Fija un requirements.txt a las últimas versiones publicadas y revisa sus vulnerabilidades"),
    ]),
    ("Probar", [
        ("test", "ARCHIVO", "Ejecuta una suite unittest y evalúa su calidad y cobertura"),
        ("testability", "ARCHIVO", "Detecta qué dificulta probar un módulo y propone escenarios"),
        ("contract", "URL", "Valida estado, esquema y tiempo de respuesta de un endpoint"),
    ]),
    ("Operar", [
        ("health", "", "Comprueba disco, carga y, si lo pides, un puerto TCP o una URL"),
        ("sla", "", "Evalúa una tasa de errores frente a un umbral"),
        ("serve", "", "Servidor HTTP con /metrics (Prometheus) y /healthz"),
    ]),
    ("Utilidades", [
        ("password", "ACCIÓN", "Evalúa, cifra o verifica una contraseña"),
        ("demo", "AGENTE", "Ejecuta la demo de un agente con datos de ejemplo"),
        ("list", "", "Lista los 8 agentes"),
        ("doctor", "", "Revisa la instalación y las dependencias opcionales"),
        ("help", "[COMANDO]", "Muestra la ayuda general o la de un comando"),
    ]),
]
COMMAND_ALIASES = {"serve-sre": "serve"}
COMMAND_NAMES = [name for _, cmds in COMMAND_GROUPS for name, _, _ in cmds]

STAGE_LABELS = dict((
    ("quality_sast", "Análisis estático"),
    ("defensive_secrets", "Secretos"),
    ("refactor_metrics", "Métricas y SOLID"),
    ("documentation", "Documentación OpenAPI"),
    ("infra_and_deps", "Infraestructura y dependencias"),
    ("dependency_vulns", "Vulnerabilidades en dependencias"),
))
STATUS_LABELS = {"ok": ("OK", "green"), "fail": ("FALLO", "red"), "skipped": ("OMITIDA", "yellow")}


class CliError(Exception):
    """Error de uso: se muestra sin traza y termina con código 2."""

    def __init__(self, message: str, hint: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint


# Raíz del proyecto que analiza el comando en curso. Si un archivo queda lejos del directorio
# actual pero dentro de esa raíz, se muestra relativo a ella: src/app/x.py en vez de la ruta entera.
_DISPLAY_ROOT_VAR: ContextVar[Optional[str]] = ContextVar("agentes_display_root", default=None)


def reset_display_root() -> Token:
    """Reinicia la raíz de visualización para la invocación actual y devuelve su token."""
    return _DISPLAY_ROOT_VAR.set(None)


def restore_display_root(token: Token) -> None:
    """Restaura la raíz de visualización previa tras finalizar el comando."""
    _DISPLAY_ROOT_VAR.reset(token)


def set_display_root(full: str) -> None:
    """Establece la raíz del proyecto analizado si aún no se fijó en este contexto."""
    if _DISPLAY_ROOT_VAR.get() is None:
        _DISPLAY_ROOT_VAR.set(full if os.path.isdir(full) else os.path.dirname(full))


def rel(path: Any) -> str:
    """
    Ruta para mostrar: relativa al directorio actual si queda cerca; si no, relativa al
    proyecto analizado; si no está en ninguno de los dos, absoluta.
    """
    text = str(path)
    if not text or "://" in text:
        return text
    if not os.path.isabs(text):
        return os.path.normpath(text)
    try:
        relative = os.path.relpath(text)
    except ValueError:
        return text
    # Hasta dos niveles hacia arriba sigue siendo más legible que la ruta absoluta.
    if relative.split(os.sep).count("..") <= 2:
        return relative
    root = _DISPLAY_ROOT_VAR.get()
    if root and text != root and text.startswith(root.rstrip(os.sep) + os.sep):
        return os.path.relpath(text, root)
    return text


def require_path(path: str, kind: str = "any") -> str:
    """Valida que la ruta exista y coincida con el tipo esperado ('any', 'file' o 'dir')."""
    full = os.path.abspath(os.path.expanduser(path))
    if os.path.exists(full):
        set_display_root(full)
    if not os.path.exists(full):
        raise CliError(
            f"No existe la ruta: {path}",
            "Revisa que esté bien escrita. Las rutas son relativas al directorio actual.",
        )
    if kind == "file" and not os.path.isfile(full):
        raise CliError(f"Se esperaba un archivo y '{path}' es un directorio.")
    if kind == "dir" and not os.path.isdir(full):
        raise CliError(f"Se esperaba un directorio y '{path}' es un archivo.")
    return full


def require_python_file(path: str) -> str:
    """Valida que la ruta corresponda a un archivo .py existente."""
    full = require_path(path, "file")
    if not full.endswith(".py"):
        raise CliError(f"Se esperaba un archivo .py: {path}")
    return full


def visible(findings: Sequence[FindingLike]) -> List[Finding]:
    """Copia para mostrar: rutas relativas y sin entradas puramente informativas."""
    shown = []
    for item in findings:
        f = as_finding(item)
        if not f.silent:
            shown.append(Finding(rel(f.file), f.line, f.level, f.message, f.rule_id))
    return shown


def dicts(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Convierte una lista de Finding en diccionarios serializables, con su categoría."""
    from ..common.rules import annotate

    return annotate([f.to_dict() for f in findings])


def emit_json(data: Any) -> None:
    """Serializa e imprime una estructura en formato JSON legible."""
    import json

    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))


def show_findings(findings: Sequence[FindingLike], limit: int, empty: str = "Sin hallazgos.", *,
                  security_checked: bool = False) -> None:
    """
    Muestra los hallazgos visibles en consola, separados en seguridad y calidad del código para
    que un riesgo de seguridad no quede entre docstrings que faltan, o un mensaje de éxito si no
    hay ninguno. El límite se aplica a cada sección. security_checked indica que el comando
    busca problemas de seguridad: si no encontró ninguno, se dice de forma explícita.
    """
    from ..common.rules import CATEGORY_LABELS, QUALITY, SECURITY, category

    shown = visible(findings)
    if not shown:
        ui.ok(empty)
        return
    groups = {SECURITY: [f for f in shown if category(f) == SECURITY], QUALITY: [f for f in shown if category(f) == QUALITY]}
    if security_checked and not groups[SECURITY]:
        ui.out()
        ui.ok("Ningún hallazgo de seguridad.")
    for key in (SECURITY, QUALITY):
        group = groups[key]
        if group:
            ui.section(f"{CATEGORY_LABELS[key]} ({len(group)}): {describe_counts(count_by_level(group))}")
            ui.findings(group, limit=limit)


def drop_inline(findings: List[T]) -> Tuple[List[T], int]:
    """Quita los hallazgos silenciados en su línea. Devuelve (los demás, cuántos se quitaron)."""
    from ..common.suppressions import InlineSuppressions

    inline = InlineSuppressions()
    kept = inline.filter(findings)
    return kept, inline.suppressed


def show_inline_note(count: int) -> None:
    """Avisa de cuántos hallazgos se silenciaron en su línea: callarlos no debe pasar desapercibido."""
    if count:
        ui.hint(f"{count} hallazgos silenciados en su línea (# agentes: ignore, noqa o nosec) no se muestran.")


def guard_overwrite(path: str, force: bool) -> None:
    """Evita sobrescribir un archivo existente salvo que se indique --force."""
    if os.path.exists(path) and not force:
        raise CliError(
            f"Ya existe {rel(path)} y no se ha sobrescrito.",
            "Añade --force para reemplazarlo o usa -o para elegir otra ruta.",
        )


def ensure_parent(path: str) -> None:
    """Crea el directorio padre de la ruta de salida si aún no existe."""
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)


def python_files(target: str) -> List[str]:
    """Lista los archivos Python bajo el archivo o directorio objetivo."""
    from ..common.orchestrator import _iter_python_files

    return _iter_python_files(target)
