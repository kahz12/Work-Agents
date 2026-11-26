"""
Construcción del analizador de argumentos del CLI y mensajes de error en español.
"""
from __future__ import annotations

import argparse
import re
from typing import Any, Callable, Dict, Optional, Tuple

from .. import __version__
from ..common.console import ui
from .analyze import (
    AUDIT_TYPES,
    cmd_analyze,
    cmd_audit,
    cmd_metrics,
    cmd_pipeline,
    cmd_secrets,
    cmd_vulns,
)
from .common import AGENTS, COMMAND_GROUPS
from .generate import GENERATORS, cmd_fix, cmd_generate
from .ops import (
    cmd_demo,
    cmd_doctor,
    cmd_health,
    cmd_list,
    cmd_password,
    cmd_serve,
    cmd_sla,
)
from .testing import cmd_contract, cmd_test, cmd_testability

_ARGPARSE_TRANSLATIONS = [
    (r"the following arguments are required: (.+)", r"Faltan argumentos obligatorios: \1"),
    (r"unrecognized arguments: (.+)", r"Argumentos no reconocidos: \1"),
    (r"argument (.+?): invalid choice: (.+?) \(choose from (.+)\)", r"Valor no válido \2 para \1. Opciones: \3"),
    (r"argument (.+?): expected one argument", r"La opción \1 necesita un valor."),
    (r"argument (.+?): expected at least one argument", r"La opción \1 necesita al menos un valor."),
    (r"argument (.+?): invalid int value: (.+)", r"\1 espera un número entero y recibió \2."),
    (r"argument (.+?): invalid float value: (.+)", r"\1 espera un número y recibió \2."),
    (r"argument (.+?): not allowed with argument (.+)", r"\1 no se puede combinar con \2."),
]


def _translate(message: str) -> str:
    for pattern, replacement in _ARGPARSE_TRANSLATIONS:
        if re.search(pattern, message):
            return re.sub(pattern, replacement, message)
    return message


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    def add_usage(self, usage: Any, actions: Any, groups: Any, prefix: Optional[str] = None) -> None:
        super().add_usage(usage, actions, groups, prefix if prefix is not None else "Uso: ")


class AgentesParser(argparse.ArgumentParser):
    """ArgumentParser con ayuda y errores en español."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("formatter_class", _HelpFormatter)
        kwargs["add_help"] = False
        super().__init__(*args, **kwargs)
        self._positionals.title = "Argumentos"
        self._optionals.title = "Opciones"
        self.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS, help="Muestra esta ayuda.")

    def error(self, message: str) -> None:  # type: ignore[override]
        ui.error(_translate(message), f"Consulta la ayuda con: {self.prog} -h")
        raise SystemExit(2)


def _examples(*lines: str) -> str:
    return "Ejemplos:\n" + "\n".join(f"  {line}" for line in lines)


def _add_output_flags(
    parser: argparse.ArgumentParser,
    *,
    as_json: bool = True,
    limit: bool = False,
    offline: bool = False,
) -> None:
    if as_json:
        parser.add_argument("--json", action="store_true", help="Salida en JSON, para scripts.")
    if limit:
        parser.add_argument(
            "--limit", type=int, default=20, metavar="N",
            help="Máximo de elementos a listar (0 = todos). Por defecto, 20.",
        )
    if offline:
        parser.add_argument(
            "--offline", action="store_true",
            help="No hace consultas de red (OSV, PyPI). Equivale a AGENTES_OFFLINE=1.",
        )
    parser.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS, help="Desactiva el color.")


_SubAdder = Callable[..., argparse.ArgumentParser]


def _register_analyze(add: _SubAdder) -> None:
    p = add("pipeline", cmd_pipeline, _examples(
        "agentes pipeline .", "agentes pipeline ./mi_proyecto -o ./reports", "agentes pipeline . --no-bandit --max-files 500",
        "agentes pipeline . --write-baseline .agentes-baseline.json   acepta lo que hay hoy",
        "agentes pipeline . --baseline .agentes-baseline.json         falla solo con hallazgos nuevos",
    ))
    p.add_argument("path", metavar="RUTA", help="Archivo o directorio a auditar.")
    p.add_argument("-o", "--output", metavar="DIR", help="Directorio de informes. Por defecto, reports/ dentro de RUTA.")
    p.add_argument("--no-fail", action="store_true", help="No devuelve error por hallazgos altos o críticos. Los secretos siguen fallando.")
    p.add_argument("--max-files", type=int, default=None, metavar="N", help="Límite de archivos .py. Por defecto, todos.")
    p.add_argument("--no-bandit", action="store_true", help="Usa solo el motor AST, más rápido en proyectos grandes.")
    p.add_argument(
        "--baseline", metavar="ARCHIVO",
        help="Línea base de hallazgos aceptados: no cuentan para el resultado. Solo fallan los nuevos.",
    )
    p.add_argument(
        "--write-baseline", metavar="ARCHIVO",
        help="Guarda los hallazgos altos, críticos y secretos actuales como línea base y termina con 0.",
    )
    _add_output_flags(p, limit=True, offline=True)

    p = add("analyze", cmd_analyze, _examples("agentes analyze ./src", "agentes analyze app.py -o ./reports --fail-on-high"))
    p.add_argument("path", metavar="RUTA", help="Archivo o directorio.")
    p.add_argument("-o", "--output", metavar="DIR", help="Directorio de informes.")
    p.add_argument("--fail-on-high", action="store_true", help="Devuelve 1 si hay hallazgos altos o críticos.")
    p.add_argument("--no-bandit", action="store_true", help="Usa solo el motor AST.")
    _add_output_flags(p, limit=True, offline=True)

    p = add("secrets", cmd_secrets, _examples("agentes secrets .", "agentes secrets .env", "agentes secrets ./config --json"))
    p.add_argument("path", metavar="RUTA", help="Archivo o directorio.")
    _add_output_flags(p, limit=True)

    p = add("vulns", cmd_vulns, _examples(
        "agentes vulns .", "agentes vulns requirements.txt", "agentes vulns package-lock.json --json",
        "",
        "Lee requirements*.txt, package.json, package-lock.json, poetry.lock y Pipfile.lock. Solo se",
        "comprueban las dependencias con versión exacta. Envía a api.osv.dev el nombre y la versión",
        "de cada una, nada más.",
    ))
    p.add_argument("path", metavar="RUTA", help="Directorio o manifiesto de dependencias.")
    _add_output_flags(p, limit=True, offline=True)

    p = add("audit", cmd_audit, _examples(
        "agentes audit Dockerfile", "agentes audit .env", "agentes audit app.log", "agentes audit tests/test_api.py",
        "agentes audit https://example.com", "agentes audit ./infra", "agentes audit mi.conf --type systemd",
    ))
    p.add_argument("target", metavar="RUTA|URL", help="Archivo, directorio o URL http(s).")
    p.add_argument(
        "--type", choices=AUDIT_TYPES, default="auto",
        help="Tipo de auditoría. Por defecto se deduce del nombre del archivo.",
    )
    _add_output_flags(p, limit=True)

    p = add("metrics", cmd_metrics, _examples("agentes metrics ./src", "agentes metrics app.py --limit 0"))
    p.add_argument("path", metavar="RUTA", help="Archivo .py o directorio.")
    _add_output_flags(p, limit=True)


def _register_generate(add: _SubAdder) -> None:
    p = add("generate", cmd_generate, _examples(
        "agentes generate                      lista los tipos disponibles",
        "agentes generate compose --service api --port 8000",
        "agentes generate helm -o ./chart --service api --image myorg/api:1.2.0",
        "agentes generate nginx --domain midominio.com",
        "agentes generate openapi --source app.py -o openapi.yaml",
        "agentes generate tests --source app.py --framework pytest",
        "agentes generate tests --source app.py --record",
        "agentes generate diagram --source modelos.py",
    ))
    p.add_argument(
        "kind", nargs="?", choices=list(GENERATORS), metavar="TIPO",
        help="Qué generar: " + ", ".join(GENERATORS) + ". Sin TIPO, lista los disponibles.",
    )
    p.add_argument("-o", "--output", metavar="SALIDA", help="Archivo o directorio de salida. Cada tipo tiene uno por defecto.")
    p.add_argument("--force", action="store_true", help="Sobrescribe la salida si ya existe.")
    p.add_argument("--source", metavar="ARCHIVO", help="Fuente Python (openapi, swagger, docs, diagram y tests).")
    p.add_argument("--service", default="web", metavar="NOMBRE", help="Nombre del servicio, del chart o título de la API. Por defecto, web.")
    p.add_argument("--image", default="myorg/myapp:1.0.0", help="Imagen de contenedor. Por defecto, myorg/myapp:1.0.0.")
    p.add_argument("--port", type=int, default=8080, help="Puerto del servicio. Por defecto, 8080.")
    p.add_argument("--mem-limit", default="512m", help="Límite de memoria (compose). Por defecto, 512m.")
    p.add_argument("--cpus", default="0.50", help="Límite de CPU (compose). Por defecto, 0.50.")
    p.add_argument("--domain", default="example.com", help="Dominio (nginx y caddy). Por defecto, example.com.")
    p.add_argument("--csp", metavar="POLÍTICA", help="Content-Security-Policy (nginx y caddy).")
    p.add_argument("--framework", choices=["unittest", "pytest"], default="unittest", help="Framework de los tests. Por defecto, unittest.")
    p.add_argument(
        "--naming-convention", action="store_true",
        help="openapi y swagger: trata también como rutas las funciones get_/post_/put_/delete_. "
             "Por defecto solo cuentan los decoradores de Flask y FastAPI.",
    )
    p.add_argument(
        "--record", action="store_true",
        help="Solo tests: ejecuta el módulo y graba lo que devuelve cada función (tests de caracterización). "
             "Se omiten las funciones con E/S o resultados no deterministas.",
    )
    _add_output_flags(p, as_json=False)

    p = add("fix", cmd_fix, _examples(
        "agentes fix requirements.txt --dry-run", "agentes fix requirements.txt",
        "",
        "Cada paquete sin versión, o con >=, ~= o >, se fija a la versión más reciente publicada en",
        "PyPI que cumple lo declarado. Lo que no se puede resolver se deja como está y se explica.",
        "Después se consultan en OSV las vulnerabilidades de las versiones resultantes.",
    ))
    p.add_argument("path", metavar="ARCHIVO", help="Ruta al requirements.txt.")
    p.add_argument("--dry-run", action="store_true", help="Muestra los cambios sin modificar el archivo.")
    # Opciones obsoletas, ocultas en la ayuda: se aceptan para no romper scripts que las pasen,
    # pero no tienen efecto. fix siempre consulta PyPI y nunca fija una versión inventada;
    # con --default-version, cmd_fix avisa de que se ignora.
    p.add_argument("--pypi", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--default-version", default=None, help=argparse.SUPPRESS)
    _add_output_flags(p, limit=True, offline=True)


def _register_testing(add: _SubAdder) -> None:
    p = add("test", cmd_test, _examples("agentes test tests/test_app.py", "agentes test test_app.py --verbose"))
    p.add_argument("path", metavar="ARCHIVO", help="Archivo de tests unittest.")
    p.add_argument("-v", "--verbose", action="store_true", help="Muestra las trazas completas de los fallos.")
    _add_output_flags(p, limit=True)

    p = add("testability", cmd_testability, _examples("agentes testability app.py", "agentes testability app.py --matrix"))
    p.add_argument("path", metavar="ARCHIVO", help="Módulo Python a revisar.")
    p.add_argument("--matrix", action="store_true", help="Incluye la matriz de escenarios de prueba sugeridos.")
    _add_output_flags(p, limit=True)

    p = add("contract", cmd_contract, _examples(
        "agentes contract https://api.example.com/health",
        "agentes contract https://api.example.com/users/1 --schema usuario.json --max-ms 300",
        "agentes contract https://api.example.com/users --method POST --body '{\"name\": \"Ana\"}' --status 201",
        "",
        "El esquema es un JSON con el tipo de cada campo:",
        '  {"id": "int", "name": "str", "tags": ["str"], "owner": {"email": "str"}}',
    ))
    p.add_argument("url", metavar="URL", help="Endpoint http(s) a comprobar.")
    p.add_argument("--method", default="GET", help="Método HTTP. Por defecto, GET.")
    p.add_argument("--status", type=int, default=200, metavar="CÓDIGO", help="Código de estado esperado. Por defecto, 200.")
    p.add_argument("--schema", metavar="ARCHIVO", help="JSON con los tipos esperados en la respuesta.")
    p.add_argument("--strict", action="store_true", help="Rechaza campos que no estén en el esquema.")
    p.add_argument("--max-ms", type=float, default=500.0, metavar="MS", help="Tiempo máximo de respuesta. Por defecto, 500 ms.")
    p.add_argument("--timeout", type=float, default=5.0, metavar="S", help="Tiempo de espera de la conexión. Por defecto, 5 s.")
    p.add_argument("--header", action="append", metavar="'Nombre: valor'", help="Cabecera a enviar. Se puede repetir.")
    p.add_argument("--body", metavar="JSON", help="Cuerpo de la petición.")
    _add_output_flags(p)


def _register_ops(add: _SubAdder) -> None:
    p = add("health", cmd_health, _examples(
        "agentes health", "agentes health --tcp localhost:5432 --http https://example.com/healthz",
    ))
    p.add_argument("--disk", default="/", metavar="RUTA", help="Ruta cuyo disco se comprueba. Por defecto, /.")
    p.add_argument("--min-free-mb", type=float, default=100.0, metavar="MB", help="Espacio libre mínimo. Por defecto, 100 MB.")
    p.add_argument("--tcp", metavar="HOST:PUERTO", help="Comprueba que un puerto TCP acepta conexiones.")
    p.add_argument("--http", metavar="URL", help="Comprueba que una URL responde.")
    p.add_argument("--expect-status", type=int, default=200, metavar="CÓDIGO", help="Estado HTTP esperado. Por defecto, 200.")
    _add_output_flags(p)

    p = add("sla", cmd_sla, _examples("agentes sla --total 12000 --errors 340", "agentes sla --total 500 --errors 3 --max-rate 1"))
    p.add_argument("--total", type=int, required=True, metavar="N", help="Peticiones totales.")
    p.add_argument("--errors", type=int, required=True, metavar="N", help="Peticiones con error.")
    p.add_argument("--max-rate", type=float, default=5.0, metavar="PCT", help="Tasa de errores máxima en %%. Por defecto, 5.")
    _add_output_flags(p)

    p = add("serve", cmd_serve, _examples("agentes serve", "agentes serve --host 0.0.0.0 --port 9100"), aliases=("serve-sre",))
    p.add_argument("--host", default="127.0.0.1", help="Interfaz de escucha. Por defecto, 127.0.0.1.")
    p.add_argument("--port", type=int, default=9100, help="Puerto. Por defecto, 9100.")
    _add_output_flags(p, as_json=False)


def _register_utils(add: _SubAdder) -> None:
    p = add("password", cmd_password, _examples(
        "agentes password check", "agentes password hash", "agentes password verify 'argon2:$argon2id$...'",
        "echo 'mi clave' | agentes password check --stdin",
        "",
        "La contraseña se pide de forma interactiva para que no quede en el historial del shell.",
        "check y hash consultan Have I Been Pwned por k-anonimato: solo se envían los 5 primeros",
        "caracteres del hash SHA-1, nunca la contraseña. --offline lo desactiva.",
    ))
    p.add_argument(
        "action", choices=["check", "hash", "verify"], metavar="ACCIÓN",
        help="check: evalúa la fortaleza. hash: genera el hash. verify: la compara con un hash.",
    )
    p.add_argument("hash", nargs="?", metavar="HASH", help="Hash a comprobar (solo con verify). Ponlo entre comillas simples.")
    p.add_argument("--stdin", action="store_true", help="Lee la contraseña de la entrada estándar.")
    _add_output_flags(p, offline=True)

    p = add("demo", cmd_demo, _examples("agentes demo qa", "agentes demo all"))
    p.add_argument("agent", metavar="AGENTE", help=" | ".join(AGENTS) + " | all")
    _add_output_flags(p, as_json=False)

    p = add("list", cmd_list)
    _add_output_flags(p, as_json=False)

    p = add("doctor", cmd_doctor)
    _add_output_flags(p)

    p = add("help", lambda a: 0)
    p.add_argument("topic", nargs="?", metavar="COMANDO", help="Comando del que mostrar la ayuda.")


def build_parser() -> argparse.ArgumentParser:
    """Construye y devuelve el parser principal del CLI con todos sus subcomandos."""
    parser = AgentesParser(prog="agentes", description=f"CLI DevSecOps AGENTES v{__version__}")
    summaries: Dict[str, str] = {name: desc for _, cmds in COMMAND_GROUPS for name, _, desc in cmds}
    sub = parser.add_subparsers(dest="command", metavar="<comando>", title="Comandos")

    def add(
        name: str,
        func: Callable[[argparse.Namespace], int],
        epilog: str = "",
        aliases: Tuple[str, ...] = (),
    ) -> argparse.ArgumentParser:
        p = sub.add_parser(
            name, help=summaries[name], description=summaries[name] + ".",
            epilog=epilog, aliases=list(aliases),
        )
        p.set_defaults(func=func)
        return p

    _register_analyze(add)
    _register_generate(add)
    _register_testing(add)
    _register_ops(add)
    _register_utils(add)

    # Opciones globales: `agentes --list` equivale a `agentes list`.
    parser.add_argument("--list", "-l", action="store_true", help="Lista los agentes (equivale a 'list').")
    parser.add_argument("--version", "-V", action="version", version=f"agentes {__version__}", help="Muestra la versión.")
    parser.add_argument("--no-color", action="store_true", default=False, help="Desactiva el color.")
    return parser
