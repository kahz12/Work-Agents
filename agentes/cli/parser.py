"""
Argument parser for the CLI: every subcommand, its options and its usage examples.
"""
from __future__ import annotations

import argparse
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


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Keeps the hand-wrapped examples in each epilog exactly as written."""

    def add_usage(self, usage: Any, actions: Any, groups: Any, prefix: Optional[str] = None) -> None:
        super().add_usage(usage, actions, groups, prefix if prefix is not None else "Usage: ")


class AgentesParser(argparse.ArgumentParser):
    """
    ArgumentParser whose errors go through the shared console: a single "Error:" line on
    stderr plus a hint pointing at the command's help, then exit code 2.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("formatter_class", _HelpFormatter)
        kwargs["add_help"] = False
        super().__init__(*args, **kwargs)
        self._positionals.title = "Arguments"
        self._optionals.title = "Options"
        self.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS, help="Show this help and exit.")

    def error(self, message: str) -> None:  # type: ignore[override]
        ui.error(message[:1].upper() + message[1:], f"See the help with: {self.prog} -h")
        raise SystemExit(2)


def _examples(*lines: str) -> str:
    return "Examples:\n" + "\n".join(f"  {line}" for line in lines)


def _add_output_flags(
    parser: argparse.ArgumentParser,
    *,
    as_json: bool = True,
    limit: bool = False,
    offline: bool = False,
) -> None:
    if as_json:
        parser.add_argument("--json", action="store_true", help="Print JSON, for scripts.")
    if limit:
        parser.add_argument(
            "--limit", type=int, default=20, metavar="N",
            help="Maximum number of items to list (0 = all). Default: 20.",
        )
    if offline:
        parser.add_argument(
            "--offline", action="store_true",
            help="Make no network lookups (OSV, PyPI). Same as AGENTES_OFFLINE=1.",
        )
    parser.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS, help="Disable colour output.")


_SubAdder = Callable[..., argparse.ArgumentParser]


def _register_analyze(add: _SubAdder) -> None:
    p = add("pipeline", cmd_pipeline, _examples(
        "agentes pipeline .", "agentes pipeline ./my_project -o ./reports", "agentes pipeline . --no-bandit --max-files 500",
        "agentes pipeline . --write-baseline .agentes-baseline.json   accept everything found today",
        "agentes pipeline . --baseline .agentes-baseline.json         fail only on new findings",
    ))
    p.add_argument("path", metavar="PATH", help="File or directory to audit.")
    p.add_argument("-o", "--output", metavar="DIR", help="Report directory. Default: reports/ inside PATH.")
    p.add_argument("--no-fail", action="store_true", help="Do not fail on high or critical findings. Secrets still fail.")
    p.add_argument("--max-files", type=int, default=None, metavar="N", help="Maximum number of .py files. Default: all.")
    p.add_argument("--no-bandit", action="store_true", help="Use the AST engine only; faster on large projects.")
    p.add_argument(
        "--baseline", metavar="FILE",
        help="Baseline of accepted findings: they do not affect the result. Only new findings fail.",
    )
    p.add_argument(
        "--write-baseline", metavar="FILE",
        help="Save the current high, critical and secret findings as a baseline and exit with 0.",
    )
    _add_output_flags(p, limit=True, offline=True)

    p = add("analyze", cmd_analyze, _examples("agentes analyze ./src", "agentes analyze app.py -o ./reports --fail-on-high"))
    p.add_argument("path", metavar="PATH", help="File or directory.")
    p.add_argument("-o", "--output", metavar="DIR", help="Report directory.")
    p.add_argument("--fail-on-high", action="store_true", help="Exit with 1 when there are high or critical findings.")
    p.add_argument("--no-bandit", action="store_true", help="Use the AST engine only.")
    _add_output_flags(p, limit=True, offline=True)

    p = add("secrets", cmd_secrets, _examples("agentes secrets .", "agentes secrets .env", "agentes secrets ./config --json"))
    p.add_argument("path", metavar="PATH", help="File or directory.")
    _add_output_flags(p, limit=True)

    p = add("vulns", cmd_vulns, _examples(
        "agentes vulns .", "agentes vulns requirements.txt", "agentes vulns package-lock.json --json",
        "",
        "Reads requirements*.txt, package.json, package-lock.json, poetry.lock and Pipfile.lock. Only",
        "dependencies with an exact version are checked. Each one's name and version are sent to",
        "api.osv.dev, and nothing else.",
    ))
    p.add_argument("path", metavar="PATH", help="Directory or dependency manifest.")
    _add_output_flags(p, limit=True, offline=True)

    p = add("audit", cmd_audit, _examples(
        "agentes audit Dockerfile", "agentes audit .env", "agentes audit app.log", "agentes audit tests/test_api.py",
        "agentes audit https://example.com", "agentes audit ./infra", "agentes audit my.conf --type systemd",
    ))
    p.add_argument("target", metavar="PATH|URL", help="File, directory or http(s) URL.")
    p.add_argument(
        "--type", choices=AUDIT_TYPES, default="auto",
        help="Audit kind. By default it is inferred from the file name.",
    )
    _add_output_flags(p, limit=True)

    p = add("metrics", cmd_metrics, _examples("agentes metrics ./src", "agentes metrics app.py --limit 0"))
    p.add_argument("path", metavar="PATH", help=".py file or directory.")
    _add_output_flags(p, limit=True)


def _register_generate(add: _SubAdder) -> None:
    p = add("generate", cmd_generate, _examples(
        "agentes generate                      list the available kinds",
        "agentes generate compose --service api --port 8000",
        "agentes generate helm -o ./chart --service api --image myorg/api:1.2.0",
        "agentes generate nginx --domain mydomain.com",
        "agentes generate openapi --source app.py -o openapi.yaml",
        "agentes generate tests --source app.py --framework pytest",
        "agentes generate tests --source app.py --record",
        "agentes generate diagram --source models.py",
    ))
    p.add_argument(
        "kind", nargs="?", choices=list(GENERATORS), metavar="KIND",
        help="What to generate: " + ", ".join(GENERATORS) + ". Without KIND, the available kinds are listed.",
    )
    p.add_argument("-o", "--output", metavar="OUTPUT", help="Output file or directory. Each kind has its own default.")
    p.add_argument("--force", action="store_true", help="Overwrite the output if it already exists.")
    p.add_argument("--source", metavar="FILE", help="Python source (openapi, swagger, docs, diagram and tests).")
    p.add_argument("--service", default="web", metavar="NAME", help="Service name, chart name or API title. Default: web.")
    p.add_argument("--image", default="myorg/myapp:1.0.0", help="Container image. Default: myorg/myapp:1.0.0.")
    p.add_argument("--port", type=int, default=8080, help="Service port. Default: 8080.")
    p.add_argument("--mem-limit", default="512m", help="Memory limit (compose). Default: 512m.")
    p.add_argument("--cpus", default="0.50", help="CPU limit (compose). Default: 0.50.")
    p.add_argument("--domain", default="example.com", help="Domain (nginx and caddy). Default: example.com.")
    p.add_argument("--csp", metavar="POLICY", help="Content-Security-Policy (nginx and caddy).")
    p.add_argument("--framework", choices=["unittest", "pytest"], default="unittest", help="Test framework. Default: unittest.")
    p.add_argument(
        "--naming-convention", action="store_true",
        help="openapi and swagger: also treat get_/post_/put_/delete_ functions as routes. "
             "By default only Flask and FastAPI decorators count.",
    )
    p.add_argument(
        "--record", action="store_true",
        help="tests only: run the module and record what each function returns (characterisation tests). "
             "Functions with I/O or non-deterministic results are skipped.",
    )
    _add_output_flags(p, as_json=False)

    p = add("fix", cmd_fix, _examples(
        "agentes fix requirements.txt --dry-run", "agentes fix requirements.txt",
        "",
        "Every package without a version, or with >=, ~= or >, is pinned to the newest version on",
        "PyPI that satisfies its declaration. Anything that cannot be resolved is left untouched",
        "and explained. The resulting versions are then checked against OSV.",
    ))
    p.add_argument("path", metavar="FILE", help="Path to the requirements.txt.")
    p.add_argument("--dry-run", action="store_true", help="Show the changes without modifying the file.")
    # Deprecated options, hidden from the help. They are still accepted so scripts that pass
    # them keep working, but they have no effect: fix always queries PyPI and never pins a
    # made-up version. cmd_fix warns when --default-version is given.
    p.add_argument("--pypi", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--default-version", default=None, help=argparse.SUPPRESS)
    _add_output_flags(p, limit=True, offline=True)


def _register_testing(add: _SubAdder) -> None:
    p = add("test", cmd_test, _examples("agentes test tests/test_app.py", "agentes test test_app.py --verbose"))
    p.add_argument("path", metavar="FILE", help="unittest test file.")
    p.add_argument("-v", "--verbose", action="store_true", help="Show full tracebacks for failures.")
    _add_output_flags(p, limit=True)

    p = add("testability", cmd_testability, _examples("agentes testability app.py", "agentes testability app.py --matrix"))
    p.add_argument("path", metavar="FILE", help="Python module to review.")
    p.add_argument("--matrix", action="store_true", help="Include the matrix of suggested test scenarios.")
    _add_output_flags(p, limit=True)

    p = add("contract", cmd_contract, _examples(
        "agentes contract https://api.example.com/health",
        "agentes contract https://api.example.com/users/1 --schema user.json --max-ms 300",
        "agentes contract https://api.example.com/users --method POST --body '{\"name\": \"Ana\"}' --status 201",
        "",
        "The schema is a JSON file giving each field's type:",
        '  {"id": "int", "name": "str", "tags": ["str"], "owner": {"email": "str"}}',
    ))
    p.add_argument("url", metavar="URL", help="http(s) endpoint to check.")
    p.add_argument("--method", default="GET", help="HTTP method. Default: GET.")
    p.add_argument("--status", type=int, default=200, metavar="CODE", help="Expected status code. Default: 200.")
    p.add_argument("--schema", metavar="FILE", help="JSON file with the types expected in the response.")
    p.add_argument("--strict", action="store_true", help="Reject fields that are not in the schema.")
    p.add_argument("--max-ms", type=float, default=500.0, metavar="MS", help="Maximum response time. Default: 500 ms.")
    p.add_argument("--timeout", type=float, default=5.0, metavar="S", help="Connection timeout. Default: 5 s.")
    p.add_argument("--header", action="append", metavar="'Name: value'", help="Header to send. Can be repeated.")
    p.add_argument("--body", metavar="JSON", help="Request body.")
    _add_output_flags(p)


def _register_ops(add: _SubAdder) -> None:
    p = add("health", cmd_health, _examples(
        "agentes health", "agentes health --tcp localhost:5432 --http https://example.com/healthz",
    ))
    p.add_argument("--disk", default="/", metavar="PATH", help="Path whose disk is checked. Default: /.")
    p.add_argument("--min-free-mb", type=float, default=100.0, metavar="MB", help="Minimum free space. Default: 100 MB.")
    p.add_argument("--tcp", metavar="HOST:PORT", help="Check that a TCP port accepts connections.")
    p.add_argument("--http", metavar="URL", help="Check that a URL responds.")
    p.add_argument("--expect-status", type=int, default=200, metavar="CODE", help="Expected HTTP status. Default: 200.")
    _add_output_flags(p)

    p = add("sla", cmd_sla, _examples("agentes sla --total 12000 --errors 340", "agentes sla --total 500 --errors 3 --max-rate 1"))
    p.add_argument("--total", type=int, required=True, metavar="N", help="Total number of requests.")
    p.add_argument("--errors", type=int, required=True, metavar="N", help="Number of failed requests.")
    p.add_argument("--max-rate", type=float, default=5.0, metavar="PCT", help="Maximum error rate in %%. Default: 5.")
    _add_output_flags(p)

    p = add("serve", cmd_serve, _examples("agentes serve", "agentes serve --host 0.0.0.0 --port 9100"), aliases=("serve-sre",))
    p.add_argument("--host", default="127.0.0.1", help="Interface to listen on. Default: 127.0.0.1.")
    p.add_argument("--port", type=int, default=9100, help="Port. Default: 9100.")
    _add_output_flags(p, as_json=False)


def _register_utils(add: _SubAdder) -> None:
    p = add("password", cmd_password, _examples(
        "agentes password check", "agentes password hash", "agentes password verify 'argon2:$argon2id$...'",
        "echo 'my password' | agentes password check --stdin",
        "",
        "The password is prompted for interactively so it never lands in the shell history.",
        "check and hash query Have I Been Pwned using k-anonymity: only the first 5 characters",
        "of the SHA-1 hash are sent, never the password. --offline disables the lookup.",
    ))
    p.add_argument(
        "action", choices=["check", "hash", "verify"], metavar="ACTION",
        help="check: assess its strength. hash: generate the hash. verify: compare it with a hash.",
    )
    p.add_argument("hash", nargs="?", metavar="HASH", help="Hash to check against (verify only). Wrap it in single quotes.")
    p.add_argument("--stdin", action="store_true", help="Read the password from standard input.")
    _add_output_flags(p, offline=True)

    p = add("demo", cmd_demo, _examples("agentes demo qa", "agentes demo all"))
    p.add_argument("agent", metavar="AGENT", help=" | ".join(AGENTS) + " | all")
    _add_output_flags(p, as_json=False)

    p = add("list", cmd_list)
    _add_output_flags(p, as_json=False)

    p = add("doctor", cmd_doctor)
    _add_output_flags(p)

    p = add("help", lambda a: 0)
    p.add_argument("topic", nargs="?", metavar="COMMAND", help="Command to show the help for.")


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level parser with every subcommand registered."""
    parser = AgentesParser(prog="agentes", description=f"AGENTES DevSecOps CLI v{__version__}")
    summaries: Dict[str, str] = {name: desc for _, cmds in COMMAND_GROUPS for name, _, desc in cmds}
    sub = parser.add_subparsers(dest="command", metavar="<command>", title="Commands")

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

    # Global options: `agentes --list` is the same as `agentes list`.
    parser.add_argument("--list", "-l", action="store_true", help="List the agents (same as 'list').")
    parser.add_argument("--version", "-V", action="version", version=f"agentes {__version__}", help="Show the version.")
    parser.add_argument("--no-color", action="store_true", default=False, help="Disable colour output.")
    return parser
