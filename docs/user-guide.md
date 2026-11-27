# Work-Agents user guide

[Español](guia-de-usuario.md) | **English**

This guide covers Work-Agents 3.2.3 end to end: installation, every command with all of its
options, the rules each auditor applies, the report formats, continuous integration and using
the agents as a Python library. For an overview, see the [README](../README.md).

## Contents

- [Introduction](#introduction)
- [Installation](#installation)
- [Core concepts](#core-concepts)
- [Reading the output](#reading-the-output)
- [Getting started](#getting-started)
- [Analyzing a project](#analyzing-a-project)
  - [`pipeline`](#pipeline) · [`analyze`](#analyze) · [`secrets`](#secrets) · [`vulns`](#vulns) · [`audit`](#audit) · [`metrics`](#metrics)
- [Generating and fixing](#generating-and-fixing)
  - [`generate`](#generate) · [`fix`](#fix)
- [Testing](#testing)
  - [`test`](#test) · [`testability`](#testability) · [`contract`](#contract)
- [Operations](#operations)
  - [`health`](#health) · [`sla`](#sla) · [`serve`](#serve)
- [Utilities](#utilities)
  - [`password`](#password) · [`demo`](#demo) · [`list`](#list) · [`doctor`](#doctor) · [`help`](#help)
- [Rule catalog](#rule-catalog)
- [Reports and formats](#reports-and-formats)
- [Baseline](#baseline)
- [Silencing a finding on its line](#silencing-a-finding-on-its-line)
- [Continuous integration](#continuous-integration)
- [Library usage](#library-usage)
- [Network and privacy](#network-and-privacy)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)

---

## Introduction

Work-Agents is a command-line tool that audits Python projects from three angles:

- **Security (DevSecOps)**: insecure code, exposed secrets, dependencies with known
  vulnerabilities and weak infrastructure configuration.
- **Quality and testing (QA)**: complexity, design, performance, testability and test suite
  quality, plus generation of new tests.
- **Operations (SRE)**: health probes, error rates, Prometheus metrics and log analysis.

Internally it is split into eight agents, each a subpackage of `agentes`:

| Agent       | Responsibility                                                                  |
|-------------|---------------------------------------------------------------------------------|
| `defensive` | Input sanitization, password hashing, CSRF, HMAC tokens, RBAC, rate limiting, `.env` auditing and secret detection. |
| `quality`   | Static analysis (AST engine and Bandit), SARIF, vulnerabilities (OSV), version pinning (PyPI) and linter configuration. |
| `hardening` | Templates and audits for Nginx, Caddy, Dockerfile, Kubernetes and systemd.      |
| `refactor`  | Complexity metrics, SOLID heuristics, performance and Mermaid diagrams.         |
| `qa`        | Test generation and execution, testability and API contract testing.            |
| `sre`       | Structured logging, log anomalies, health probes, Prometheus and alerting.      |
| `devops`    | GitHub Actions, GitLab CI, Docker Compose, Helm and YAML validation.            |
| `docs`      | OpenAPI 3.0.3, Swagger UI and Markdown manuals.                                 |

You do not need to know the agents to use the tool: the `agentes` command combines them into
concrete tasks. The agents only matter if you want to [use them from Python](#library-usage).

**What Work-Agents does not do.** It does not run the code it analyzes (except `test` and
`generate tests --record`, which do so by design), it does not modify your source code (only
`fix` rewrites a `requirements.txt`, and only when asked) and it never sends code to any
service.

---

## Installation

### Requirements

- Python 3.9, 3.10, 3.11, 3.12 or 3.13 (CI tests all five).
- Required dependencies, installed automatically: `PyYAML>=6.0`, `packaging>=21.0` and, on
  Python 3.9 and 3.10, `tomli>=1.1`.
- CI runs on Linux. The tool is pure Python, but some features depend on the OS: the load
  average reported by `health` only exists on Unix-like systems (elsewhere it shows 0).

### Installing from the repository

The package is not published on PyPI. A virtual environment is recommended:

```bash
git clone https://github.com/kahz12/Work-Agents.git
cd Work-Agents
python3 -m venv .venv
source .venv/bin/activate          # on Windows: .venv\Scripts\activate
pip install -e .
```

`-e` (editable mode) applies changes in the repository without reinstalling. For a regular
install, drop `-e`.

### Installing directly from Git

Without cloning, for example in a CI job:

```bash
pip install "git+https://github.com/kahz12/Work-Agents.git"
pip install "agentes-devsecops[all] @ git+https://github.com/kahz12/Work-Agents.git"   # with extras
```

### Extras

Extras are optional. Each one improves an engine that already works without it:

| Extra    | Packages                | Without the extra                                            | With the extra                                   |
|----------|-------------------------|--------------------------------------------------------------|--------------------------------------------------|
| `crypto` | argon2-cffi, bcrypt     | `password hash` uses PBKDF2-HMAC-SHA256 with 600,000 iterations. | Uses Argon2 (or bcrypt if only bcrypt is present). |
| `sast`   | bandit                  | Static analysis uses only the built-in AST engine.           | Bandit runs in addition to the AST engine.       |
| `dev`    | pytest, ruff, pyflakes, coverage | You cannot run the repository's tests or lint.               | `pytest -q` and `ruff check .` work.             |
| `all`    | All of the above        |                                                              |                                                  |

```bash
pip install -e ".[crypto,sast]"
pip install -e ".[all]"
```

### Running without installing

If you prefer not to install the package, install only the dependencies and use the launcher:

```bash
pip install -r requirements.txt
python3 agentes_cli.py pipeline .
```

`python3 -m agentes` also works when the repository directory is on `PYTHONPATH`.

### Checking the installation

```bash
agentes --version
agentes doctor
```

`doctor` shows which components are installed and which are missing:

```text
AGENTES v3.2.3 diagnostics
==========================

  Component    Status    Detail
  Python       OK        3.14.4
  PyYAML       OK        YAML and Kubernetes validation
  bandit       optional  pip install bandit   (without it, the built-in AST engine is used)
  argon2-cffi  optional  pip install argon2-cffi
  bcrypt       OK        password hashing with bcrypt
  pytest       OK        run generated pytest suites

Password hashing  bcrypt
Demo output       next to each agent (set AGENTES_WORKDIR to change it)
Terminal colour   off

[OK] Ready to use. The optional components add features, but they are not required.
To install them all: pip install -e ".[all]"
```

Each row is a component with its status (`OK`; `optional` when it is optional and missing;
`MISSING` when it is required and missing) and either what it is used for or how to install
it. Below the table: the active password hashing backend, where demos write their files and
whether color is enabled. `doctor` returns `1` only if a required component (Python 3.9+ or
PyYAML) is missing.

### Upgrading from version 2

In version 3 the packages moved under `agentes/`. If you upgrade an old install, reinstall:

```bash
git pull
pip install -e .
```

The `--pypi` and `--default-version` options of `fix` are still accepted so old scripts keep
working, but they no longer have any effect.

### Uninstalling

```bash
pip uninstall agentes-devsecops
```

---

## Core concepts

### Findings

Everything an auditor detects is a **finding** with these fields:

| Field     | Content                                                                              |
|-----------|--------------------------------------------------------------------------------------|
| `file`    | File (or URL, for the header audit).                                                 |
| `line`    | Line number, starting at 1. It is `0` when it does not apply: a missing directive, an HTTP header, the whole file. |
| `level`   | Severity, see the next table.                                                        |
| `message` | Description and recommendation.                                                       |
| `rule_id` | Rule identifier, see the [rule catalog](#rule-catalog).                              |
| `category` | `security` (a security risk) or `quality` (reliability, maintainability or performance). Only in the commands' JSON output and in `pipeline.json`. |

### Security and code quality

The console splits findings into two sections, **Security** and **Code quality**, so a security risk does not get buried among missing docstrings. When
an analysis that looks for security problems (`pipeline`, `analyze`) finds none, it says so:

```text
[OK] No security findings.

Code quality (87): 68 medium, 19 low
```

Code quality covers metrics and SOLID principles, performance, test quality, Python and YAML
syntax errors and these static-analysis rules: docstrings, too many arguments, mutable default
arguments, `open()` outside a `with`, exception handling (`except:`, `except Exception`,
swallowing with `pass`), blocking calls in `async def`, global state and too many branches.
Everything else (secrets, infrastructure, dependencies, vulnerabilities, headers, logs and the
rest of the static analysis) is security. The category changes neither the severity nor the
exit code.

### Severities

From most to least severe (the level names appear as-is in JSON and SARIF):

| Level      | Blocking | Typical examples                                                       |
|------------|----------|------------------------------------------------------------------------|
| `CRITICAL` | Yes      | `eval`, `pickle.loads`, `os.system`, tracebacks or out-of-memory errors in logs. |
| `ERROR`    | Yes      | Something could not be analyzed (unreadable file, corrupt manifest). It is never treated as clean. |
| `HIGH`     | Yes      | `shell=True`, hand-built SQL, secrets, a container running as root.    |
| `MEDIUM`   | No       | Missing `timeout`, weak hash, unpinned base image.                     |
| `LOW`      | No       | Missing docstrings, `assert` outside tests, `>=` in dependencies.      |
| `INFO`     | No       | Informational. Not shown on the console.                               |
| `OK`       | No       | Check passed. Not shown on the console.                                |

"Blocking" means the finding makes commands that fail on high or critical findings fail
(`pipeline`, `audit`, `vulns`, `analyze --fail-on-high`...).

### Exit codes

| Code  | Meaning                                                                              |
|-------|--------------------------------------------------------------------------------------|
| `0`   | Everything is fine, or the command is informational (`metrics`, `testability`).      |
| `1`   | There are findings that make the command fail, failing tests, an endpoint that breaks its contract, a probe that is down, or an unexpected error. |
| `2`   | Usage error: nonexistent path, unknown option, misspelled command, invalid option combination, or no network for a command that needs it. |
| `130` | Interrupted with Ctrl+C.                                                             |

Each command below details exactly when it returns `1`.

### Common options

| Option        | Available in                                                       | Effect                                                    |
|---------------|--------------------------------------------------------------------|-----------------------------------------------------------|
| `-h`, `--help`| All                                                                | Command help, with examples.                              |
| `--json`      | All except `generate`, `serve`, `demo`, `list` and `help`          | Prints the result as JSON instead of the summary.         |
| `--limit N`   | `pipeline`, `analyze`, `secrets`, `vulns`, `audit`, `metrics`, `fix`, `test`, `testability` | Maximum items per list. Default 20. `0` shows everything. |
| `--offline`   | `pipeline`, `analyze`, `vulns`, `fix`, `password`                  | No network requests. Same as `AGENTES_OFFLINE=1`.         |
| `--no-color`  | All                                                                | Disables color.                                           |

`agentes --version` (or `-V`) prints the version and `agentes --list` (or `-l`) is the same as
`agentes list`.

### Environment variables

| Variable           | Effect                                                                                       |
|--------------------|----------------------------------------------------------------------------------------------|
| `AGENTES_OFFLINE`  | With `1`, `true`, `yes`, `si` or `sí`, disables every network request (OSV, PyPI, Have I Been Pwned). |
| `AGENTES_WORKDIR`  | Directory where demos write their files (see [`demo`](#demo)).                               |
| `AGENTES_DEBUG`    | When set, an unexpected error shows the full traceback instead of a short message.           |
| `NO_COLOR`         | When set, disables color ([no-color.org](https://no-color.org) convention).                  |

Color is only used when output goes to a terminal: redirecting to a file or another program
turns it off automatically.

### Paths in the output

Paths are shown relative to the current directory when they are close (up to two levels up);
otherwise relative to the analyzed project; otherwise absolute. JSON reports use absolute paths;
SARIF uses paths relative to the project root.

### Skipped directories

When walking a directory, every analysis command ignores:

- `.git`, `__pycache__`, `node_modules`, `build`, `dist` and `reports`.
- The `.mypy_cache`, `.pytest_cache` and `.ruff_cache` caches.
- `*.egg-info` directories.
- Virtual environments: `.venv`, `venv`, any name starting with `venv` or `.venv`, and any
  directory containing a `pyvenv.cfg`, whatever its name.
- The report directory given with `-o`.

Note that a directory named `reports` is always skipped, even if it contains code.

### Errors and suggestions

A misspelled command suggests the closest match and exits with `2`:

```text
$ agentes piplene .
Error: Unknown command: 'piplene'.
  Did you mean 'pipeline'? Run 'agentes' to see every command.
```

Argument errors are also explained and say how to get help. If something fails unexpectedly,
`AGENTES_DEBUG=1 agentes ...` prints the full traceback.

---

## Reading the output

### Status labels

| Label    | Meaning                                                      |
|----------|--------------------------------------------------------------|
| `[OK]`   | Success.                                                     |
| `[WARN]` | Warning: worth reading, does not change the result.          |
| `[FAIL]` | Failure: the command will exit with a non-zero code.         |
| `Error:` | Usage or environment error (printed to stderr, exit code 2). |

### Pipeline table

Each stage has a status: `OK` (passed), `FAILED` (the stage has blocking findings) or `SKIPPED`
(it could not run or did not apply, for example `skipped: offline mode` or
`skipped: no web framework detected`). The summary column says what was analyzed:

- `N SAST findings (M high/critical) in X of Y files`, followed by
  `without Bandit (AST engine only; install the 'sast' extra)` when Bandit is not installed.
- `N possible secrets/insecure settings in X of Y files (+N config)`: `+N config` counts the
  configuration files added to the scan.
- `not checked`: the vulnerability stage found nothing with an exact version to look up.

Below the table, findings are grouped into `Security` and `Code quality`, each with its count by
severity (`Security (6): 4 high, 2 medium`). With a baseline, the console also says how many
accepted findings were not counted and how many entries no longer match anything.

### Findings

Each finding starts with its level in brackets (`[CRITICAL]`, `[HIGH]`, `[MEDIUM]`, `[LOW]`),
followed by the file and line. Inside the message:

| Text                          | Meaning                                                  |
|-------------------------------|----------------------------------------------------------|
| `***REDACTED***`              | Masked part of a secret.                                 |
| `Fixed in X.`                 | The vulnerability is fixed in version X.                 |
| `No fixed version published.` | No fixed version has been published yet.                 |
| `Also detected by: bandit`    | Several engines reported it and the findings were merged. |
| `[bandit]` prefix             | The finding comes from Bandit alone.                     |
| `Line N:`                     | Line of the manifest the finding refers to.              |

---

## Getting started

This walkthrough uses a small project with deliberate problems. It takes a few minutes.

### 1. A sample project

```text
my_project/
├── app/
│   ├── main.py          Flask API with one route, a subprocess with shell=True and yaml.load
│   └── settings.py      DB_URL = "postgres://admin:<password>@db:5432/app"
├── Dockerfile           FROM python:latest, no USER
├── requirements.txt     flask==2.0.0 and an unpinned requests
└── .env                 DEBUG=true and SECRET_KEY=changeme
```

### 2. Full audit

```bash
agentes pipeline my_project
```

```text
Audit of my_project
===================

  Stage                            Status   Summary
  Static analysis                  FAILED   2 SAST findings (2 high/critical) in 2 of 2 files ·
                                            without Bandit (AST engine only; install the 'sast'
                                            extra)
  Secrets                          FAILED   1 possible secrets/insecure settings in 2 of 2 files (+1
                                            config)
  Metrics and SOLID                OK       avg_cyclomatic=1.0 avg_cognitive=0.0 · 2 files · 0 SOLID
                                            findings
  OpenAPI documentation            OK       flask: 1 routes in 2 files
  Infrastructure and dependencies  FAILED   3 findings (1 high/critical) in 2 infra/deps/YAML files
  Dependency vulnerabilities       SKIPPED  skipped: offline mode · 1 manifests not checked

Security (6): 4 high, 2 medium
  [HIGH]   my_project/Dockerfile
           The Dockerfile has no 'USER <non_root_user>' instruction. The container will run as root
           by default.
  [HIGH]   my_project/app/main.py:18
           Subprocess started with 'shell=True' (command injection risk).
  [HIGH]   my_project/app/main.py:24
           Unsafe use of 'yaml.load()' without SafeLoader (use yaml.safe_load).
  [HIGH]   my_project/app/settings.py:1
           Credential inside a connection URL: DB_URL =
           "postgres://admin:***REDACTED***@db:5432/app"
  [MEDIUM] my_project/Dockerfile:1
           Base image uses ':latest' or no pinned tag. Specify the exact version.
  [MEDIUM] my_project/requirements.txt:2
           [requests] Line 2: dependency 'requests' does not pin a version (==x.y.z). Installs can
           pick up unwanted changes.

Reports
  HTML     my_project/reports/pipeline.html
  JSON     my_project/reports/pipeline.json
  SARIF    my_project/reports/pipeline.sarif
  OpenAPI  my_project/reports/openapi.json

[FAIL] There are blocking findings (exit code 1).
Open my_project/reports/pipeline.html in a browser for the details.
```

(This output comes from a run with `--offline`. With network access, the last stage queries
OSV.)

How to read it:

1. **The stage table** summarizes each analysis. `FAILED` means the stage has blocking
   findings; `SKIPPED` means it could not run or did not apply.
2. **The findings**, most severe first, with file and line. Here: the container runs as root,
   `shell=True` allows command injection, `yaml.load` without `SafeLoader` is unsafe, a database
   URL contains a password (masked as `***REDACTED***`), the base image uses `:latest`, and
   `requests` has no pinned version.
3. **The reports** are written to `my_project/reports/`. The HTML one is the easiest to browse.
4. **The exit code** is `1` because there are high findings and a secret.

### 3. Fix and repeat

Replace `shell=True` with an argument list, use `yaml.safe_load`, move the database URL to an
environment variable, add `USER` to the Dockerfile and pin `requests==<version>`. Run
`agentes pipeline my_project` again until you see `[OK] No blocking findings.`

### 4. Check what the pipeline does not cover

The `.env` file is not audited by the pipeline (it is only scanned for real secrets). To review
its settings:

```bash
agentes audit my_project/.env
```

```text
Audit of my_project/.env
========================
Kind: env · Items checked: 1

Security (2): 2 high
  [HIGH] my_project/.env
         [DEBUG] The 'DEBUG' option is enabled. It must be disabled in production.
  [HIGH] my_project/.env
         [SECRET_KEY] The value of 'SECRET_KEY' is insecure or a known default ('changeme'). Use
         environment variables.
```

`agentes audit my_project` reviews infrastructure, dependencies, `.env` files and logs
in one go.

### 5. Next steps

- Generate tests for a module: `agentes generate tests --source app/calc.py`.
- If the project already has accepted findings, create a [baseline](#baseline).
- Add the pipeline to your [CI](#continuous-integration).

---

## Analyzing a project

### `pipeline`

```text
agentes pipeline PATH [-o DIR] [--no-fail] [--max-files N] [--no-bandit]
                      [--baseline FILE | --write-baseline FILE]
                      [--offline] [--json] [--limit N] [--no-color]
```

Full audit of a directory or file. It is the main command and the one recommended for CI.

#### Options

| Option                  | Default          | Effect                                                                         |
|-------------------------|------------------|--------------------------------------------------------------------------------|
| `PATH`                  | (required)       | Directory or file to audit. With a file, the project root is its directory.    |
| `-o`, `--output DIR`    | `PATH/reports`   | Report directory. Created if missing and excluded from the analysis.           |
| `--no-fail`             | off              | The static analysis, infrastructure and vulnerability stages do not fail on high or critical findings. Secrets still fail. |
| `--max-files N`         | all              | Analyze at most N `.py` files (in alphabetical path order). The summary and report say how many were left out. |
| `--no-bandit`           | off              | Use only the AST engine. Bandit spawns one subprocess per file, so on large projects it dominates the run time. |
| `--baseline FILE`       | none             | Findings recorded in the baseline are not counted. See [Baseline](#baseline).  |
| `--write-baseline FILE` | none             | Save current blocking findings and secrets as a baseline and exit with `0`. Cannot be combined with `--baseline`. |
| `--offline`             | off              | Do not query OSV: the vulnerability stage is skipped.                          |
| `--json`                | off              | Print the full report (the same as `pipeline.json`) instead of the summary.    |
| `--limit N`             | 20               | Maximum findings listed on the console. `0` lists all. Reports are not affected. |

#### Stages

All six stages always run, in this order. The internal name (in parentheses) is the one used in
the JSON report.

**1. Static analysis** (`quality_sast`)

- Analyzes the `.py` files found (honoring `--max-files`).
- Engines: the [built-in AST engine](#static-analysis-ast-engine) always and, when installed
  and `--no-bandit` is not used, Bandit. Findings from both on the same line and topic are
  merged into one that says "Also detected by: bandit".
- When Bandit is missing, the summary says so: `without Bandit (AST engine only; install the 'sast' extra)`.
- Status `FAILED` when there are blocking findings (unless `--no-fail`).

**2. Secrets** (`defensive_secrets`)

- Scans the analyzed `.py` files and the configuration files in the tree: `.env`, `.env.*` and
  the extensions `.env`, `.yml`, `.yaml`, `.json`, `.toml`, `.ini`, `.cfg`, `.conf`, `.sh` and
  `.sql`. The summary shows how many configuration files were added (`(+1 config)`).
- Excludes its own reports (`pipeline.json`, `analyze.json`, `openapi.json`, `*.sarif`) and the
  file passed to `--baseline` or `--write-baseline`.
- An unreadable file counts as `ERROR` (rule `SECRET-SCAN-ERROR`): it is never treated as clean.
- Status `FAILED` when there is at least one secret or unreadable file, **even with `--no-fail`**.
- Pattern details in [Secret detection](#secret-detection).

**3. Metrics and SOLID** (`refactor_metrics`)

- Computes average cyclomatic and cognitive complexity per function, lines of code and comment
  ratio.
- Applies the [SOLID and design](#solid-and-design) and [performance](#performance)
  heuristics from the catalog. In the pipeline, performance findings are always recorded as
  `MEDIUM`.
- A SOLID finding that repeats what static analysis already found on the same line is not
  counted twice.
- **It does not affect the exit code.** Its findings appear in the list and reports as
  refactoring information. The status is `FAILED` only if no file could be parsed.
- Refactoring recommendations are in the JSON report (`stages[].recommendations`), following
  the same rules as [`metrics`](#metrics): average-based ones once, and line-specific ones with
  their file, relative to the project root (`pkg/app.py:12`).

**4. OpenAPI documentation** (`documentation`)

- Runs only if some file imports a web framework: FastAPI, Flask, Starlette, Django, aiohttp,
  Bottle, Sanic, Tornado, Falcon, Quart, Litestar, Pyramid, CherryPy, Connexion or Responder.
  Otherwise it is `SKIPPED` (skipped): in a non-web project, a `get_*` function is not an
  endpoint.
- Recognizes routes declared with Flask (`@app.route`) and FastAPI (`@app.get`,
  `@router.post`...) decorators. If it finds at least one, it writes `openapi.json` to the
  report directory.
- It does not affect the exit code.

**5. Infrastructure and dependencies** (`infra_and_deps`)

- Audits `Dockerfile`, `Dockerfile.*`, `*.dockerfile`, `*.service`, `requirements*.txt`,
  `package.json` and every `*.yml` / `*.yaml`.
- Excludes Helm templates (YAML files inside `templates/` next to a `Chart.yaml`), which are not
  valid YAML until Helm renders them.
- Rules in [Dockerfile](#dockerfile), [systemd](#systemd), [YAML and Kubernetes](#yaml-and-kubernetes)
  and [Declared dependencies](#declared-dependencies).
- Status `FAILED` when there are blocking findings (unless `--no-fail`).
- It does not audit `.env` files (`audit` does).

**6. Dependency vulnerabilities** (`dependency_vulns`)

- Looks up dependencies with exact versions and the packages installed in the project's
  virtual environment in OSV. Details in [`vulns`](#vulns).
- Possible statuses:
  - `OK`: there are no manifests or environments, or no blocking vulnerabilities.
  - `SKIPPED`: offline mode, OSV did not respond, or nothing can be checked (every
    dependency uses ranges and there is no environment or lock file). In the last case the
    summary says "not checked" instead of a misleading "OK".
  - `FAILED`: high or critical vulnerabilities (unless `--no-fail`).
- A skipped stage never fails the pipeline.

#### Exit code

`pipeline` returns `1` if any of these happens:

- There are blocking findings in static analysis, infrastructure or vulnerabilities, and
  `--no-fail` is not used.
- There is at least one secret or unreadable file in the secrets stage (always).

Otherwise it returns `0`. With `--write-baseline` it always returns `0`. With `--baseline`,
accepted findings do not count toward any of the above.

#### Reports

The report directory contains:

| File             | Content                                                                |
|------------------|------------------------------------------------------------------------|
| `pipeline.json`  | Full report: stages, metrics, findings and artifact paths. See the [format](#pipelinejson). |
| `pipeline.html`  | Browser summary: stage table and findings table.                       |
| `pipeline.sarif` | Findings in SARIF 2.1.0, for GitHub Code Scanning and editors.         |
| `openapi.json`   | Only when the documentation stage found routes.                        |

Files are overwritten on every run.

#### Examples

```bash
agentes pipeline .                                       # project in the current directory
agentes pipeline ./src -o ./reports                      # reports outside the project
agentes pipeline . --no-bandit --max-files 500           # large project, faster
agentes pipeline . --offline                             # no network
agentes pipeline . --no-fail                             # only secrets cause failure
agentes pipeline . --json | jq '.stages[] | {name, status}'
```

#### Speed on large projects

The slowest parts are Bandit (one subprocess per file) and, with network access, the OSV
lookup. To speed things up: `--no-bandit`, `--offline` for local runs and `--max-files` for
quick checks. The AST engine alone analyzes hundreds of files in seconds.

---

### `analyze`

```text
agentes analyze PATH [-o DIR] [--fail-on-high] [--no-bandit] [--offline] [--json] [--limit N]
```

Runs only three parts of the pipeline: Python static analysis, the infrastructure and
dependency audit, and the vulnerability lookup. It does not scan for secrets, compute metrics or
generate OpenAPI.

| Option               | Default        | Effect                                                          |
|----------------------|----------------|-----------------------------------------------------------------|
| `PATH`               | (required)     | File or directory.                                              |
| `-o`, `--output DIR` | `PATH/reports` | Report directory.                                               |
| `--fail-on-high`     | off            | Return `1` when there are high or critical findings.            |
| `--no-bandit`        | off            | Use only the AST engine.                                        |
| `--offline`          | off            | Do not query OSV.                                               |
| `--json`, `--limit`  |                | See [common options](#common-options).                          |

It writes `analyze.json` (target and findings) and `analyze.sarif`. **It returns `0` even when
there are findings**, unless `--fail-on-high` is used; if there are high findings without the
option, it reminds you at the end. It does not support a baseline.

```bash
agentes analyze ./src
agentes analyze app.py -o ./reports --fail-on-high
```

---

### `secrets`

```text
agentes secrets PATH [--json] [--limit N]
```

Looks for keys, tokens and passwords.

- With a **file**, it scans it regardless of its extension.
- With a **directory**, it scans `.py` files and configuration files (the same extensions as the
  pipeline's secrets stage).

Values are always masked: at most the first three characters are kept and the rest is replaced
with `***REDACTED***`; in a connection URL only the password is hidden.

```text
$ agentes secrets .
Secret scan of .
================
Files scanned: 3

Security (1): 1 high
  [HIGH] app/settings.py:1
         Credential inside a connection URL: DB_URL = "postgres://admin:***REDACTED***@db:5432/app"

Values are shown masked. If a secret was ever published, rotate it as well as deleting it.
```

Returns `1` when it finds at least one secret or unreadable file.

This command applies no baseline and excludes no file in the tree: if the project contains a
baseline with accepted secrets, `secrets` may flag it (see
[Troubleshooting](#secrets-flags-the-baseline)).

```bash
agentes secrets .
agentes secrets .env
agentes secrets ./config --json
```

---

### `vulns`

```text
agentes vulns PATH [--json] [--limit N]
```

Checks [OSV](https://osv.dev) for known vulnerabilities in the dependencies. **It needs network
access**: with `--offline` or `AGENTES_OFFLINE=1` it exits with `2`.

#### What it checks

In order of reliability:

1. **The project's virtual environments**: the root itself or any direct subfolder containing a
   `pyvenv.cfg` (for example `.venv/`). Installed packages are read with their exact versions:
   they are what actually runs.
2. **Manifests** in the tree, with exact versions:

| File                  | Ecosystem | What is read                                           |
|-----------------------|-----------|--------------------------------------------------------|
| `requirements*.txt`   | PyPI      | Dependencies pinned with `==`.                         |
| `pyproject.toml`      | PyPI      | Project dependencies pinned with `==`.                 |
| `poetry.lock`         | PyPI      | Every locked version.                                  |
| `Pipfile.lock`        | PyPI      | Every locked version.                                  |
| `package.json`        | npm       | Dependencies with an exact version.                    |
| `package-lock.json`   | npm       | Every locked version.                                  |

Dependencies declared with ranges (`>=`, `<`, `^`, `~`) cannot be checked on their own, because
the installed version is unknown. If nothing can be checked, the command says so and returns
`0`:

```text
[WARN] No dependency was checked: all 4 declared ones use ranges, and there is no installed environment or lock file with exact versions.
Create the project's .venv or a lock file (poetry.lock, Pipfile.lock, pinned requirements) and run it again.
```

#### Result

Each vulnerability is a finding with rule `VULN-<OSV id>` and a message with the package, the
version, the identifier (the CVE when there is one), the summary and the fixed version:

```text
  [MEDIUM] requirements.txt:1
           requests 2.32.4 — CVE-2026-25645: Requests has Insecure Temp File Reuse in its
           extract_zipped_paths() utility function. Fixed in 2.33.0.
```

Severity comes from the GitHub advisory database (GHSA): `CRITICAL`, `HIGH`, `MEDIUM` and `LOW`
are kept as they are, and `MODERATE` becomes `MEDIUM`. When the advisory has no severity, it is
treated as `HIGH`.

If a declared range prevents installing the fixed version (for example `urllib3<2` when the fix
is in `2.2.2`), it appears in a final section:

```text
Constraints that block installing the fix
  - urllib3<2 in pyproject.toml: the fix needs 2.2.2. Raise the upper bound.
```

#### Exit code

`1` when there is any high or critical vulnerability; `0` when there is none, or when nothing
could be checked; `2` when there are no manifests or environments, offline mode is active or OSV
does not respond.

```bash
agentes vulns .
agentes vulns requirements.txt
agentes vulns package-lock.json --json
```

---

### `audit`

```text
agentes audit PATH|URL [--type TYPE] [--json] [--limit N]
```

Audits a single file, a directory or the headers of a URL. The type is inferred from the name:

| Target                                           | Type      | What it checks                                                 |
|--------------------------------------------------|-----------|----------------------------------------------------------------|
| `Dockerfile`, `Dockerfile.*`, `*.dockerfile`     | `docker`  | Root user, unpinned image, `sudo`, `chmod 777`.                |
| `*.service`                                      | `systemd` | Isolation directives that are missing or disabled.            |
| `requirements*.txt`, `package.json`              | `deps`    | Unpinned dependencies.                                         |
| `*.yml`, `*.yaml`                                | `yaml`    | Syntax and, for `kind: Pod` manifests, the security context.   |
| `.env`, `.env.*`, `*.env`                        | `env`     | Debug mode enabled and weak or default keys.                   |
| `*.log`                                          | `logs`    | Tracebacks, 5xx errors, out-of-memory, authentication and connection failures. |
| `test_*.py`, `*_test.py`                         | `tests`   | Test suite quality.                                            |
| `http://...`, `https://...`                      | `headers` | Missing HTTP security headers.                                 |
| A directory                                      | several   | All of the above except test suites and URLs, file by file.    |

The rules for each type are in the [catalog](#rule-catalog).

| Option         | Effect                                                                                      |
|----------------|---------------------------------------------------------------------------------------------|
| `--type TYPE`  | Force the type: `auto` (default), `docker`, `systemd`, `deps`, `yaml`, `env`, `logs`, `tests` or `headers`. Only applies to a file or URL; with a directory it exits with `2`. |

Notes:

- A file whose type is not recognized exits with `2` and asks for `--type`. For Python code
  that is not a test suite, use `analyze`.
- **`.env` templates.** If the name contains `example`, `sample`, `template`, `dist`, `tpl` or
  `defaults` (`.env.example`, `.env.sample`...), empty or example values are expected and not
  flagged. Only `DEBUG` or `TESTING` enabled by default is reported, as `LOW`.
- Reading a `.env` file never exports anything into the process environment.
- **URLs.** A `GET` request is made with an 8-second timeout. Headers are checked even when the
  server answers with a 4xx or 5xx error.

Returns `1` when there are high or critical findings.

```bash
agentes audit Dockerfile
agentes audit .env
agentes audit app.log
agentes audit tests/test_api.py
agentes audit https://example.com
agentes audit ./infra
agentes audit my.conf --type systemd
```

---

### `metrics`

```text
agentes metrics PATH [--json] [--limit N]
```

Maintainability metrics for one `.py` file or every one in a directory (tests included). It is
informational: **it always returns `0`** (except on usage errors, such as a directory with no
`.py` files).

It shows, in this order:

1. **Totals**: files, lines of code, functions, and average cyclomatic and cognitive
   complexity per function.
2. **Most complex files** (when there is more than one), by
   average cyclomatic complexity.
3. **Most complex functions**: the top 10 (all with `--limit 0`),
   colored by cyclomatic complexity: up to 5 is simple, 6 to 10 deserves attention, more than
   10 calls for splitting.
4. **Findings** from the [SOLID and design](#solid-and-design) and [performance](#performance)
   rules, with their original severity (unlike the pipeline, where performance is always
   `MEDIUM`).
5. **Refactoring recommendations**, of two kinds:
   - Average-based ones (high average cyclomatic or cognitive complexity, less than 5%
     documentation) are assessed over everything analyzed, like the totals, and appear once.
   - Line-specific ones (SOLID and performance findings) give the file and line, for example
     `[DESIGN SRP - src/app/screens.py:412]`.

   When there are more than the limit, the number left out is shown. The `[EXCELLENT]`
   verdict only appears when there are no recommendations and no findings, including
   files that could not be parsed.

```text
Metrics for .
=============
Files                          3
Lines of code                  17
Functions                      4
Average cyclomatic complexity  1.5
Average cognitive complexity   0.25

Most complex files
  Lines  Funcs  Cyclom.  Cognit.  File
      4      1      3.0      1.0  calc.py
     12      3      1.0      0.0  app/main.py
      1      0      1.0      0.0  app/settings.py

Most complex functions
  Cyclom.  Cognit.  Function
        3        1  discount  (calc.py:4)
        1        0  get_user  (app/main.py:11)
        1        0  archive  (app/main.py:16)
        1        0  load_settings  (app/main.py:21)
  Reference: up to 5 is simple, 6 to 10 is worth watching, above 10 calls for splitting it up.

Recommendations
  - [EXCELLENT] The analysed code meets every maintainability, reliability, performance and SOLID
    threshold.
```

**Cyclomatic complexity**: number of independent paths through a function (1 plus each `if`,
`for`, `while`, `except` and boolean operator). **Cognitive complexity**: how hard it is to read;
it penalizes nesting more than the raw number of branches.

With `--json` it returns `totals`, `files` (per file), `functions` (with `cyclomatic` and
`cognitive`), `findings` and `recommendations`.

---

## Generating and fixing

### `generate`

```text
agentes generate [TYPE] [-o OUTPUT] [--force] [type options]
```

Without `TYPE`, it lists the available types. Each type has a default output, relative to the
current directory; `-o` changes it.

**It never overwrites.** If the output already exists, it stops with `2` and asks for `--force`
or another path with `-o`. The exception is `linters`, which keeps existing files and writes only
the missing ones.

#### Options

| Option                    | Default               | Types                                    | Effect                                       |
|---------------------------|-----------------------|------------------------------------------|----------------------------------------------|
| `-o`, `--output OUTPUT`   | per type              | all                                      | Output file or directory.                    |
| `--force`                 | off                   | all                                      | Overwrite the output if it exists.           |
| `--source FILE`           | none                  | `openapi`, `swagger`, `docs`, `diagram`, `tests` | Source Python file (required for these types). |
| `--service NAME`          | `web`                 | `compose`, `helm`, `k8s`, `openapi`, `swagger` | Service or chart name, or API title.   |
| `--image IMAGE`           | `myorg/myapp:1.0.0`   | `compose`, `helm`, `k8s`                 | Container image.                             |
| `--port PORT`             | `8080`                | `compose`, `helm`                        | Service port.                                |
| `--mem-limit LIMIT`       | `512m`                | `compose`                                | Memory limit.                                |
| `--cpus N`                | `0.50`                | `compose`                                | CPU limit.                                   |
| `--domain DOMAIN`         | `example.com`         | `nginx`, `caddy`                         | Server domain.                               |
| `--csp POLICY`            | `default-src 'self';` | `nginx`, `caddy`                         | `Content-Security-Policy` value.             |
| `--framework`             | `unittest`            | `tests`                                  | `unittest` or `pytest`.                      |
| `--record`                | off                   | `tests`                                  | Record real values by running the module.    |
| `--naming-convention`     | off                   | `openapi`, `swagger`                     | Treat `get_`, `post_`, `put_` and `delete_` functions as routes. |

#### Infrastructure types

**`compose`** (output: `docker-compose.yml`)

A hardened Docker Compose service:

- `read_only: true` with a `tmpfs` on `/tmp`.
- `security_opt: no-new-privileges:true`.
- `mem_limit` and `cpus` (honored by `docker compose` v2), `mem_reservation: 128m` and an
  equivalent `deploy.resources` block for Docker Swarm.
- `restart: unless-stopped`, the published port and a dedicated network.
- With the default image, the service is built from `Dockerfile.hardened` (generate it with
  `generate dockerfile`). If you pass `--image`, that image is used instead of building.

```bash
agentes generate compose --service api --image myorg/api:1.2.0 --port 8000 --mem-limit 256m --cpus 0.25
```

**`helm`** (output: directory `chart/`)

A chart with `Chart.yaml`, `values.yaml` and `templates/deployment.yaml`. The container does not
run as root (`runAsNonRoot`), cannot escalate privileges (`allowPrivilegeEscalation: false`)
and drops every capability (`drop: [ALL]`). Overwrite protection checks whether `Chart.yaml`
exists in the destination.

```bash
agentes generate helm -o ./chart --service api --image myorg/api:1.2.0 --port 8000
helm install api ./chart
```

**`k8s`** (output: `pod.yaml`)

A Pod manifest named `<service>-hardened` with:

- `runAsNonRoot: true`, user and group `10001`, `fsGroup: 10001` and the `RuntimeDefault`
  seccomp profile.
- Per container: `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true` and
  `capabilities.drop: [ALL]`.
- Resources: limits of `500m` CPU and `512Mi` memory; requests of `100m` and `128Mi`.

**`dockerfile`** (output: `Dockerfile.hardened`)

A multi-stage Dockerfile on `python:3.10-slim`: one stage installs the dependencies from
`requirements.txt` and the final one copies the result, creates the `appuser` user (UID and GID
10001), gives it ownership of `/app` and runs as `USER appuser`. It exposes port 8080 and runs
`python3 main.py`: adjust the Python version, port and command to your application.

**`systemd`** (output: `app.service`)

A unit with `User=appuser`, `Restart=on-failure` and these isolation directives:
`NoNewPrivileges=true`, `ProtectSystem=strict` (with `ReadWritePaths` for logs and `/tmp`),
`ProtectHome=true`, `PrivateTmp=true`, `PrivateDevices=true`, `ProtectKernelTunables=true`,
`ProtectKernelModules=true` and an empty `CapabilityBoundingSet=`. Adjust `WorkingDirectory`,
`ExecStart` and `ReadWritePaths` (they point to `/opt/mi_aplicacion` by default).

**`nginx`** (output: `nginx.conf`)

A `server` block on port 443 with HTTP/2, TLS 1.2 and 1.3 only, ECDHE ciphers with GCM,
`server_tokens off`, six security headers (`Content-Security-Policy`, `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff`, `Strict-Transport-Security` with `preload`,
`Referrer-Policy` and `Permissions-Policy`) and buffer and body size limits (10 MB). **It does
not include `ssl_certificate` and `ssl_certificate_key`**: add them with your certificate paths.

```bash
agentes generate nginx --domain mydomain.com --csp "default-src 'self'; img-src 'self' data:"
```

**`caddy`** (output: `Caddyfile`)

The same for Caddy v2: TLS 1.2 and 1.3, the six headers, removal of the `Server` header and
`file_server`. Caddy obtains certificates automatically.

#### CI and quality types

**`github-actions`** (output: `.github/workflows/devsecops.yml`)

A workflow triggered on `push` and `pull_request` to `main` and `master`, with Python 3.12: an
audit job (ruff for lint and style checks, plus Bandit) and a test job
(`python -m unittest discover`).

**`gitlab-ci`** (output: `.gitlab-ci.yml`)

A pipeline with three stages: `lint` (flake8 with 100-character lines), `test` (unittest) and
`security` (Bandit), with a pip cache.

**`linters`** (output: current directory)

Writes three files to the given directory:

- `.flake8`: 100-character lines and exclusion of environments and builds.
- `pyproject.toml`: black (100 characters), isort (black profile) and mypy
  (`disallow_untyped_defs`) settings.
- `.eslintrc.json`: `eslint:recommended` with `eqeqeq` and `curly` as errors.

Existing files are kept (with a warning), so it does not overwrite your `pyproject.toml`;
`--force` replaces them.

#### Documentation types

**`openapi`** (output: `openapi.json`)

An OpenAPI 3.0.3 specification from a Python file, without importing or running it:

- Recognizes routes declared with Flask (`@app.route`) and FastAPI (`@app.get`,
  `@router.post`...) decorators.
- With `--naming-convention`, also functions prefixed with `get_`, `post_`, `put_` or
  `delete_`. If there are no decorators but there are functions with those prefixes, the command
  suggests the option.
- Type annotations become parameters and schemas.
- If there are no routes, the specification is empty and a warning is shown: no endpoint is ever
  invented.
- The format follows the output: `.yaml` or `.yml` writes YAML; `.json` writes JSON; any other
  path is treated as a directory and `openapi.json` is written inside it.
- `--service` sets the API title.

```bash
agentes generate openapi --source app.py
agentes generate openapi --source app.py -o openapi.yaml --service "Orders API"
```

**`swagger`** (output: `swagger_ui.html`)

An HTML page with Swagger UI and the specification embedded. Swagger UI assets are loaded from
a CDN, so it needs network access to render.

**`docs`** (output: `DOCS.md`)

A Markdown manual with the file's modules, classes and functions and their docstrings.

**`diagram`** (output: `diagrama.md`)

A Mermaid class diagram: each class with its first five methods (and a note with how many more
it has) and the inheritance relationships. If the output ends in `.md`, it is wrapped in a
` ```mermaid ` block with a title, ready to render on GitHub.

#### The `tests` type

```bash
agentes generate tests --source app.py                       # unittest, test_app.py next to app.py
agentes generate tests --source app.py --framework pytest
agentes generate tests --source app.py --record
```

Generates a suite with nominal, edge and error cases for each public function. The default
output is `test_<source>.py` in the same directory as the source.

- **unittest** (default): a `TestCase` class with a nominal test and, when the function
  validates its input, an invalid-input test with `assertRaisesRegex`.
- **pytest**: parametrized tests with boundary values and adversarial cases. If
  [Hypothesis](https://hypothesis.readthedocs.io) is installed, property-based tests are added;
  otherwise the suite still works.

**Where expected values come from.** The generator never guesses a function's return value from
its name. Each assertion comes from one of these sources:

1. **The function body**, when it is pure (assignments, `if`, `return` and `raise` over the
   parameters and a few builtins such as `len` or `abs`). It is computed without running the
   code. A real example:

   ```python
   def discount(price: float, percent: float) -> float:
       if percent < 0 or percent > 100:
           raise ValueError("percent out of range")
       return price - price * percent / 100
   ```

   produces:

   ```python
   def test_discount_happy_path(self):
       result = discount(100.0, 10.0)
       # Value computed from the function body.
       self.assertAlmostEqual(result, 90.0)

   def test_discount_invalid_input(self):
       with self.assertRaisesRegex(ValueError, r"percent\ out\ of\ range"):
           discount(100.0, -1)
   ```

2. **Real execution**, with `--record`. The module is imported in a separate process and each
   function's return value is recorded. These are characterization tests: they pin the current
   behavior, correct or not, so review them. Functions with I/O or non-deterministic results are
   skipped.
3. **Only what can be verified**, in every other case: the annotated type, that it returns
   `None` or that it does not.

**Where sample values come from.** Only required arguments are passed; those with a default keep
it. For each one, from most to least reliable:

1. **Its type annotation**, including containers (`List[int]` becomes `[1]`, `Dict[str, int]`
   becomes `{"sample": 1}`), `Optional`, `Union`, `Literal`, type aliases and standard library
   types such as `Path`, `Decimal` or `datetime`. Classes from the module are built with values
   of their types: dataclasses and `NamedTuple` with their required fields, enums with their
   first member (`list(Color)[0]`).
2. **How the body uses it**: whether it is iterated, indexed, has `.lower()` called on it or has
   a number added to it.
3. **Its name** (`precio` / `price` becomes `100.0`, `email` becomes `"user@example.com"`,
   `path` becomes `"/tmp/test.txt"`...).

Values from 2 and 3 are assumptions, and the test says so in a comment. If they do not fit the
function (`TypeError` or `AttributeError`), the test is skipped with the reason instead of
failing: not knowing how to build a good sample is not a bug in the code. A parameter annotated
with a type that cannot be built does not get a made-up value of another type: its test is
skipped and asks to be completed by hand.

Methods are called on an object built with those same values; `@staticmethod` and
`@classmethod` on the class, and properties are read without calling them. Abstract classes and
`Protocol`s are not instantiated. The suite imports the module by its full name inside the
package (`from app.services.payments import ...`) and adds its root to `sys.path` relative to the
suite, so it works from any directory and with relative imports.

**What is not tested.** Functions that read `sys.argv` or end the process (`sys.exit`,
`raise SystemExit`) are tested through their command line: their test is skipped and says so.
`None` input tests are only generated when the body uses the parameter without checking it and
its type does not allow `None`.

**Side effects.** Everything with side effects is replaced with `autospec` test doubles, so the
generated tests never write, delete, move, spawn processes or open network connections:

- Opening, writing, deleting, moving or renaming files (`open`, `os.remove`, `shutil.rmtree`,
  `Path.unlink`, `Path.write_text`...) and changing permissions.
- Processes (`subprocess`, `os.system`) and network (`requests`, `urllib`, `socket`,
  `http.client`, `httpx`, `aiohttp`).

These are detected however they are imported (`import shutil as sh`,
`from os import remove as rm`) and propagated: if a function calls a module helper (or a method
on `self`) that deletes files, its test replaces that call too. Exceptions raised by those
helpers are propagated as well: the boundary-value test accepts the one a private helper raises
while validating.

- `open()` is replaced with an empty file (`mock_open(read_data="")`): a generic double would
  return another double from `read()`, and a parser might never finish.
- With I/O replaced, the return value is not asserted, since it depends on the doubles. If the
  function cannot process its simulated data (`json.loads` of a double), the test is skipped.
  The I/O failure test is skipped if the function never reaches the I/O with the sample values.
- On top of that, every test runs without network access and with an empty standard input. A
  network call the analysis cannot see, because another module makes it, fails with `OSError`
  as if there were no network, and code reading standard input finds it empty instead of
  waiting forever. Connections to `localhost` still work.

**`--record` safety.** While recording, it blocks writing, deleting, moving, spawning processes
and opening connections, even when that happens in another module. If a function tries, its
result is not recorded and its test replaces those calls. It does not write `__pycache__` into
the project and warns if the module tries to write on import. It is not a sandbox for hostile
code: it is a safety net for ordinary code.

After generating, the command suggests the next step (`agentes test test_app.py` or
`pytest test_app.py`).

---

### `fix`

```text
agentes fix FILE [--dry-run] [--json] [--limit N]
```

Pins the versions in a `requirements.txt` and checks the resulting versions for
vulnerabilities. **It needs network access** (it queries PyPI and OSV); with `--offline` it exits
with `2`.

| Original line           | Result                                                                    |
|-------------------------|---------------------------------------------------------------------------|
| `flask`                 | `flask==<latest published version>`                                       |
| `flask>=2.0`            | `flask==<latest version satisfying >=2.0>`                                |
| `flask~=2.2`            | `flask==<latest 2.x satisfying ~=2.2>`                                    |
| `flask>2.0`             | `flask==<latest version satisfying >2.0>`                                 |
| `flask==2.0.0`          | Unchanged (but its vulnerabilities are checked).                          |

The chosen version is the newest one that satisfies the declaration, is stable (no
pre-releases), has not been yanked and can be installed on your Python version. Environment
markers (`; python_version < "3.11"`) and comments are preserved.

Anything that cannot be resolved (nonexistent package, no version satisfies the range) is left
as is and explained in the "Unchanged" section. A version is never invented.

It then looks up every pinned version, new and old, in OSV and lists vulnerabilities with the
version that fixes them. Versions that were already pinned are not changed: upgrade them
manually to the fixed version shown.

```text
$ agentes fix requirements.txt --dry-run
Proposed changes in requirements.txt
====================================

  - flask>=2.0
  + flask==3.1.3
  ...
```

The exact versions depend on what is published on PyPI when you run it.

| Option      | Effect                                                    |
|-------------|-----------------------------------------------------------|
| `--dry-run` | Show the changes without modifying the file.              |

Returns `1` when any resulting version has a high or critical vulnerability.

---

## Testing

### `test`

```text
agentes test FILE [-v] [--json] [--limit N]
```

Runs a **unittest** suite and reports its results, estimated coverage and quality.

- Runs the file with the unittest loader, in the same process, adding its directory to
  `sys.path` so it can import the module under test. This executes the project's code.
- **Estimated coverage**: which public functions of the module under test have at least one
  test, based on names. It is a name-based estimate, not a measurement of executed lines; use
  `coverage.py` for that.
- **Suite quality**: applies the [test suite quality](#test-suite-quality) rules.

```text
Tests in test_calc.py
=====================
Run        2
Passed     2
Failed     0
Errors     0
Skipped    0
Pass rate  100.0%
Duration   0.001 s

Estimated coverage
  1 of 1 public functions in 'calc' have at least one test (100.0%).
  This is an estimate based on names, not a measurement of executed lines.

[OK] All tests pass.
```

| Option            | Effect                                                     |
|-------------------|------------------------------------------------------------|
| `-v`, `--verbose` | Show the full traceback of each failing test (by default, only the last line). |
| `--limit N`       | Maximum quality findings listed.                           |

Returns `1` when any test fails or errors, or when no test was found. For pytest suites, use
`pytest` directly; `agentes audit test_x.py` reviews the quality of any suite without running it.

---

### `testability`

```text
agentes testability FILE [--matrix] [--json] [--limit N]
```

Detects what makes a module hard to test, without running it: mutable global state,
dependencies created inside functions, I/O mixed with logic and non-deterministic calls. The
rules are in [Testability rules](#testability-rules).

With `--matrix` it adds a matrix of suggested scenarios per function, in up to four categories:

- `HAPPY PATH`: nominal input and output contract.
- `BOUNDARY / EDGE CASE`: zero, `-1`, empty strings, Unicode, `NaN` or infinity, empty
  collections.
- `ADVERSARIAL / ERROR`: null or wrongly typed input, with a controlled error expected.
- `CONCURRENCY / I/O FAULT`: only for functions that do I/O or are `async`. The I/O is mocked to
  fail (or the coroutine times out) and the error must propagate after cleanup.

```text
Suggested test scenarios (17)
  Function       Category                 Scenario and expected result
  get_user       HAPPY PATH               nominal_valid: Runs without raising and returns exactly
                                          the contracted output.
  get_user       BOUNDARY / EDGE CASE     boundary_zero: Handles the extreme boundary (0, -1, empty
                                          or Unicode) without failing silently.
  ...
```

It is informational: it always returns `0`.

---

### `contract`

```text
agentes contract URL [--method M] [--status N] [--schema FILE] [--strict]
                     [--max-ms MS] [--timeout S] [--header 'Name: value'] [--body JSON] [--json]
```

Makes a real HTTP request to an endpoint and checks its contract.

| Option                   | Default     | Effect                                                                  |
|--------------------------|-------------|-------------------------------------------------------------------------|
| `URL`                    |             | Must start with `http://` or `https://`.                                |
| `--method`               | `GET`       | HTTP method.                                                            |
| `--status CODE`          | `200`       | Expected status code.                                                   |
| `--schema FILE`          | none        | JSON file with the expected types in the response.                      |
| `--strict`               | off         | With `--schema`, reject fields that are not in the schema.              |
| `--max-ms MS`            | `500`       | Maximum response time in milliseconds.                                  |
| `--timeout S`            | `5`         | Connection timeout in seconds.                                          |
| `--header 'Name: value'` | none        | Header to send. Can be repeated.                                        |
| `--body JSON`            | none        | Request body. Sent as JSON when it is valid JSON; otherwise as text.    |

Checks shown: `Status Code`, `SLA Latencia` (latency) and, with `--schema`, `Esquema JSON` (JSON
schema). When the request cannot be completed, `HTTP Request` appears as a failure.

**Schema format.** A JSON object with the type of each field:

```json
{"id": "int", "name": "str", "tags": ["str"], "owner": {"email": "str"}}
```

- Supported types: `str` (or `string`), `int` (`integer`), `float` (`number`), `bool`
  (`boolean`), `list` (`array`) and `dict` (`object`).
- A list declares a single type: `["str"]` requires every element to be a string.
- A nested object is declared with another object.
- Matching is strict: `true` does not count as `int`, and an integer such as `10` does not count
  as `float`.

```bash
agentes contract https://api.example.com/health
agentes contract https://api.example.com/users/1 --schema user.json --max-ms 300
agentes contract https://api.example.com/users --method POST \
  --header "Authorization: Bearer $TOKEN" --body '{"name": "Ana"}' --status 201
```

Returns `0` when every check passes and `1` when any fails.

---

## Operations

### `health`

```text
agentes health [--disk PATH] [--min-free-mb MB] [--tcp HOST:PORT] [--http URL]
               [--expect-status CODE] [--json]
```

Checks system health with several probes:

| Probe | Option                          | Default        | Fails when                                            |
|-------|---------------------------------|----------------|-------------------------------------------------------|
| Disk  | `--disk`, `--min-free-mb`       | `/`, 100 MB    | Free space is below the minimum or the path does not exist. |
| Load  | (always)                        |                | Never: informational (one-minute average).            |
| TCP   | `--tcp HOST:PORT`               | no probe       | The connection cannot be opened within 2 seconds.     |
| HTTP  | `--http URL`, `--expect-status` | no probe, 200  | No response within 3 seconds, or an unexpected code.  |

Resulting status:

- `HEALTHY`: every probe is fine.
- `DEGRADED`: an external probe (TCP or HTTP) fails, but the disk is fine.
- `UNHEALTHY`: the disk check fails.

A 4xx or 5xx is a response, not an outage: with `--expect-status 503` (a service in maintenance,
for example) the HTTP probe passes if the server answers 503.

If `/` reports no free space (for example in a container with a read-only file system), the
disk of the current directory is measured instead.

```bash
agentes health
agentes health --tcp localhost:5432 --http https://example.com/healthz
agentes health --disk /var/lib/docker --min-free-mb 2048 --json
```

Returns `0` only when the status is `HEALTHY`.

---

### `sla`

```text
agentes sla --total N --errors N [--max-rate PCT] [--json]
```

Computes the error rate (`errors / total * 100`) and compares it with the maximum allowed
(`--max-rate`, 5% by default). It alerts when the rate **exceeds** the maximum; matching it does
not alert.

```text
$ agentes sla --total 12000 --errors 340
[OK] Error rate 2.83%: within the 5.0% limit.
```

Returns `1` on alert. With `--total 0` there is no rate to evaluate and it returns `0`. If
`--errors` is negative or greater than `--total`, it exits with `2`.

---

### `serve`

```text
agentes serve [--host HOST] [--port PORT]
```

Starts an HTTP server with two endpoints (by default on `127.0.0.1:9100`):

| Path                     | Response                                                                        |
|--------------------------|---------------------------------------------------------------------------------|
| `/metrics`               | Metrics in the Prometheus text format (`text/plain; version=0.0.4`).            |
| `/healthz` (or `/health`)| JSON with the `health` probe results. Status `200` when the status is `HEALTHY` and `503` otherwise. |
| Anything else            | `404` with a JSON body listing the valid paths.                                 |

Exposed metrics:

| Metric                      | Type    | Meaning                                                    |
|-----------------------------|---------|------------------------------------------------------------|
| `app_requests_total`        | counter | Requests handled by the server.                            |
| `app_requests_errors_total` | counter | Requests answered with `404` or `503`.                     |
| `app_uptime_seconds`        | gauge   | Seconds since the process started.                         |

The disk probe behind `/healthz` uses a 1 MB minimum. When listening on every interface
(`--host 0.0.0.0` or `::`) it warns that the server is reachable from the network. If the port is
in use, it exits with `2` and suggests another one. Stop it with Ctrl+C. The former name,
`serve-sre`, still works.

Prometheus configuration:

```yaml
scrape_configs:
  - job_name: agentes
    static_configs:
      - targets: ["localhost:9100"]
```

To try it in a hardened container (read-only, `no-new-privileges`, 256 MB and half a CPU):

```bash
docker compose -f docker-compose.demo.yml up --build
curl http://localhost:9100/metrics
```

---

## Utilities

### `password`

```text
agentes password check|hash|verify [HASH] [--stdin] [--offline] [--json]
```

The password is read interactively without echoing it, so it never ends up in the shell
history. In scripts, `--stdin` reads it from standard input (one line).

#### `password check`

Scores the password from 0 to 6 and looks it up in known breaches.

```text
$ agentes password check --offline
Password (not echoed):
[FAIL] Password is weak (2 of 6 points).
  - It is based on a very common password ('password'): one of the first an attacker tries.
Known breaches (Have I Been Pwned): not checked (no connection or --offline mode).
```

**How it is scored:**

1. **Composition** (up to 6 points): 2 for 12 or more characters (1 for 8 to 11) and 1 for each
   character class present: uppercase, lowercase, digits and symbols.
2. **Passphrases**: with 16 or more characters the minimum score is 5, and with 20 or more it is
   6, even without symbols or digits.
3. **Penalties** for what an attacker tries first:
   - A very common base word, including substitutions (`P4ssw0rd`, `Adm1n`, `Qwerty2024!`):
     capped at 2 points. The list covers English and Spanish words.
   - A keyboard or alphabetical sequence of 4 or more characters (`qwer`, `1234`, `abcd`): -2.
   - Repetition (`aaaa`, `abcabc`): -1, capped at 1 point when it is a short repeated block.
   - A year between 1950 and 2049: -1.

| Points | Rating                 |
|--------|------------------------|
| 6      | `strong`               |
| 5      | `acceptable`           |
| 0 to 4 | `weak`                 |

`Password123!` satisfies every composition rule and is still rated weak.

It also queries [Have I Been Pwned](https://haveibeenpwned.com/Passwords) using k-anonymity: only
the first 5 characters of the SHA-1 hash are sent, never the password. Returns `0` when the
password is acceptable or strong and does not appear in breaches; `1` otherwise.

#### `password hash`

Asks for the password twice and writes the hash to standard output (and only the hash, so you
can capture it). Warnings (weak password, breached password, PBKDF2 in use) go to standard error.

| Backend | When                                  | Hash format                                           |
|---------|---------------------------------------|-------------------------------------------------------|
| Argon2  | `argon2-cffi` installed               | `argon2:$argon2id$v=19$...`                           |
| bcrypt  | `bcrypt` installed, no `argon2-cffi`  | `bcrypt:$2b$12$...`                                   |
| PBKDF2  | Neither installed                     | `pbkdf2:sha256:600000:<base64 salt>:<base64 hash>`    |

PBKDF2-HMAC-SHA256 uses 600,000 iterations, the OWASP-recommended minimum, and a random 16-byte
salt.

```bash
agentes password hash > hash.txt
```

#### `password verify`

```bash
agentes password verify 'argon2:$argon2id$v=19$m=65536,t=3,p=4$...'
```

Quote the hash with single quotes so the shell does not expand the `$` signs. Returns `0` when the
password matches and `1` when it does not. The comparison runs in constant time. When the hash is
PBKDF2 with fewer iterations than recommended, or PBKDF2 while Argon2 or bcrypt is available, it
warns that the hash should be regenerated. Verifying an Argon2 or bcrypt hash requires the
corresponding package.

---

### `demo`

```text
agentes demo AGENT|all
```

Runs the demo of one agent (`defensive`, `quality`, `hardening`, `refactor`, `qa`, `sre`,
`devops` or `docs`) with sample data; `all` runs every demo. `agentes qa` is the same as
`agentes demo qa`.

Demos write sample files (reports, generated tests, configurations). Where:

1. If `AGENTES_WORKDIR` is set, in `$AGENTES_WORKDIR/<agent>`.
2. In a clone of the repository, next to the agent's `main.py` (those files are in `.gitignore`).
3. In a read-only install, in `./<agent>` under the current directory.

```bash
AGENTES_WORKDIR=/tmp/agentes-demo agentes demo all
```

### `list`

Lists the eight agents with their package and a description.

### `doctor`

Checks the installation: Python version, PyYAML, Bandit, argon2-cffi, bcrypt and pytest, the
active hashing backend, where demos write and whether color is enabled. See
[Checking the installation](#checking-the-installation). With `--json` it returns the same data
in structured form.

### `help`

`agentes help` shows the start screen with every command; `agentes help COMMAND` is the same as
`agentes COMMAND -h`.

---

## Rule catalog

Each table gives the condition that triggers the rule, its severity and notes.

### Static analysis (AST engine)

Rule in reports: `SAST-<LEVEL>` (for example `SAST-HIGH`).

| Condition                                                                  | Severity | Notes                                               |
|----------------------------------------------------------------------------|----------|-----------------------------------------------------|
| Call to `eval()` or `exec()`                                               | CRITICAL |                                                     |
| `pickle.loads()`                                                           | CRITICAL | Deserialization of untrusted data.                  |
| `os.system()` or `os.popen()`                                              | CRITICAL | Command injection.                                  |
| `subprocess.Popen/run/call` with `shell=True`                              | HIGH     |                                                     |
| `yaml.load()` without `SafeLoader` or `CSafeLoader`                        | HIGH     | Use `yaml.safe_load`.                               |
| `execute()` or `executemany()` with SQL built with `+`, `%`, an f-string or `.format` | HIGH | Use query parameters.                        |
| `requests` or `httpx` with `verify=False`                                  | HIGH     | Unverified TLS.                                     |
| A secret written in code: assignment, annotation, dictionary key or keyword argument (`password=`, `api_key=`, `token`...) | HIGH | Not applied to test files. Ignores values shorter than 8 characters, empty, `<...>`, `$VAR`, `{...}` and fillers such as `changeme`, `your-...`, `example`, `dummy`, `xxxx`. |
| `random.*` used to produce sensitive material (variables named with `password`, `token`, `secret`, `nonce`, `salt`, `otp`...) | HIGH | Use the `secrets` module. |
| Bare `except:`                                                             | HIGH     | Also catches `SystemExit` and `KeyboardInterrupt`.  |
| `except Exception: pass` (or `...`)                                        | MEDIUM   | Calibrated: reliability, not security.              |
| `except Exception:` that discards the error                                | MEDIUM   | Not flagged if it re-raises (`raise`) or logs the traceback (`logger.exception`, `exc_info=True`). |
| `except Exception as e:` that uses `e` (reports or stores it)              | LOW      | Common at a boundary: CLI, SDK, thread.             |
| `hashlib.md5()` or `hashlib.sha1()` without `usedforsecurity=False`        | MEDIUM   | If it protects nothing (cache, checksums), pass `usedforsecurity=False`. |
| `requests` or `httpx` without `timeout`                                    | MEDIUM   | Risk of hanging forever.                            |
| `urllib.request.urlopen` without `timeout`                                 | MEDIUM   | The import is resolved: another library's `urlopen` does not count. |
| Blocking call (`requests`, `urlopen`, `time.sleep`) inside `async def`     | MEDIUM   |                                                     |
| `open()` outside a `with` block                                            | MEDIUM   | Not flagged when closed in a `finally`, in every `except` plus the `else`, or via `ExitStack.enter_context`. |
| `open()` with a path built from an f-string, `+` or `%`                    | MEDIUM   | Validate the path against path traversal.           |
| `os.path.exists()` or `isfile()` followed by `open()` for writing on the same variable | MEDIUM   | TOCTOU race condition. Reading after the check is not flagged. |
| Jinja `render` or `from_string`                                            | MEDIUM   | Review autoescaping.                                |
| Function with more than 5 arguments                                        | MEDIUM   | Not counting `self` and `cls`.                      |
| Mutable default argument (list, dict or set)                               | MEDIUM   | Use `None`.                                         |
| Public function without a docstring                                        | LOW      | Not applied to test files or `_private` functions.  |
| `assert` outside tests                                                     | LOW      | `python -O` strips `assert` statements.             |

Test files are `test_*.py`, `*_test.py` and `conftest.py`.

**Bandit.** When installed, its findings are added with a `[bandit]` prefix and its own
severity. See the [Bandit documentation](https://bandit.readthedocs.io) for its rule list.

**Merging and calibration.** Bandit, the AST engine and the SOLID auditor sometimes detect the
same thing on the same line. Those findings are grouped by topic (swallowed exceptions, broad
except, weak hash, `eval`/`exec`, shell, `pickle`, `yaml.load`, `assert`, SQL) and merged into
one: the AST engine's message is kept, with the most severe level of the group and an "Also detected by"
note. Severity is then calibrated per topic: swallowing
exceptions and MD5/SHA-1 become `MEDIUM` and `assert` becomes `LOW`; `eval`, `pickle` and
`shell=True` keep theirs.

### Secret detection

Rule: `SECRET`. Every secret is `HIGH`. An unreadable file produces `SECRET-SCAN-ERROR` at level
`ERROR`.

**Provider patterns** (virtually no false positives; applied to every file, tests included):

| Provider or kind               | Recognized form                                          |
|--------------------------------|----------------------------------------------------------|
| AWS                            | `AKIA...` and `ASIA...` keys (20 characters) and 40-character secret keys assigned to an `aws_*secret*` variable. |
| GitHub                         | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` and `github_pat_`. |
| Slack                          | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-` and `xoxs-` tokens and `hooks.slack.com/services/...` webhooks. |
| Stripe                         | `sk_live_`, `sk_test_`, `rk_live_` and `rk_test_`.       |
| Google                         | `AIza...` API keys.                                      |
| Anthropic                      | `sk-ant-...`.                                            |
| OpenAI                         | `sk-...` (20 or more characters).                        |
| SendGrid                       | `SG.xxx.yyy`.                                            |
| npm, PyPI, GitLab              | `npm_...`, `pypi-...` and `glpat-...`.                   |
| Private key                    | `-----BEGIN ... PRIVATE KEY-----` header.                |
| JWT                            | Three base64url segments starting with `eyJ`.            |
| Discord-style token            | Three segments of 24, 6 and 27 characters.               |
| Connection URL                 | `postgres://`, `mysql://`, `mongodb://`, `mongodb+srv://`, `redis://`, `amqp://` or `ftp://` with a user and password. |
| Authorization header           | `Authorization` or `Proxy-Authorization` with `Basic` or `Bearer` and a value of 16 or more characters. |

**Generic patterns**: a key with a credential-like name (`api_key`, `secret`, `password`,
`passwd`, `passphrase`, `token`, `auth_token`, `credential`, `access_key`, `client_secret`,
`private_key` and variants) assigned a quoted value, in Python, JSON, YAML or similar syntax. To
avoid false positives, generic patterns:

- Are not applied to test files.
- Ignore values shorter than 8 characters, empty, `<...>`, `{{...}}`, `%s`, `$VAR` or `${VAR}`,
  values starting with `your-`, `my-` or `tu-`, values containing `example`, `placeholder`,
  `changeme`, `dummy`, `sample`, `fake`, `redacted`, `todo`... and the values `none`, `null`,
  `true`, `false`, `test` or `demo`.
- Ignore keys that name a field (`password_field`, `token_name`, `secret_label`...) and keys
  whose value equals their name.

In every case comment lines (`#`, `//`, `-- `, `;`, `/*`, `* `) are skipped and only one finding
is reported per line, from the most specific pattern.

### Dockerfile

Rule: `DOCKERFILE`.

| Condition                                              | Severity | Line  |
|--------------------------------------------------------|----------|-------|
| No `USER` instruction with a non-root user             | HIGH     | 0     |
| `USER root` or `USER 0`                                | HIGH     | yes   |
| `USER` without a user                                  | HIGH     | yes   |
| `FROM` without an image                                | HIGH     | yes   |
| `sudo` or `chmod 777`                                  | HIGH     | yes   |
| `FROM` with `:latest` or no version tag                | MEDIUM   | yes   |

### systemd

Rule: `SYSTEMD`. Commented-out lines are ignored: a commented directive protects nothing.

| Directive          | Expected value     | Severity when missing or disabled     |
|--------------------|--------------------|---------------------------------------|
| `NoNewPrivileges`  | `true`             | HIGH                                  |
| `ProtectSystem`    | any active value (`strict`, `full`, `true`) | MEDIUM       |
| `ProtectHome`      | `true`             | MEDIUM                                |
| `PrivateTmp`       | `true`             | LOW                                   |

A directive counts as disabled with `false`, `no`, `off`, `0` or an empty value.

### YAML and Kubernetes

| Condition                                                        | Rule      | Severity |
|------------------------------------------------------------------|-----------|----------|
| YAML that PyYAML cannot read, with the line of the error         | `YAML`    | HIGH     |
| Pod without `spec.securityContext.runAsNonRoot: true`            | `K8S-POD` | HIGH     |
| Container without `allowPrivilegeEscalation: false`              | `K8S-POD` | HIGH     |
| Container without `readOnlyRootFilesystem: true`                 | `K8S-POD` | MEDIUM   |
| Container without `capabilities.drop: [ALL]`                     | `K8S-POD` | MEDIUM   |

A tab is only an error where YAML does not allow it (in indentation or as a separator); in
comments, inside quotes or in a literal block it is valid.

The security context is checked in `Pod` documents (rule `K8S-POD`) and in the ones that create
pods: `Deployment`, `StatefulSet`, `DaemonSet`, `ReplicaSet`, `ReplicationController`, `Job` and
`CronJob` (rule `K8S-WORKLOAD`). In a multi-document file each one is checked.

### HTTP headers

Rule: `HTTP-HEADERS`. Each missing header is flagged:

| Header                      | Severity | Recommended value                                    |
|-----------------------------|----------|------------------------------------------------------|
| `Content-Security-Policy`   | HIGH     | `default-src 'self'; script-src 'self'; object-src 'none';` |
| `X-Frame-Options`           | HIGH     | `DENY`                                               |
| `X-Content-Type-Options`    | MEDIUM   | `nosniff`                                            |
| `Strict-Transport-Security` | MEDIUM   | `max-age=31536000; includeSubDomains; preload`       |
| `Referrer-Policy`           | MEDIUM   | `strict-origin-when-cross-origin`                    |
| `Permissions-Policy`        | MEDIUM   | `geolocation=(), microphone=(), camera=()`           |

### `.env` files

Rule: `ENV`.

| Condition                                                                 | Severity |
|---------------------------------------------------------------------------|----------|
| `DEBUG` or `TESTING` set to `true`, `1` or `yes`                          | HIGH     |
| A key containing `secret`, `key`, `token` or `password` with the value `admin`, `123456`, `secret`, `changeme`, `default` or `root` | HIGH |
| The same kind of key with a value shorter than 16 characters              | MEDIUM   |

Empty values mean "not defined" and are not flagged. In templates (`.env.example`...) only
`DEBUG`/`TESTING` enabled is reported, as `LOW`.

### Logs

Rule: `LOG`. The first matching pattern on each line is reported, with a snippet of up to 80
characters.

| Pattern                                                                | Severity |
|------------------------------------------------------------------------|----------|
| `Traceback (most recent call last)`                                    | CRITICAL |
| `MemoryError`, `OutOfMemoryError` or `Out of memory`                   | CRITICAL |
| HTTP 5xx response (`HTTP/1.1" 500`...)                                  | HIGH     |
| `ConnectionRefusedError`, `DatabaseConnectionError` or `TimeoutError`  | HIGH     |
| `Authentication failed`, `Invalid password` or `Failed login`          | MEDIUM   |

### Declared dependencies

| File                | Condition                                 | Rule       | Severity |
|---------------------|-------------------------------------------|------------|----------|
| `requirements*.txt` | No version                                | `DEPS-PIP` | MEDIUM   |
| `requirements*.txt` | `>=` or `~=`                              | `DEPS-PIP` | LOW      |
| `package.json`      | Version with `^`, `~` or `*`              | `DEPS-NPM` | MEDIUM   |
| `package.json`      | Invalid JSON                              | `DEPS-NPM` | ERROR    |

A `>=` or `~=` is not flagged when the `pyproject.toml` in the same directory declares that
dependency: the requirements.txt copies the package's contract, and a library must not pin exact
versions. To pin them in an application, use a lock file or `agentes fix`.

Known vulnerabilities are a separate rule (`VULN-<id>`), described in [`vulns`](#vulns). When a
manifest cannot be read during that lookup, it is reported as `VULN-READ-ERROR` at level `ERROR`.

### SOLID and design

Rule: `SOLID-<principle>`.

| Principle            | Condition                                                          | Severity |
|----------------------|--------------------------------------------------------------------|----------|
| `SRP`                | Class with more than 10 methods                                    | MEDIUM   |
| `OCP`                | Function with more than 12 `if/elif` branches (the ruff and pylint threshold) | MEDIUM |
| `DIP`                | Direct instantiation of a class inside `__init__`                  | LOW      |
| `GUARD`              | More than 3 levels of nesting                                      | MEDIUM   |
| `STATE-SAFETY`       | Mutable default argument                                           | HIGH     |
| `STATE-SAFETY`       | Use of `global`                                                    | MEDIUM   |
| `EXCEPTION-HYGIENE`  | Bare `except:`                                                     | HIGH     |
| `EXCEPTION-HYGIENE`  | `except` that only does `pass` or `...`                            | HIGH (MEDIUM in the pipeline) |
| `EXCEPTION-HYGIENE`  | Broad catch that silently returns `None`                           | HIGH (MEDIUM in the pipeline) |
| `EXCEPTION-HYGIENE`  | `raise NewException()` inside `except` without `from exc`          | HIGH     |
| `DATA-CONTRACT`      | `@dataclass` without `slots=True`                                  | LOW      |

In the pipeline these findings do not change the exit code.

### Performance

Rule: `PERF`. In the pipeline every one is recorded as `MEDIUM`; in `metrics` they keep the
severity in this table.

| Condition                                                                     | Severity |
|-------------------------------------------------------------------------------|----------|
| `in` lookup on a list or tuple literal inside a loop                          | HIGH     |
| `.pop(0)` or `.insert(0, ...)` inside a loop (use `collections.deque`)        | HIGH     |
| `re.compile()` with the same pattern on every iteration of a loop             | HIGH     |
| Blocking call inside `async def`                                              | HIGH     |
| HTTP request inside a loop (N+1 pattern)                                      | HIGH     |
| Database operation inside a loop (N+1 pattern)                                | HIGH     |
| String concatenation `s += ...` inside a loop                                 | MEDIUM   |
| `.readlines()` (loads the whole file into memory)                             | MEDIUM   |

`.pop(0)` and `.insert(0, ...)` outside a loop are not flagged, nor is prepending a path to
`sys.path`. `re.compile` inside a loop is not flagged when the pattern changes on each iteration.
`in` over a few constants (up to 8) or over values that change on each iteration is not flagged
either.

### Test suite quality

Rule: `TEST-QUALITY`. Applied by `test` and by `audit` on test files.

| Code              | Condition                                                                   | Severity |
|-------------------|-----------------------------------------------------------------------------|----------|
| `WEAK-ASSERT`     | Test without any assertion (except tests marked *skip*)                     | HIGH     |
| `WEAK-ASSERT`     | `assert True`, `assertTrue(True)` or a comparison of two equal constants    | HIGH     |
| `GENERIC-RAISES`  | `assertRaises(Exception)` or `pytest.raises(Exception)` (also `BaseException`) | HIGH  |
| `GENERIC-RAISES`  | `pytest.raises(...)` without `match=`                                       | MEDIUM   |
| `UNISOLATED-IO`   | Real call to `requests.*`, `urllib.request.*`, `urlopen`, `sqlite3.*` or `time.sleep` in a test without `patch`, `monkeypatch` or `Mock` | HIGH |
| `UNSAFE-MOCK`     | `Mock()` or `MagicMock()` without `spec` or `spec_set`                      | MEDIUM   |
| `UNSAFE-MOCK`     | `patch()` without `autospec`, `spec`, `spec_set` or `new`                   | MEDIUM   |
| `UNSAFE-MOCK`     | `patch` or `patch.object` on a private member (`_something`)                | MEDIUM   |

### Testability rules

Rule: `TESTABILITY`. Applied by `testability`.

| Code                | Condition                                                                    | Severity |
|---------------------|------------------------------------------------------------------------------|----------|
| `GLOBAL-STATE`      | `global` inside a function, or mutation of a module-level variable (`CACHE[k] = v`, `ITEMS.append(x)`) | HIGH |
| `MIXED-IO`          | A function that mixes logic (conditions, loops, operations) with direct I/O  | HIGH     |
| `NON-DETERMINISTIC` | `time.time`, `time.monotonic`, `time.perf_counter`, `time.sleep`, `datetime.now`, `datetime.utcnow`, `date.today`, `uuid.uuid4`, `random.*` or `os.getenv` | MEDIUM |
| `NON-DETERMINISTIC` | Direct read of `os.environ[...]`                                             | MEDIUM   |
| `HARDCODED-DEP`     | A function creates a collaborator instead of receiving it. Recognized by the class name: words such as `Client`, `Service`, `Repository`, `Session`, `Engine`, `Connection`, `Database`, `Cache`, `Gateway` or `Adapter` (`UserRepository()`, `HttpClient()`) | MEDIUM |

---

## Reports and formats

### `pipeline.json`

Schema `agentes.pipeline.v1`. Top-level fields:

| Field           | Type    | Content                                                           |
|-----------------|---------|-------------------------------------------------------------------|
| `schema`        | string  | `"agentes.pipeline.v1"`.                                          |
| `target`        | string  | Absolute path analyzed.                                           |
| `timestamp`     | string  | UTC date and time in ISO 8601.                                    |
| `status`        | string  | `"ok"` or `"fail"`.                                               |
| `exit_code`     | integer | `0` or `1`.                                                       |
| `stages`        | list    | One entry per stage, in order.                                    |
| `python_files`  | integer | `.py` files found.                                                |
| `files_scanned` | integer | `.py` files analyzed.                                             |
| `files_skipped` | integer | Files left out by `--max-files`.                                  |
| `findings`      | list    | Every finding (objects with `file`, `line`, `level`, `message`, `rule_id` and `category`). |
| `findings_by_category` | object | How many findings there are in each category: `security` and `quality`. |
| `inline_suppressed` | integer | Findings [silenced on their line](#silencing-a-finding-on-its-line). |
| `baseline`      | object  | Only with `--baseline`: `file`, `suppressed` (accepted) and `unused` (entries that no longer appear). |
| `artifacts`     | object  | Paths of `json`, `html` and `sarif`.                              |

Each stage has `name`, `status` (`ok`, `fail` or `skipped`), `summary` and
`findings_count`, plus its own fields:

| Stage               | Extra fields                                                                    |
|---------------------|---------------------------------------------------------------------------------|
| `quality_sast`      | `files_scanned`, `files_total`, `files_skipped`, `engine` (`"bandit+ast"` or `"ast"`). |
| `defensive_secrets` | `scan_errors`, `extra_config_files`, `files_scanned`, `files_total`, `files_skipped`. |
| `refactor_metrics`  | `files_analyzed`, `metrics` (lines, comments, functions, average complexities), `recommendations`, `errors`. |
| `documentation`     | `files_analyzed`, `frameworks`, `errors`.                                       |
| `infra_and_deps`    | `files_scanned`.                                                                |
| `dependency_vulns`  | `manifests`, `environments`, `dependencies_checked`, `dependencies_unpinned`, `installed_packages`, `blocked_fixes`. |

Examples with `jq`:

```bash
jq '.stages[] | {name, status, summary}' reports/pipeline.json
jq '[.findings[] | select(.level == "HIGH" or .level == "CRITICAL")] | length' reports/pipeline.json
jq -r '.findings[] | "\(.level)\t\(.file):\(.line)\t\(.rule_id)"' reports/pipeline.json
```

### `pipeline.sarif` and `analyze.sarif`

SARIF 2.1.0 with a single run. Tool: `AGENTES-Pipeline` or `AGENTES-Analyze`. Each finding is a
result with `ruleId`, message and location (path relative to the project root with `/`
separators, and line; `1` when the finding has no line). Severity mapping:

| Severity                       | SARIF level |
|--------------------------------|-------------|
| `CRITICAL`, `HIGH`, `ERROR`     | `error`     |
| `MEDIUM`                        | `warning`   |
| `LOW`                         | `note`      |

Each rule carries the `security` or `maintainability` tag in `properties.tags`. Security rules
also carry `security-severity` (9.5 critical, 8.0 high, 5.5 medium, 2.0 low), which is what
GitHub Code Scanning uses to classify them as security alerts and rate them.

GitHub Code Scanning, Visual Studio Code (SARIF Viewer extension) and other tools read this
format directly.

### `pipeline.html`

A self-contained page (no external resources) with the stage table and the findings table
(file, line, level, type, rule and message). All content coming from the analyzed project is escaped.

### `--json` output of each command

| Command       | Main fields                                                                       |
|---------------|-----------------------------------------------------------------------------------|
| `pipeline`    | The full report described above.                                                  |
| `analyze`     | `target`, `files`, `findings`, `inline_suppressed`, `vulnerability_check`, `artifacts`. |
| `secrets`     | `target`, `files_scanned`, `findings`, `inline_suppressed`.                       |
| `vulns`       | `target`, `manifests`, `environments`, `status` (`ok`, `fail` or `unchecked`), `dependencies_checked`, `dependencies_unpinned`, `installed_packages`, `findings`, `inline_suppressed`, `blocked_fixes`. |
| `audit`       | `target`, `kind`, `files`, `findings`, `inline_suppressed`.                       |
| `metrics`     | `target`, `totals`, `files`, `functions`, `findings`, `recommendations`, `inline_suppressed`. |
| `fix`         | `file`, `dry_run`, `corrections`, `changes`, `unresolved`, `vulnerabilities`, `vulnerability_check_error`. |
| `test`        | `tests_run`, `passed`, `failures`, `errors`, `skipped`, `pass_rate_percentage`, `duration_seconds`, `failure_details`, `coverage`. |
| `testability` | `file`, `findings`, `scenarios`.                                                  |
| `contract`    | `passed`, `elapsed_ms`, `assertions` and response data.                           |
| `health`      | `status`, `checks` (one entry per probe), `probe_duration_ms` and system data.    |
| `sla`         | `total`, `errors`, `error_rate_pct`, `max_rate_pct`, `alert`.                     |
| `password`    | `check`: `score`, `max_score`, `strength`, `feedback`, `breaches`. `hash`: `hash`, `backend`, `score`, `breaches`. `verify`: `valid`, `needs_rehash`. |
| `doctor`      | `version`, `checks`, `crypto_backend`, `workdir`.                                 |

In `breaches`, `null` means it could not be checked (offline) and `0` means the password does not
appear in breaches.

---

## Baseline

A baseline lets you adopt Work-Agents in a project that already has findings, or that contains test
data that looks like them (such as a corpus of fake secrets): CI fails only on new ones.

### Creating it

```bash
agentes pipeline . --write-baseline .agentes-baseline.json
```

```text
[OK] Baseline written to .agentes-baseline.json: 4 findings accepted.
The 2 medium or low findings are not stored, because they never fail the pipeline.
Review the file before committing it: everything it lists will stop failing the analysis.
```

Only findings that would fail the analysis are saved: blocking findings and every secret. Medium
and low findings are not needed.

### Using it

```bash
agentes pipeline . --baseline .agentes-baseline.json
```

Accepted findings do not count toward stage status or the exit code, and they do not appear in
the list or the reports. The console says how many were accepted:

```text
Baseline .agentes-baseline.json: 3 accepted findings are not counted.
  1 entries no longer match anything: regenerate the baseline to drop them.
```

### How findings are identified

Each finding is identified by a fingerprint (the first 20 characters of a SHA-256) of its rule,
its file relative to the root and its message with line numbers removed. Therefore:

- The baseline stays valid when code moves around.
- If the message changes (for example, a different variable holding a different secret), the
  finding is new.
- If the same finding appears more times than recorded, the extra occurrences are new.

### Format

```json
{
  "schema": "agentes.baseline.v1",
  "generated_by": "agentes 3.2.3",
  "note": "Reviewed and accepted findings. Regenerate with: agentes pipeline . --write-baseline <file>",
  "entries": [
    {
      "fingerprint": "930d4decba31c0168a75",
      "rule_id": "SAST-HIGH",
      "file": "app/main.py",
      "level": "HIGH",
      "message": "Subprocess started with 'shell=True' (command injection risk)."
    }
  ]
}
```

Only `fingerprint` matters; the other fields help you review the file. To stop accepting a
finding, delete its entry or regenerate the file.

### Good practices

- **Review it before committing it.** Everything in it stops blocking.
- Regenerate it when the console reports unused entries, so it does not accept a finding that
  was already fixed if it comes back.
- The file contains masked fragments of the accepted secrets. With `--baseline` the pipeline
  excludes it from the secret scan; without that option, or with `agentes secrets`, it is scanned
  like any other JSON file (see [Troubleshooting](#secrets-flags-the-baseline)).
- This repository uses its own (`.agentes-baseline.json`) in CI to audit itself.

---

## Silencing a finding on its line

To accept one specific finding and keep the reason next to the code, add a comment on the line
the finding points to:

```python
result = eval(expr)  # agentes: ignore[dynamic-exec] - the expression is validated first
except Exception:  # agentes: ignore - SDK boundary, every error is reported
```

- `# agentes: ignore` silences everything flagged on that line.
- `# agentes: ignore[RULE, ...]` silences only the listed rules. Each one can be the `rule_id`
  from the JSON (`SECRET`, `SOLID-GUARD`, `DEPS-PIP`...) or its prefix (`SAST`, `SOLID`, `K8S`),
  the SARIF `ruleId`, which is what GitHub Code Scanning shows (`SAST-SHELL`, `SAST-TOCTOU`...),
  or the rule name: `broad-except`, `bare-except`, `exception-swallow`,
  `mutable-default`, `blocking-async`, `weak-hash`, `dynamic-exec`, `shell`, `pickle`,
  `yaml-load`, `assert`, `sql`, `docstring`, `too-many-args`, `open-without-with`, `toctou`,
  `path-traversal`, `no-timeout`, `tls-verify`, `jinja`, `insecure-random`, `hardcoded-secret`,
  `global-state` and `too-many-branches`.

ruff/flake8 and Bandit comments are honoured too when their code matches one of the rules, so the
same justification does not have to be written twice:

| Comment                 | Silences                                                       |
|-------------------------|----------------------------------------------------------------|
| `# noqa: BLE001`        | `except Exception` (other codes too: `E722`, `B006`, `S602`, `PLR0913`, `D103`...) |
| `# noqa` without codes  | Nothing: it is usually there for another tool and would hide security findings. |
| `# nosec B602`          | The matching Bandit rule (`B101`, `B307`, `B324`, `B608`...).  |
| `# nosec` without codes | All static analysis (SAST) on the line, as in Bandit, but not secrets. |

A secret is only silenced explicitly, with `# agentes: ignore` or `# agentes: ignore[SECRET]`.

Silenced findings do not count towards the stage status or the exit code and do not appear in the
reports, but the console says how many there are and the JSON counts them in `inline_suppressed`:

```text
4 findings suppressed inline (# agentes: ignore, noqa or nosec) are not shown.
```

Findings without a line (a whole file, a Kubernetes document, an HTTP header) can only be accepted
with the [baseline](#baseline). In the pipeline, findings silenced on their line are removed
before the baseline is applied.

---

## Continuous integration

### GitHub Actions

```yaml
name: Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write        # required to upload SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install "git+https://github.com/kahz12/Work-Agents.git"
      - run: agentes pipeline . -o reports --baseline .agentes-baseline.json
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/pipeline.sarif
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: audit
          path: reports/
```

- `if: always()` uploads the report even when the previous step fails because of findings.
- Findings appear in the Security tab and as annotations on pull requests.
- To install Bandit, use
  `pip install "agentes-devsecops[sast] @ git+https://github.com/kahz12/Work-Agents.git"`. Whatever
  engine you used to generate the baseline, use it in CI as well (this repository uses
  `--no-bandit` in both), because Bandit and the AST engine do not produce exactly the same
  findings.

### GitLab CI

```yaml
audit:
  image: python:3.12-slim
  script:
    - pip install "git+https://github.com/kahz12/Work-Agents.git"
    - agentes pipeline . -o reports --baseline .agentes-baseline.json
  artifacts:
    when: always
    paths:
      - reports/
```

### Local pre-commit hook

A `.git/hooks/pre-commit` that prevents committing secrets:

```bash
#!/bin/sh
agentes secrets . --no-color || {
  echo "Possible secrets found. Review the output above before committing."
  exit 1
}
```

Make it executable with `chmod +x .git/hooks/pre-commit`.

### Recommendations

- Use `--offline` for runs that must not depend on the network, and a separate job with network
  access for vulnerabilities (`agentes vulns .`).
- Keep `reports/` as an artifact to review the HTML.
- Use `--json` and `jq` to build your own gating rules.

---

## Library usage

The agents are Python packages you can import. The main interface is the CLI; this section shows
the most useful classes. Every example was tested with version 3.2.3.

### Running the pipeline

```python
from agentes.common.orchestrator import run_pipeline

report, exit_code = run_pipeline(
    "./my_project",
    output_dir="./reports",          # None: <project>/reports
    fail_on_high=True,               # False is the same as --no-fail
    max_files=None,
    prefer_bandit=False,             # False is the same as --no-bandit
    check_vulnerabilities=False,     # False: no OSV. None: query unless AGENTES_OFFLINE=1
    baseline=None,                   # path to a baseline
)
print(report["status"], len(report["findings"]))
```

### Individual audits

```python
from agentes.common import audits

for f in audits.audit_file("Dockerfile"):          # type inferred from the name
    print(f.level, f.rule_id, f.line, f.message)

audits.audit_file("my.conf", "systemd")             # explicit type
audits.scan_secrets("app/settings.py")              # list of Finding
audits.sast(["app/main.py"], prefer_bandit=False)   # static analysis
```

Each result is an `agentes.common.findings.Finding` with `file`, `line`, `level`, `message`,
`rule_id`, the `blocking` and `silent` properties, and `to_dict()`.

### Passwords, tokens and permissions

```python
from agentes.defensive.auth_manager import AuthManager, RateLimiter

h = AuthManager.hash_password("correct horse battery staple")
AuthManager.verify_password("correct horse battery staple", h)     # True
AuthManager.needs_rehash(h)                                          # False
AuthManager.evaluate_password_strength("Password123!")
# (2, ["It is based on a very common password ('password'): ..."])

# Anti-CSRF token bound to the session (30 minutes by default)
token = AuthManager.create_csrf_token(secret_key, "session-1")
AuthManager.verify_csrf_token(token, secret_key, "session-1")       # True

# HMAC-signed token (1 hour by default)
tok = AuthManager.create_secure_token({"sub": "ana"}, secret_key)
ok, payload, reason = AuthManager.verify_secure_token(tok, secret_key)

# RBAC
AuthManager.check_permission(["editor"], "write", {"editor": ["read", "write"]})   # True

# In-memory sliding-window rate limiting
limiter = RateLimiter(max_requests=5, window_seconds=60)
limiter.is_allowed("203.0.113.7")
```

Use a long random `secret_key` (for example `secrets.token_hex(32)`), never one written in code.

### Input validation

```python
from agentes.defensive.input_sanitizer import InputSanitizer

InputSanitizer.sanitize_html("<script>x</script>")       # '&lt;script&gt;x&lt;/script&gt;'
InputSanitizer.validate_safe_path("/srv/data", "../etc/passwd")   # None: outside the base directory
InputSanitizer.validate_email("ana@example.com")         # True
InputSanitizer.sanitize_integer("42", min_val=0, max_val=100)     # 42
InputSanitizer.validate_json_schema(
    {"id": 1, "tags": ["a"]}, {"id": int, "tags": [str]}, reject_extra_keys=True,
)                                                         # (True, [])
```

### Structured logging and probes

```python
from agentes.sre.structured_logger import StructuredLogger
from agentes.sre.health_checker import SystemHealthChecker
from agentes.sre.alerting_engine import AlertingEngine

log = StructuredLogger("api")
print(log.info("login", {"user": "ana", "password": "x"}, trace_id="t-1"))
# {"timestamp": "...", "service": "api", "level": "INFO", "message": "login",
#  "trace_id": "t-1", "context": {"user": "ana", "password": "***MASKED***"}}

SystemHealthChecker.check_health(tcp_host="localhost", tcp_port=5432)["status"]
AlertingEngine.evaluate_error_rate(12000, 340, 5.0)      # (False, "OK: ...")
```

The logger masks the keys `password`, `secret`, `token`, `authorization` and `api_key` at any
depth of the context, and generates a `trace_id` when none is given.

### Generators

```python
from agentes.docs.openapi_generator import OpenAPIGenerator
from agentes.devops.docker_compose_generator import DockerComposeGenerator
from agentes.hardening.k8s_hardening import K8sHardening

spec = OpenAPIGenerator.generate_openapi_spec("app/main.py", title="My API")
OpenAPIGenerator.export_spec_to_yaml(spec, "openapi.yaml")

DockerComposeGenerator.generate_compose_file("docker-compose.yml", service_name="api", port=8000)
yaml_text = K8sHardening.generate_hardened_pod_manifest(name="api", image="myorg/api:1.2.0")
```

---

## Network and privacy

Code analysis is local: no command sends source code anywhere. Three features contact external
services:

| Feature                                                | Service                  | What is sent                                                   |
|--------------------------------------------------------|--------------------------|----------------------------------------------------------------|
| Vulnerabilities (`pipeline`, `analyze`, `vulns`, `fix`) | `api.osv.dev`           | Ecosystem, name and version of each checkable dependency.      |
| Version selection (`fix`)                              | `pypi.org`               | Name of each package.                                          |
| Breached passwords (`password check` and `hash`)       | `api.pwnedpasswords.com` | The first 5 characters of the password's SHA-1 hash.           |

In addition, `audit URL`, `contract`, `health --http` and `health --tcp` connect to the targets
you give them.

`--offline` or `AGENTES_OFFLINE=1` disables the three external lookups:

- The pipeline marks the vulnerability stage as `SKIPPED` and does not fail because of
  it.
- `password` reports that breaches could not be checked.
- `vulns` and `fix`, which make no sense without network access, exit with `2`.

The repository's tests never use the network: they enable offline mode and mock the responses.

---

## Troubleshooting

### The summary says "without Bandit"

Bandit is not installed or not on the environment's `PATH`. Install it with
`pip install -e ".[sast]"`. If you prefer not to use it, add `--no-bandit` and the notice goes
away.

### The vulnerability stage says "not checked"

All your dependencies use ranges (`flask>=2.0`) and there is no virtual environment or lock file.
Solutions, most reliable first:

1. Create the project's environment (`python -m venv .venv` and install the dependencies): the
   installed packages will be checked.
2. Use a lock file (`poetry.lock`, `Pipfile.lock`) or a pinned `requirements.txt`
   (`agentes fix requirements.txt` pins it for you).

### The vulnerability stage is skipped

You are offline, used `--offline`, have `AGENTES_OFFLINE` set, or OSV did not respond. The
summary gives the reason.

### A finding is a false positive

- If it is an example secret, use a value that gives it away (`changeme`, `<your-key>`,
  `${VARIABLE}`) or move it to a test file.
- If it is a hash used for caching or checksums, pass `usedforsecurity=False`.
- If it is a reviewed finding that must stay, add it to a [baseline](#baseline).

### `secrets` flags the baseline

The baseline stores the messages of accepted secrets, with the value masked, and some of those
messages match the patterns again. The pipeline excludes the file when it is passed with
`--baseline`, but `agentes secrets .` (or `agentes pipeline .` without `--baseline`) scans the
whole tree and may flag it. Run `secrets` on the code directories (`agentes secrets src/`) and
always pass `--baseline` to the pipeline.

### `generate` writes nothing

The output already exists. Add `--force` to replace it or choose another path with `-o`.

### `test` finds no tests

`test` runs **unittest** suites (classes that inherit from `unittest.TestCase`). For pytest
suites, use `pytest`.

### The Swagger UI page is blank

It loads Swagger UI from a CDN: it needs internet access.

### `serve` does not start

The port is in use. Pick another one: `agentes serve --port 9200`.

### Colors clutter the output

They turn off automatically when output is redirected. Otherwise use `--no-color` or set
`NO_COLOR=1`.

### Unexpected error

Repeat the command with `AGENTES_DEBUG=1` to see the full traceback and, if it is a bug in the
tool, open an issue with it.

---

## Limitations

- **Python only.** Code analysis is for Python. For the rest of the project, configuration,
  Dockerfiles, manifests and dependencies are reviewed, including `package.json`.
- **Static analysis.** The analysis commands and `generate` read code without importing or
  running it. Only `test` (which runs the given suite) and `generate tests --record` execute
  project code.
- **Heuristics.** Rules look for known patterns; they do not follow data flow across functions.
  A clean result does not guarantee the absence of vulnerabilities.
- **Exact versions.** Vulnerabilities are checked against exact versions: those installed in the
  project's virtual environment and those pinned in manifests or lock files. With only declared
  ranges, the installed version is unknown.
- **Kubernetes.** The security context is only audited in `kind: Pod` documents, not in
  `Deployment` or other controllers.
- **Swagger UI** loads its assets from a CDN.
- **`password`** needs `argon2-cffi` or `bcrypt` to verify hashes in those formats.
