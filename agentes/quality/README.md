# Code Quality and SAST Agent

Static analysis (Bandit + AST), SARIF export, linter configuration and a dependency auto-fixer.

## Layout

- `static_checker.py` — Runs Bandit when installed plus the built-in AST engine: eval/exec, pickle, shell commands, **hardcoded secrets**, SQL built with f-strings or concatenation, assert, Jinja and more. Exports SARIF 2.1.0.
- `dependency_auditor.py` — Audits requirements.txt and package.json, and pins unpinned, `>=` and `~=` dependencies to the newest matching PyPI release.
- `package_index.py` — PyPI version lookup (stable, non-yanked, installable on the running Python).
- `vulnerabilities.py` — Known-vulnerability lookup in OSV for manifests, lock files and installed environments.
- `linter_config.py` — `.flake8`, `pyproject.toml` and ESLint configuration.
- `main.py` — Demo.

## Usage

```bash
agentes demo quality               # demo on sample data
python -m agentes.quality.main     # the same, without going through the CLI
agentes analyze ./src -o ./reports
agentes fix requirements.txt --dry-run
```
