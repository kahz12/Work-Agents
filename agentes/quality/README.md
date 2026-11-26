# Agente de Calidad de Código y SAST

SAST (Bandit + AST), SARIF, linters y auto-fixer de dependencias.

## Estructura

- `static_checker.py` — Bandit real o AST: eval/exec/pickle/shell, **secretos hardcodeados**, SQL f-string/concat, assert, Jinja. SARIF 2.1.0.
- `dependency_auditor.py` — Audit + auto-fix unpinned/`>=`/`~=` (mapa o PyPI).
- `linter_config.py` — `.flake8`, `pyproject.toml`, ESLint.
- `main.py` — Demo.

## Uso

```bash
agentes demo quality               # demo con datos de ejemplo
python -m agentes.quality.main     # lo mismo, sin pasar por el CLI
agentes analyze ./src -o ./reports
agentes fix requirements.txt --dry-run
```

