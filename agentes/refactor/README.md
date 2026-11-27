# Refactoring and Architecture Agent

Complexity metrics, SOLID heuristics, refactoring suggestions and Mermaid diagrams.

## Layout

- `code_metrics.py` — Lines of code plus **cyclomatic** and **cognitive** complexity from the AST, and a performance audit (Big-O pitfalls, memory, blocking I/O).
- `solid_checker.py` — SRP / OCP / DIP heuristics plus guard clauses, exception hygiene, state safety and dataclass contracts.
- `refactor_suggester.py` — Recommendations built from the metrics and the SOLID findings.
- `architecture_diagram.py` — **Mermaid.js** class diagram, inheritance included.
- `main.py` — Runnable demo (writes and analyses a sample `sample_monolith.py`).

## Usage

```bash
agentes demo refactor               # demo on sample data
python -m agentes.refactor.main     # the same, without going through the CLI
agentes metrics ./src
agentes generate diagram --source models.py
```
