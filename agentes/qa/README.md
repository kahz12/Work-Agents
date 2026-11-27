# QA and Test Automation Agent

Generates unit tests with real assertions, runs them, checks API contracts (offline and over real HTTP) and writes QA reports.

## Layout

- `test_generator.py` — Public facade (`QATestGenerator`) that combines `ast_inspector.py`, `testability.py`, `sample_values.py` and `emitters.py` to generate `unittest` or adversarial `pytest` suites.
- `ast_inspector.py` — AST analysis of signatures, raised exceptions and I/O propagation (`UnitTestGenerator`).
- `call_plan.py` — Works out how each generated test calls its target: sample values, constructor arguments, patched I/O.
- `expected_values.py` — Expected results computed from the function body, or recorded by running it with `--record`.
- `side_effects.py` / `project.py` — Side-effect detection and lookup of the project modules the analysed file imports.
- `testability.py` — Architectural testability audit (`TestabilityAuditor`).
- `sample_values.py` — Sample values, boundary cases and the QA scenario matrix.
- `emitters.py` — `unittest` and `pytest` suite emitters.
- `test_runner.py` — Runs a suite and reports duration, pass rate, tracebacks and suite quality.
- `api_contract_testing.py` — Validates status, JSON schema (through `common.schema`) and SLA; `request_and_validate()` performs a real HTTP request.
- `qa_reporter.py` — Markdown and HTML reports.
- `fixtures/sample_app.py` — Demo fixture and source of truth; `main.py` copies it to `sample_app.py` before analysing it.
- `main.py` — Demo (fixtures plus a local HTTP server for the contract test).

## Usage

```bash
agentes demo qa               # demo on sample data
python -m agentes.qa.main     # the same, without going through the CLI
agentes generate tests --source app.py --record
agentes test test_app.py
```
