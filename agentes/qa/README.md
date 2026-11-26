# Agente QA y Automatización de Pruebas

Generación de unit tests con asserts reales, ejecución dinámica, contratos de API (offline y HTTP real) e informes QA.

## Estructura

- `test_generator.py` — Fachada pública (`QATestGenerator`) que combina `ast_inspector.py`, `testability.py`, `sample_values.py` y `emitters.py` para generar suites `unittest` o `pytest` adversarias.
- `ast_inspector.py` — Análisis AST de firmas, excepciones y propagación de E/S (`UnitTestGenerator`).
- `testability.py` — Auditoría de testabilidad arquitectónica (`TestabilityAuditor`).
- `sample_values.py` — Valores de muestra, límites y matriz de escenarios QA.
- `emitters.py` — Emisores de suites `unittest` y `pytest`.
- `test_runner.py` — Ejecuta la suite y reporta duración, pass rate y tracebacks.
- `api_contract_testing.py` — Valida status, schema JSON (vía `common.schema`) y SLA; incluye `request_and_validate()` para HTTP real.
- `qa_reporter.py` — Reportes Markdown y HTML.
- `fixtures/sample_app.py` — Fixture de demo (fuente de verdad; `main.py` la copia a `sample_app.py`).
- `main.py` — Demo (fixtures + servidor HTTP local de contrato).

## Uso

```bash
agentes demo qa               # demo con datos de ejemplo
python -m agentes.qa.main     # lo mismo, sin pasar por el CLI
agentes generate tests --source app.py --record
agentes test test_app.py
```

