# Agente de Refactorización y Arquitectura

Métricas de complejidad, heurísticas SOLID, sugerencias de refactor y diagramas Mermaid.

## Estructura

- `code_metrics.py` — LOC, complejidad **ciclomática** y **cognitiva** por AST.
- `solid_checker.py` — Heurísticas SRP / OCP / DIP.
- `refactor_suggester.py` — Recomendaciones a partir de métricas + hallazgos SOLID.
- `architecture_diagram.py` — Diagrama de clases **Mermaid.js** (herencia incluida).
- `main.py` — Demo ejecutable (usa `sample_monolith.py` de ejemplo).

## Uso

```bash
agentes demo refactor               # demo con datos de ejemplo
python -m agentes.refactor.main     # lo mismo, sin pasar por el CLI
agentes metrics ./src
agentes generate diagram --source modelos.py
```

