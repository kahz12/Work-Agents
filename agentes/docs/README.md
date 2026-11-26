# Agente de Documentación y Swagger UI

Generación de OpenAPI 3.0.3, Swagger UI HTML y manuales Markdown a partir de código Python.

## Estructura

- `openapi_generator.py` — OpenAPI 3.0.3 por convención `get_`/`post_`/`put_`/`delete_`. Incluye **parameters** (GET/DELETE), **requestBody** + **components.schemas** (POST/PUT) según type hints. Exporta JSON y YAML.
- `swagger_ui_generator.py` — HTML con Swagger UI (CDN) y spec embebida.
- `markdown_doc_generator.py` — Manual técnico desde docstrings de módulos/clases/métodos.
- `fixtures/sample_api.py` — Fixture de demo (fuente de verdad; `main.py` la copia a `sample_api.py`).
- `main.py` — Demo ejecutable.

## Uso

```bash
agentes demo docs               # demo con datos de ejemplo
python -m agentes.docs.main     # lo mismo, sin pasar por el CLI
agentes generate openapi --source app.py -o openapi.yaml
```


Nota: el HTML de Swagger UI requiere red para cargar el CDN de swagger-ui.
