# Documentation and Swagger UI Agent

Generates OpenAPI 3.0.3 specifications, a Swagger UI HTML page and Markdown manuals from Python source code.

## Layout

- `openapi_generator.py` — OpenAPI 3.0.3 from Flask and FastAPI route decorators, optionally also from the `get_`/`post_`/`put_`/`delete_` naming convention. Produces **parameters** (GET/DELETE), **requestBody** and **components.schemas** (POST/PUT) from the type hints. Exports JSON and YAML.
- `swagger_ui_generator.py` — HTML page with Swagger UI (from a CDN) and the spec embedded.
- `markdown_doc_generator.py` — Technical manual built from module, class and method docstrings.
- `fixtures/sample_api.py` — Demo fixture and source of truth; `main.py` copies it to `sample_api.py` before analysing it.
- `main.py` — Runnable demo.

## Usage

```bash
agentes demo docs               # demo on sample data
python -m agentes.docs.main     # the same, without going through the CLI
agentes generate openapi --source app.py -o openapi.yaml
```

Note: the Swagger UI page needs network access to load swagger-ui from the CDN.
