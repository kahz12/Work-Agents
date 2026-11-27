#!/usr/bin/env python3
import os
import shutil

from ..common.workspace import agent_output_dir
from .markdown_doc_generator import MarkdownDocGenerator
from .openapi_generator import OpenAPIGenerator
from .swagger_ui_generator import SwaggerUIGenerator


def print_header(title: str):
    print("\n" + "=" * 65)
    print(f" {title.upper()}")
    print("=" * 65)


def main():
    print_header("Documentation and Swagger UI Agent")
    print("Loaded modules: interactive Swagger UI and YAML exporter.")

    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    current_dir = agent_output_dir(__file__)
    fixture = os.path.join(pkg_dir, "fixtures", "sample_api.py")
    sample_file = os.path.join(current_dir, "sample_api.py")
    shutil.copy2(fixture, sample_file)

    # -----------------------------------------------------------------
    # OpenAPI 3.0.3 specification in JSON and YAML: walks the fixture's AST
    # to extract each endpoint's route, HTTP method and parameters.
    # -----------------------------------------------------------------
    print_header("Demo 1: OpenAPI 3.0.3 in JSON and YAML")

    spec = OpenAPIGenerator.generate_openapi_spec(sample_file, title="User Service", version="1.0.0")
    json_path = os.path.join(current_dir, "openapi.json")
    yaml_path = os.path.join(current_dir, "openapi.yaml")

    OpenAPIGenerator.export_spec_to_json(spec, json_path)
    OpenAPIGenerator.export_spec_to_yaml(spec, yaml_path)

    print(f"OpenAPI specification (JSON) written to: {json_path}")
    print(f"OpenAPI specification (YAML) written to: {yaml_path}")
    print(f"Component schemas: {list(spec.get('components', {}).get('schemas', {}).keys())}")

    # -----------------------------------------------------------------
    # Swagger UI viewer in a single HTML file: the spec is embedded in the
    # page and Swagger UI loads from cdnjs, so no server is needed.
    # -----------------------------------------------------------------
    print_header("Demo 2: Interactive Swagger UI HTML viewer")

    swagger_html = os.path.join(current_dir, "swagger_ui.html")
    SwaggerUIGenerator.generate_swagger_ui_html(spec, swagger_html)
    print(f"Interactive Swagger UI page written to: {swagger_html}")

    # -----------------------------------------------------------------
    # Markdown reference manual with the fixture's classes, functions,
    # signatures and docstrings.
    # -----------------------------------------------------------------
    print_header("Demo 3: Markdown technical manual")

    doc_path = os.path.join(current_dir, "API_DOCUMENTATION.md")
    MarkdownDocGenerator.generate_module_docs(sample_file, doc_path)
    print(f"Markdown technical manual written to: {doc_path}")

    print("\n" + "=" * 65)
    print(" Documentation agent finished successfully.")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
