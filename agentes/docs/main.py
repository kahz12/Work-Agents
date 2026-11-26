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
    print_header("Agente de Documentación y Swagger UI")
    print("Módulos Swagger UI Interactivo y Exportador YAML cargados.")

    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    current_dir = agent_output_dir(__file__)
    fixture = os.path.join(pkg_dir, "fixtures", "sample_api.py")
    sample_file = os.path.join(current_dir, "sample_api.py")
    shutil.copy2(fixture, sample_file)

    # -----------------------------------------------------------------
    # Especificación OpenAPI 3.0.3 en JSON y YAML: recorre el AST del fixture
    # para sacar las rutas, los métodos HTTP y los parámetros de cada endpoint.
    # -----------------------------------------------------------------
    print_header("Demostración 1: Generación de OpenAPI 3.0.3 en JSON y YAML")

    spec = OpenAPIGenerator.generate_openapi_spec(sample_file, title="Servicio de Usuarios", version="1.0.0")
    json_path = os.path.join(current_dir, "openapi.json")
    yaml_path = os.path.join(current_dir, "openapi.yaml")

    OpenAPIGenerator.export_spec_to_json(spec, json_path)
    OpenAPIGenerator.export_spec_to_yaml(spec, yaml_path)

    print(f"Especificación OpenAPI en JSON generada en: {json_path}")
    print(f"Especificación OpenAPI en YAML generada en: {yaml_path}")
    print(f"Component schemas: {list(spec.get('components', {}).get('schemas', {}).keys())}")

    # -----------------------------------------------------------------
    # Visor Swagger UI en un HTML: la especificación va incrustada en la página
    # y Swagger UI se carga desde cdnjs, así que no hace falta ningún servidor.
    # -----------------------------------------------------------------
    print_header("Demostración 2: Generación de Visor Interactivo Swagger UI HTML")

    swagger_html = os.path.join(current_dir, "swagger_ui.html")
    SwaggerUIGenerator.generate_swagger_ui_html(spec, swagger_html)
    print(f"Interfaz gráfica Swagger UI interactiva generada en: {swagger_html}")

    # -----------------------------------------------------------------
    # Manual de referencia en Markdown con las clases, funciones, firmas y
    # docstrings del fixture.
    # -----------------------------------------------------------------
    print_header("Demostración 3: Generación de Manual Técnico en Markdown")

    doc_path = os.path.join(current_dir, "API_DOCUMENTATION.md")
    MarkdownDocGenerator.generate_module_docs(sample_file, doc_path)
    print(f"Manual técnico en Markdown generado en: {doc_path}")

    print("\n" + "=" * 65)
    print(" Agente de Documentación ejecutado exitosamente.")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
