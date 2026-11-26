import os


class GitHubActionsGenerator:
    """
    Generador automatizado de flujos de trabajo defensivos para GitHub Actions (.github/workflows/ci.yml).
    Incluye etapas de linting (Ruff), SAST (Bandit) y pruebas unitarias.
    """

    GITHUB_WORKFLOW_TEMPLATE = """name: DevSecOps CI/CD Pipeline

on:
  push:
    branches: [ "main", "master" ]
  pull_request:
    branches: [ "main", "master" ]

permissions:
  contents: read

jobs:
  security-and-lint:
    name: Auditoría de Seguridad y Calidad
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Código
        uses: actions/checkout@v4

      - name: Configurar Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Instalar Dependencias
        run: |
          python -m pip install --upgrade pip
          pip install ruff bandit pytest

      - name: Ejecutar Linter (Ruff)
        run: |
          ruff check .

      - name: Análisis SAST de Seguridad (Bandit)
        run: |
          bandit -r . -f txt

  unit-tests:
    name: Pruebas Unitarias y Cobertura
    needs: security-and-lint
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Código
        uses: actions/checkout@v4

      - name: Configurar Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Ejecutar Pruebas
        run: |
          python -m unittest discover -s . -p "test_*.py"
"""

    @staticmethod
    def generate_workflow(output_filepath: str) -> str:
        """
        Genera un archivo de flujo de trabajo seguro para GitHub Actions.
        """
        dirpath = os.path.dirname(os.path.abspath(output_filepath))
        os.makedirs(dirpath, exist_ok=True)
        with open(output_filepath, "w", encoding="utf-8") as f:
            f.write(GitHubActionsGenerator.GITHUB_WORKFLOW_TEMPLATE)
        return output_filepath
