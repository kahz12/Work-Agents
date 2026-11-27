import os


class GitHubActionsGenerator:
    """
    Generates a security-minded GitHub Actions workflow with linting (Ruff), SAST (Bandit) and
    unit tests. The workflow grants the GITHUB_TOKEN read-only access to the repository.
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
    name: Security and quality audit
    runs-on: ubuntu-latest
    steps:
      - name: Check out code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install ruff bandit pytest

      - name: Lint (Ruff)
        run: |
          ruff check .

      - name: Security SAST (Bandit)
        run: |
          bandit -r . -f txt

  unit-tests:
    name: Unit tests
    needs: security-and-lint
    runs-on: ubuntu-latest
    steps:
      - name: Check out code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Run tests
        run: |
          python -m unittest discover -s . -p "test_*.py"
"""

    @staticmethod
    def generate_workflow(output_filepath: str) -> str:
        """
        Write the workflow to output_filepath (parent directories are created) and return the path.
        """
        dirpath = os.path.dirname(os.path.abspath(output_filepath))
        os.makedirs(dirpath, exist_ok=True)
        with open(output_filepath, "w", encoding="utf-8") as f:
            f.write(GitHubActionsGenerator.GITHUB_WORKFLOW_TEMPLATE)
        return output_filepath
