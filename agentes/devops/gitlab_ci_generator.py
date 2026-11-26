import os


class GitLabCIGenerator:
    """
    Generador automatizado de canalizaciones defensivas para GitLab CI (.gitlab-ci.yml).
    """

    GITLAB_CI_TEMPLATE = """image: python:3.10-slim

stages:
  - lint
  - test
  - security

variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

cache:
  paths:
    - .cache/pip/

before_script:
  - python -V
  - pip install --upgrade pip

linting_job:
  stage: lint
  script:
    - pip install flake8
    - flake8 . --max-line-length=100

unit_test_job:
  stage: test
  script:
    - python -m unittest discover -s . -p "test_*.py"

sast_security_job:
  stage: security
  script:
    - pip install bandit
    - bandit -r . -f txt
"""

    @staticmethod
    def generate_ci_file(output_filepath: str) -> str:
        """
        Genera un archivo de configuración seguro para GitLab CI.
        """
        dirpath = os.path.dirname(os.path.abspath(output_filepath))
        os.makedirs(dirpath, exist_ok=True)
        with open(output_filepath, "w", encoding="utf-8") as f:
            f.write(GitLabCIGenerator.GITLAB_CI_TEMPLATE)
        return output_filepath
