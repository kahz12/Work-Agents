#!/usr/bin/env python3
import os

from ..common.workspace import agent_output_dir
from .docker_compose_generator import DockerComposeGenerator
from .github_actions_generator import GitHubActionsGenerator
from .gitlab_ci_generator import GitLabCIGenerator
from .helm_generator import HelmGenerator
from .yaml_validator import YAMLValidator


def print_header(title: str):
    print("\n" + "=" * 65)
    print(f" {title.upper()}")
    print("=" * 65)

def main():
    print_header("Agente DevOps, Pipelines CI/CD y Docker Compose")
    print("Módulos GitHub Actions, GitLab CI, Docker Compose, Helm Chart y Validador YAML cargados.")

    current_dir = agent_output_dir(__file__)

    # -----------------------------------------------------------------
    # Workflow de GitHub Actions con lint (Ruff), análisis de seguridad (Bandit)
    # y tests (pytest), con permisos mínimos para el GITHUB_TOKEN.
    # -----------------------------------------------------------------
    print_header("Demostración 1: Generación de Workflow CI/CD GitHub Actions")

    gh_workflow = os.path.join(current_dir, ".github", "workflows", "ci.yml")
    GitHubActionsGenerator.generate_workflow(gh_workflow)
    print(f"Workflow GitHub Actions DevSecOps generado en: {gh_workflow}")

    # -----------------------------------------------------------------
    # Pipeline de GitLab CI con las etapas lint, test y security (Bandit).
    # -----------------------------------------------------------------
    print_header("Demostración 2: Generación de Pipeline GitLab CI")

    gitlab_file = os.path.join(current_dir, ".gitlab-ci.yml")
    GitLabCIGenerator.generate_ci_file(gitlab_file)
    print(f"Pipeline GitLab CI generado en: {gitlab_file}")

    # -----------------------------------------------------------------
    # docker-compose.yml con límites de memoria y CPU, sistema de archivos de
    # solo lectura y no-new-privileges.
    # -----------------------------------------------------------------
    print_header("Demostración 3: Generación de Docker Compose Fortalecido")

    compose_file = os.path.join(current_dir, "docker-compose.yml")
    DockerComposeGenerator.generate_compose_file(compose_file)
    print(f"Manifiesto Docker Compose multicontenedor generado en: {compose_file}")

    # -----------------------------------------------------------------
    # Helm Chart con Chart.yaml, values.yaml y un Deployment cuyo securityContext
    # exige usuario no root y sistema de archivos de solo lectura.
    # -----------------------------------------------------------------
    print_header("Demostración 4: Generación de Helm Chart para Kubernetes")

    helm_dir = os.path.join(current_dir, "my-helm-chart")
    HelmGenerator.generate_helm_chart(helm_dir, chart_name="payment-service")
    print(f"Helm Chart fortalecido creado en: {helm_dir}")

    # -----------------------------------------------------------------
    # Valida con PyYAML la sintaxis del values.yaml recién generado.
    # -----------------------------------------------------------------
    print_header("Demostración 5: Validador Estático de Sintaxis YAML")

    values_path = os.path.join(helm_dir, "values.yaml")
    valid_yaml, errors = YAMLValidator.validate_yaml_syntax(values_path)
    print(f"Validando sintaxis de '{os.path.basename(values_path)}'...")
    print(f"  Estado: {'VÁLIDO' if valid_yaml else 'CON ERRORES'}")

    print("\n" + "=" * 65)
    print(" Agente DevOps ejecutado exitosamente.")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    main()
