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
    print_header("DevOps, CI/CD Pipelines and Docker Compose Agent")
    print("Loaded modules: GitHub Actions, GitLab CI, Docker Compose, Helm chart and YAML validator.")

    current_dir = agent_output_dir(__file__)

    # -----------------------------------------------------------------
    # GitHub Actions workflow with linting (Ruff), security analysis (Bandit)
    # and tests, granting the GITHUB_TOKEN the minimum permissions.
    # -----------------------------------------------------------------
    print_header("Demo 1: GitHub Actions CI/CD workflow")

    gh_workflow = os.path.join(current_dir, ".github", "workflows", "ci.yml")
    GitHubActionsGenerator.generate_workflow(gh_workflow)
    print(f"DevSecOps GitHub Actions workflow written to: {gh_workflow}")

    # -----------------------------------------------------------------
    # GitLab CI pipeline with lint, test and security (Bandit) stages.
    # -----------------------------------------------------------------
    print_header("Demo 2: GitLab CI pipeline")

    gitlab_file = os.path.join(current_dir, ".gitlab-ci.yml")
    GitLabCIGenerator.generate_ci_file(gitlab_file)
    print(f"GitLab CI pipeline written to: {gitlab_file}")

    # -----------------------------------------------------------------
    # docker-compose.yml with memory and CPU limits, a read-only filesystem
    # and no-new-privileges.
    # -----------------------------------------------------------------
    print_header("Demo 3: Hardened Docker Compose file")

    compose_file = os.path.join(current_dir, "docker-compose.yml")
    DockerComposeGenerator.generate_compose_file(compose_file)
    print(f"Docker Compose manifest written to: {compose_file}")

    # -----------------------------------------------------------------
    # Helm chart with Chart.yaml, values.yaml and a Deployment whose
    # securityContext requires a non-root user and a read-only filesystem.
    # -----------------------------------------------------------------
    print_header("Demo 4: Helm chart for Kubernetes")

    helm_dir = os.path.join(current_dir, "my-helm-chart")
    HelmGenerator.generate_helm_chart(helm_dir, chart_name="payment-service")
    print(f"Hardened Helm chart created in: {helm_dir}")

    # -----------------------------------------------------------------
    # Validate the freshly generated values.yaml with PyYAML.
    # -----------------------------------------------------------------
    print_header("Demo 5: Static YAML syntax validation")

    values_path = os.path.join(helm_dir, "values.yaml")
    valid_yaml, errors = YAMLValidator.validate_yaml_syntax(values_path)
    print(f"Validating the syntax of '{os.path.basename(values_path)}'...")
    print(f"  Status: {'VALID' if valid_yaml else 'HAS ERRORS'}")

    print("\n" + "=" * 65)
    print(" DevOps agent finished successfully.")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    main()
