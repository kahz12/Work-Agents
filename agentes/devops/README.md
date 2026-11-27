# DevOps, CI/CD Pipelines and Helm Agent

Generates GitHub Actions workflows, GitLab CI pipelines, hardened Docker Compose files and Helm charts, and validates YAML.

## Layout

- `github_actions_generator.py` — DevSecOps workflow (ruff, bandit, unittest) with a read-only `GITHUB_TOKEN`.
- `gitlab_ci_generator.py` — Staged pipeline (lint / test / security).
- `docker_compose_generator.py` — Compose file with `read_only`, `no-new-privileges`, **`mem_limit`/`cpus` (Compose v2)** and `deploy.resources` (Swarm), both documented in the generated file.
- `helm_generator.py` — Chart with `runAsNonRoot`, `allowPrivilegeEscalation: false` and `capabilities.drop: [ALL]`.
- `yaml_validator.py` — Parses with **PyYAML** (multi-document files included) and reports errors with their line number; tabs in indentation get a dedicated message. Ports and values such as `no-new-privileges:true` produce no false positives.
- `main.py` — Runnable demo.

## Usage

```bash
agentes demo devops               # demo on sample data
python -m agentes.devops.main     # the same, without going through the CLI
agentes generate compose --service api --port 8000
```
