# Agente DevOps, Pipelines CI/CD y Helm

Generación de GitHub Actions, GitLab CI, Docker Compose endurecido, Helm Charts y validación YAML.

## Estructura

- `github_actions_generator.py` — Workflow DevSecOps (ruff, bandit, unittest).
- `gitlab_ci_generator.py` — Pipeline por stages (lint / test / security).
- `docker_compose_generator.py` — Compose con `read_only`, `no-new-privileges`, **`mem_limit`/`cpus` (Compose v2)** y `deploy.resources` (Swarm, documentado).
- `helm_generator.py` — Chart con `runAsNonRoot`, `allowPrivilegeEscalation: false` y `capabilities.drop: [ALL]`.
- `yaml_validator.py` — Rechaza tabs y parsea con **PyYAML** (sin falsos positivos en puertos / `no-new-privileges:true`).
- `main.py` — Demo ejecutable.

## Uso

```bash
agentes demo devops               # demo con datos de ejemplo
python -m agentes.devops.main     # lo mismo, sin pasar por el CLI
agentes generate compose --service api --port 8000
```

