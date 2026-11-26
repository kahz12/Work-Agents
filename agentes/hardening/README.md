# Agente de Fortalecimiento de Infraestructura

Generación y auditoría de configuraciones defensivas para web servers, Docker, systemd y Kubernetes.

## Estructura

- `webserver_hardening.py` — Plantillas **Nginx** y **Caddyfile** (TLS 1.2/1.3; en Caddy, `protocols` dentro de `tls { }`), cabeceras de seguridad y auditoría de headers HTTP.
- `k8s_hardening.py` — Manifiestos PodSecurity (`runAsNonRoot`, `readOnlyRootFilesystem`, `drop: ALL`) y auditoría de contexts.
- `container_hardening.py` — Dockerfile multi-stage non-root y auditoría de Dockerfiles.
- `service_hardening.py` — Unidades systemd endurecidas (`ProtectSystem`, `PrivateTmp`, `NoNewPrivileges`, etc.).
- `main.py` — Demo ejecutable.

## Uso

```bash
agentes demo hardening               # demo con datos de ejemplo
python -m agentes.hardening.main     # lo mismo, sin pasar por el CLI
agentes audit Dockerfile
agentes generate nginx --domain midominio.com
```

