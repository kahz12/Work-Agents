# Infrastructure Hardening Agent

Generates and audits defensive configurations for web servers, Docker, systemd and Kubernetes.

## Layout

- `webserver_hardening.py` — **Nginx** and **Caddyfile** templates (TLS 1.2/1.3; in Caddy, `protocols` goes inside `tls { }`), security headers and an HTTP header audit.
- `k8s_hardening.py` — Pod Security manifests (`runAsNonRoot`, `readOnlyRootFilesystem`, `drop: ALL`) and a securityContext audit for Pods and workloads.
- `container_hardening.py` — Multi-stage, non-root Dockerfile and a Dockerfile audit.
- `service_hardening.py` — Hardened systemd units (`ProtectSystem`, `PrivateTmp`, `NoNewPrivileges`, etc.) and a unit audit that ignores commented-out directives.
- `main.py` — Runnable demo.

## Usage

```bash
agentes demo hardening               # demo on sample data
python -m agentes.hardening.main     # the same, without going through the CLI
agentes audit Dockerfile
agentes generate nginx --domain mydomain.com
```
