#!/usr/bin/env python3
import os

from ..common.workspace import agent_output_dir
from .container_hardening import ContainerHardening
from .k8s_hardening import K8sHardening
from .service_hardening import ServiceHardening
from .webserver_hardening import WebServerHardening


def print_header(title: str):
    print("\n" + "=" * 65)
    print(f" {title.upper()}")
    print("=" * 65)

def main():
    print_header("Infrastructure Hardening Agent")
    print("Loaded modules: Nginx/Caddy, Docker, systemd and Kubernetes Pod Security.")

    current_dir = agent_output_dir(__file__)

    # Hardened TLS settings and HTTP security headers for a Caddyfile.
    print_header("Demo 1: Hardened Nginx and Caddyfile")

    caddy_conf = WebServerHardening.generate_caddy_config("mydomain.com")
    print("Generated Caddyfile:")
    print("-" * 50)
    print(caddy_conf.strip())
    print("-" * 50)

    # Hardened Dockerfile: unprivileged user and a minimal runtime image.
    print_header("Demo 2: Docker container generation and audit")

    dockerfile_path = os.path.join(current_dir, "Dockerfile.hardened")
    ContainerHardening.generate_hardened_dockerfile(dockerfile_path)
    print(f"Hardened Dockerfile written to: {dockerfile_path}")

    # Kubernetes Pod Security: generate a least-privilege Pod, then audit an insecure one.
    print_header("Demo 3: Kubernetes Pod Security Standards audit")

    K8sHardening.generate_hardened_pod_manifest("my-microservice", "my-image:1.2.0")
    print("Kubernetes Pod manifest with a hardened securityContext generated.")

    insecure_pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "spec": {
            "containers": [{"name": "app", "image": "nginx:latest"}]
        }
    }
    print("\nAuditing an insecure Kubernetes Pod manifest...")
    k8s_findings = K8sHardening.audit_pod_security_context(insecure_pod)
    for elem, level, desc in k8s_findings:
        print(f"[{level}] Element: {elem} -> {desc}")

    # systemd unit with filesystem, capability and namespace isolation.
    print_header("Demo 4: systemd service isolation hardening")

    service_path = os.path.join(current_dir, "my_app.service")
    ServiceHardening.generate_hardened_service(service_path)
    print(f"Isolated systemd unit written to: {service_path}")

    print("\n" + "=" * 65)
    print(" Hardening agent finished successfully.")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    main()
