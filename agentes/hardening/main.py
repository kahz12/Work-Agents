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
    print_header("Agente de Fortalecimiento de Infraestructura")
    print("Módulos Nginx/Caddy, Docker, Systemd y Kubernetes PodSecurity cargados.")

    current_dir = agent_output_dir(__file__)

    # Generación de configuración TLS endurecida y cabeceras HTTP defensivas para Caddyfile.
    print_header("Demostración 1: Generación de Nginx y Caddyfile Fortalecidos")

    caddy_conf = WebServerHardening.generate_caddy_config("midominio.com")
    print("Muestra de Caddyfile generado:")
    print("-" * 50)
    print(caddy_conf.strip())
    print("-" * 50)

    # Emisión de Dockerfile endurecido con usuario sin privilegios y superficie mínima.
    print_header("Demostración 2: Generación y Auditoría de Contenedor Docker")

    dockerfile_path = os.path.join(current_dir, "Dockerfile.hardened")
    ContainerHardening.generate_hardened_dockerfile(dockerfile_path)
    print(f"Dockerfile fortalecido generado en: {dockerfile_path}")

    # Auditoría y generación de políticas PodSecurity de Kubernetes bajo principio de mínimo privilegio.
    print_header("Demostración 3: Kubernetes PodSecurity Standards Audit")

    K8sHardening.generate_hardened_pod_manifest("mi-microservicio", "mi-imagen:1.2.0")
    print("Manifiesto Kubernetes Pod SecurityContext generado exitosamente.")

    pod_inseguro = {
        "apiVersion": "v1",
        "kind": "Pod",
        "spec": {
            "containers": [{"name": "app", "image": "nginx:latest"}]
        }
    }
    print("\nAuditando manifiesto Pod Kubernetes inseguro...")
    k8s_hallazgos = K8sHardening.audit_pod_security_context(pod_inseguro)
    for elem, nivel, desc in k8s_hallazgos:
        print(f"[{nivel}] Componente: {elem} -> {desc}")

    # Emisión de unidad systemd con aislamiento de sistema de archivos, capacidades y espacios de nombres.
    print_header("Demostración 4: Systemd Service Isolation Hardening")

    service_path = os.path.join(current_dir, "mi_aplicacion.service")
    ServiceHardening.generate_hardened_service(service_path)
    print(f"Unidad de servicio systemd aislada generada en: {service_path}")

    print("\n" + "=" * 65)
    print(" Agente de Fortalecimiento ejecutado exitosamente.")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    main()
