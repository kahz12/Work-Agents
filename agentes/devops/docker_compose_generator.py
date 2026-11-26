import os


class DockerComposeGenerator:
    """
    Generador de docker-compose.yml parametrizable (puerto, imagen, recursos).
    """

    @staticmethod
    def generate_compose_file(
        output_filepath: str,
        *,
        service_name: str = "web",
        image: str = "myorg/myapp:1.0.0",
        port: int = 8080,
        mem_limit: str = "512m",
        cpus: str = "0.50",
        dockerfile: str = "Dockerfile.hardened",
        use_image: bool = False,
    ) -> str:
        """
        Genera un archivo docker-compose.yml con fortalecimiento defensivo.
        Por defecto usa build local; con use_image=True o image custom explícita vía flag CLI.
        """
        if use_image or (image and image != "myorg/myapp:1.0.0" and not image.startswith("myorg/myservice")):
            # Priorizar imagen preconstruida explícita sobre la construcción local desde Dockerfile.
            source = f"    image: {image}\n"
        else:
            source = (
                "    build:\n"
                "      context: .\n"
                f"      dockerfile: {dockerfile}\n"
            )

        # Convertir sufijo de megabytes a mayúscula según convención del bloque deploy.resources.limits en Swarm.
        mem_deploy = mem_limit.upper() if mem_limit[-1:].lower() == "m" else mem_limit

        content = f"""# Generado por agentes (agente devops).
# deploy.resources solo se aplica en Docker Swarm; con `docker compose` se aplican
# mem_limit y cpus, por eso se declaran los dos.
version: '3.8'

services:
  {service_name}:
{source}    ports:
      - "{port}:{port}"
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /tmp
    mem_limit: {mem_limit}
    cpus: {cpus}
    mem_reservation: 128m
    deploy:
      resources:
        limits:
          cpus: '{cpus}'
          memory: {mem_deploy}
        reservations:
          cpus: '0.10'
          memory: 128M
    networks:
      - app_internal_network
    security_opt:
      - no-new-privileges:true

networks:
  app_internal_network:
    driver: bridge
    internal: false
"""
        dirpath = os.path.dirname(os.path.abspath(output_filepath))
        os.makedirs(dirpath, exist_ok=True)
        with open(output_filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return output_filepath
