import os
from typing import List, Tuple


class ContainerHardening:
    """
    Auditor y generador de archivos Dockerfile fortalecidos (*Hardened Containers*).
    Aplica principios de menor privilegio, usuarios no-root y construcción multietapa.
    """

    HARDENED_DOCKERFILE_TEMPLATE = """# Dockerfile Fortalecido (Multi-stage Build)
# Etapa 1: Compilación
FROM python:3.10-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Etapa 2: Ejecución con Privilegios Mínimos (Non-root)
FROM python:3.10-slim AS runner
WORKDIR /app

# Crear usuario y grupo sin privilegios de root (UID/GID 10001)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin appuser

# Copiar artefactos y dependencias de la etapa anterior
COPY --from=builder /root/.local /home/appuser/.local
COPY . /app

# Asignar propiedad de archivos al usuario sin privilegios
RUN chown -R appuser:appgroup /app

# Cambiar a usuario no-root
USER appuser
ENV PATH=/home/appuser/.local/bin:$PATH

EXPOSE 8080
CMD ["python3", "main.py"]
"""

    @staticmethod
    def audit_dockerfile(filepath: str) -> List[Tuple[int, str, str]]:
        """
        Audita un Dockerfile en busca de malas prácticas de seguridad containerizada.
        """
        findings = []
        if not os.path.exists(filepath):
            return [(0, "ERROR", f"El archivo Dockerfile '{filepath}' no existe.")]

        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()

        has_user_instruction = False

        for idx, line in enumerate(lines, 1):
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            if line_str.startswith("FROM"):
                parts = line_str.split()
                if len(parts) < 2:
                    findings.append((idx, "ALTO", "Instrucción 'FROM' malformada sin imagen base especificada."))
                elif ":latest" in line_str or ":" not in parts[1]:
                    findings.append((idx, "MEDIO", "Uso de la etiqueta ':latest' o sin versión fija en la imagen base. Se recomienda especificar la versión exacta."))

            if line_str.split(" ")[0].upper() == "USER":
                # Comparar el argumento, no buscar subcadenas: 'nonroot' contiene 'root'
                # y '1000' contiene '0', y ambos son usuarios correctos.
                partes = line_str.split(None, 1)
                usuario = partes[1].strip().split(":")[0].strip() if len(partes) > 1 else ""
                if not usuario:
                    findings.append((idx, "ALTO", "Instrucción 'USER' sin usuario especificado."))
                elif usuario in ("root", "0"):
                    findings.append((idx, "ALTO", f"Definición explícita de usuario 'USER {usuario}'. Evita ejecutar contenedores como root."))
                else:
                    has_user_instruction = True

            if "sudo" in line_str or "chmod 777" in line_str:
                findings.append((idx, "ALTO", "Uso de 'sudo' o permisos excesivos 'chmod 777' dentro del contenedor."))

        if not has_user_instruction:
            findings.append((0, "ALTO", "El Dockerfile no especifica la instrucción 'USER <usuario_no_root>'. El contenedor se ejecutará como root por defecto."))

        return findings

    @staticmethod
    def generate_hardened_dockerfile(target_path: str) -> str:
        """
        Genera una plantilla Dockerfile fortalecida en la ruta indicada.
        """
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(ContainerHardening.HARDENED_DOCKERFILE_TEMPLATE)
        return target_path
