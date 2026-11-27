import os
from typing import List, Tuple


class ContainerHardening:
    """
    Audits Dockerfiles and generates hardened ones: least privilege, a non-root user and a
    multi-stage build that keeps build tooling out of the runtime image.
    """

    HARDENED_DOCKERFILE_TEMPLATE = """# Hardened Dockerfile (multi-stage build)
# Stage 1: build
FROM python:3.10-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: runtime with minimal privileges (non-root)
FROM python:3.10-slim AS runner
WORKDIR /app

# Unprivileged user and group (UID/GID 10001)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin appuser

# Copy the dependencies installed in the build stage, then the application
COPY --from=builder /root/.local /home/appuser/.local
COPY . /app

# Hand the application files over to the unprivileged user
RUN chown -R appuser:appgroup /app

# Drop root for everything that follows, including the running process
USER appuser
ENV PATH=/home/appuser/.local/bin:$PATH

EXPOSE 8080
CMD ["python3", "main.py"]
"""

    @staticmethod
    def audit_dockerfile(filepath: str) -> List[Tuple[int, str, str]]:
        """
        Audit a Dockerfile for container security bad practices.
        Returns (line, level, message) tuples; line 0 applies to the whole file.
        """
        findings = []
        if not os.path.exists(filepath):
            return [(0, "ERROR", f"Dockerfile '{filepath}' does not exist.")]

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
                    findings.append((idx, "HIGH", "Malformed 'FROM' instruction with no base image."))
                elif ":latest" in line_str or ":" not in parts[1]:
                    findings.append((idx, "MEDIUM", "Base image uses ':latest' or no pinned tag. Specify the exact version."))

            if line_str.split(" ")[0].upper() == "USER":
                # Compare the whole argument rather than searching for substrings: 'nonroot'
                # contains 'root' and '1000' contains '0', yet both are fine users.
                parts = line_str.split(None, 1)
                user = parts[1].strip().split(":")[0].strip() if len(parts) > 1 else ""
                if not user:
                    findings.append((idx, "HIGH", "'USER' instruction with no user given."))
                elif user in ("root", "0"):
                    findings.append((idx, "HIGH", f"Explicit 'USER {user}'. Do not run containers as root."))
                else:
                    has_user_instruction = True

            if "sudo" in line_str or "chmod 777" in line_str:
                findings.append((idx, "HIGH", "Use of 'sudo' or overly broad 'chmod 777' permissions inside the container."))

        if not has_user_instruction:
            findings.append((0, "HIGH", "The Dockerfile has no 'USER <non_root_user>' instruction. The container will run as root by default."))

        return findings

    @staticmethod
    def generate_hardened_dockerfile(target_path: str) -> str:
        """
        Write the hardened Dockerfile template to target_path and return the path.
        """
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(ContainerHardening.HARDENED_DOCKERFILE_TEMPLATE)
        return target_path
