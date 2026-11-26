import os
from typing import List, Tuple


class ServiceHardening:
    """
    Auditor y generador de unidades de servicio Systemd fortalecidas (*Systemd Service Hardening*).
    Aplica namespaces de Linux, aislamiento de sistema de archivos y restricciones de privilegios.
    """

    SYSTEMD_SERVICE_TEMPLATE = """[Unit]
Description=Servicio de Aplicación Fortalecido (Hardened Systemd Unit)
After=network.target

[Service]
Type=simple
User=appuser
Group=appgroup
WorkingDirectory=/opt/mi_aplicacion
ExecStart=/usr/bin/python3 /opt/mi_aplicacion/main.py
Restart=on-failure

# ---------------------------------------------------------
# Directivas de Fortalecimiento y Aislamiento de Seguridad
# ---------------------------------------------------------
# Prevenir que el proceso obtenga nuevos privilegios (suid/sgid)
NoNewPrivileges=true

# Montar el sistema de archivos del SO como Lectura Únicamente (Read-Only)
ProtectSystem=strict
ReadWritePaths=/var/log/mi_aplicacion /tmp

# Prevenir acceso a los directorios /home, /root y /run/user
ProtectHome=true

# Crear espacio de nombres temporal aislado para /tmp
PrivateTmp=true

# Ocultar dispositivos de hardware (/dev) innecesarios
PrivateDevices=true

# Bloquear modificaciones a la configuración del Kernel (sysctl)
ProtectKernelTunables=true

# Bloquear carga de módulos del Kernel
ProtectKernelModules=true

# Limitar las capacidades de Linux permitidas al proceso
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
"""

    @staticmethod
    def generate_hardened_service(target_path: str) -> str:
        """
        Genera un archivo de unidad de servicio systemd fortalecido.
        """
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(ServiceHardening.SYSTEMD_SERVICE_TEMPLATE)
        return target_path

    @staticmethod
    def audit_systemd_service(filepath: str) -> List[Tuple[str, str, str]]:
        """
        Audita un archivo .service de systemd comprobando si contiene directivas de aislamiento.
        """
        findings = []
        if not os.path.exists(filepath):
            return [("N/A", "ERROR", f"El archivo de servicio '{filepath}' no existe.")]

        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        # Directivas activas: clave -> valor. Ignora comentarios, porque una directiva
        # comentada no aplica nada aunque el texto aparezca en el fichero.
        activas = {}
        for raw in content.splitlines():
            linea = raw.strip()
            if not linea or linea.startswith(("#", ";")) or "=" not in linea:
                continue
            clave, _, valor = linea.partition("=")
            activas[clave.strip()] = valor.strip().strip('"').lower()

        NEGATIVOS = {"false", "no", "off", "0", ""}
        essential_directives = [
            ("NoNewPrivileges", "true", "ALTO", "Previene escalada de privilegios SUID."),
            ("ProtectSystem", None, "MEDIO", "Protege archivos del sistema (/usr, /boot, /etc) contra escritura."),
            ("ProtectHome", "true", "MEDIO", "Aísla los directorios personales de usuarios."),
            ("PrivateTmp", "true", "BAJO", "Aísla el directorio de archivos temporales /tmp."),
        ]

        for clave, esperado, level, reason in essential_directives:
            actual = activas.get(clave)
            if actual is None:
                findings.append((clave, level, f"Falta la directiva de aislamiento '{clave}='. {reason}"))
            elif actual in NEGATIVOS:
                mostrado = actual or "vacío"
                findings.append((clave, level, f"'{clave}={mostrado}' desactiva la protección. {reason}"))
            elif esperado is not None and actual != esperado:
                findings.append((clave, level, f"'{clave}={actual}' no es '{esperado}'. {reason}"))

        if not findings:
            findings.append(("SYSTEMD", "OK", "El archivo de servicio cuenta con aislamiento de seguridad defensivo."))

        return findings
