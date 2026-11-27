import os
from typing import List, Tuple


class ServiceHardening:
    """
    Audits systemd service units and generates hardened ones, using Linux namespaces,
    filesystem isolation and privilege restrictions.
    """

    SYSTEMD_SERVICE_TEMPLATE = """[Unit]
Description=Hardened application service
After=network.target

[Service]
Type=simple
User=appuser
Group=appgroup
WorkingDirectory=/opt/my_app
ExecStart=/usr/bin/python3 /opt/my_app/main.py
Restart=on-failure

# ---------------------------------------------------------
# Hardening and isolation directives
# ---------------------------------------------------------
# The process can never gain new privileges (setuid/setgid binaries)
NoNewPrivileges=true

# Mount the whole OS filesystem read-only, except the paths listed below
ProtectSystem=strict
ReadWritePaths=/var/log/my_app /tmp

# No access to /home, /root or /run/user
ProtectHome=true

# Private /tmp namespace for this service
PrivateTmp=true

# Hide hardware devices under /dev
PrivateDevices=true

# Block changes to kernel tunables (sysctl)
ProtectKernelTunables=true

# Block loading kernel modules
ProtectKernelModules=true

# Empty bounding set: the process holds no Linux capabilities at all
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
"""

    @staticmethod
    def generate_hardened_service(target_path: str) -> str:
        """
        Write the hardened unit template to target_path and return the path.
        """
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(ServiceHardening.SYSTEMD_SERVICE_TEMPLATE)
        return target_path

    @staticmethod
    def audit_systemd_service(filepath: str) -> List[Tuple[str, str, str]]:
        """
        Check a systemd .service file for the essential isolation directives.
        Returns (directive, level, message) tuples, or a single OK entry.
        """
        findings = []
        if not os.path.exists(filepath):
            return [("N/A", "ERROR", f"Service file '{filepath}' does not exist.")]

        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        # Active directives: key -> value. Comments are skipped, because a commented-out
        # directive enforces nothing even though its text is present in the file.
        active = {}
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", ";")) or "=" not in line:
                continue
            key, _, value = line.partition("=")
            active[key.strip()] = value.strip().strip('"').lower()

        # Values systemd treats as "off". An empty assignment resets the directive to its
        # default, which for these directives means no protection.
        disabled_values = {"false", "no", "off", "0", ""}
        essential_directives = [
            # (directive, required value or None for "any enabling value", level, why it matters)
            ("NoNewPrivileges", "true", "HIGH", "It prevents privilege escalation through setuid binaries."),
            ("ProtectSystem", None, "MEDIUM", "It protects system files (/usr, /boot, /etc) against writes."),
            ("ProtectHome", "true", "MEDIUM", "It isolates users' home directories."),
            ("PrivateTmp", "true", "LOW", "It isolates the temporary files directory /tmp."),
        ]

        for key, expected, level, reason in essential_directives:
            current = active.get(key)
            if current is None:
                findings.append((key, level, f"Missing isolation directive '{key}='. {reason}"))
            elif current in disabled_values:
                shown = current or "empty"
                findings.append((key, level, f"'{key}={shown}' disables the protection. {reason}"))
            elif expected is not None and current != expected:
                findings.append((key, level, f"'{key}={current}' is not '{expected}'. {reason}"))

        if not findings:
            findings.append(("SYSTEMD", "OK", "The service file has the essential isolation directives."))

        return findings
