import os
import re
from typing import List, Tuple


class LogAnomalyAuditor:
    """
    Auditor SRE de anomalías e incidentes en archivos de registro (*Log Anomaly Auditor*).
    Detecta ráfagas de excepciones, errores 5xx, fallos de autenticación y fugas de memoria.
    """

    ANOMALY_PATTERNS = [
        (r"(?i)Traceback \(most recent call last\)", "CRITICO", "Ráfaga de excepciones no capturadas (Stack Traceback)."),
        (r"HTTP/\d\.\d\"?\s+5\d\d", "ALTO", "Spike de errores internos del servidor (HTTP 5xx)."),
        (r"(?i)(OutOfMemoryError|MemoryError|Out of memory)", "CRITICO", "Aviso de agotamiento de memoria del sistema (OOM)."),
        (r"(?i)(Authentication failed|Invalid password|Failed login)", "MEDIO", "Intento fallido de autenticación o posible fuerza bruta."),
        (r"(?i)(ConnectionRefusedError|DatabaseConnectionError|TimeoutError)", "ALTO", "Fallo de conectividad o tiempo de espera en base de datos/servicio externo.")
    ]

    @staticmethod
    def audit_log_file(filepath: str) -> List[Tuple[int, str, str, str]]:
        """
        Audita un archivo de log y retorna una lista de hallazgos (Línea, Severidad, Patrón, Fragmento).
        """
        findings = []
        if not os.path.exists(filepath):
            return [(0, "ERROR", "N/A", f"Archivo de log '{filepath}' no encontrado.")]

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    line_str = line.strip()
                    if not line_str:
                        continue

                    for pattern, severity, description in LogAnomalyAuditor.ANOMALY_PATTERNS:
                        if re.search(pattern, line_str):
                            masked_snippet = line_str[:80] + "..." if len(line_str) > 80 else line_str
                            findings.append((line_num, severity, description, masked_snippet))
                            break
        except Exception as e:
            findings.append((0, "ERROR", "N/A", f"Error al procesar archivo de log: {str(e)}"))

        return findings
