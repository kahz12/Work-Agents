import os
import re
from typing import List, Tuple


class LogAnomalyAuditor:
    """
    Scans log files for incidents: uncaught exceptions, 5xx responses, authentication failures,
    memory exhaustion and connectivity errors. Each line is reported at most once, for the
    first pattern it matches.
    """

    ANOMALY_PATTERNS = [
        (r"(?i)Traceback \(most recent call last\)", "CRITICAL", "Uncaught exception (Traceback)."),
        (r"HTTP/\d\.\d\"?\s+5\d\d", "HIGH", "Internal server error response (HTTP 5xx)."),
        (r"(?i)(OutOfMemoryError|MemoryError|Out of memory)", "CRITICAL", "System memory exhausted (OOM)."),
        (r"(?i)(Authentication failed|Invalid password|Failed login)", "MEDIUM", "Failed authentication attempt or possible brute force."),
        (r"(?i)(ConnectionRefusedError|DatabaseConnectionError|TimeoutError)", "HIGH", "Connectivity failure or timeout reaching a database or external service.")
    ]

    @staticmethod
    def audit_log_file(filepath: str) -> List[Tuple[int, str, str, str]]:
        """
        Audit a log file. Returns (line, severity, description, snippet) tuples; snippets are
        truncated to 80 characters.
        """
        findings = []
        if not os.path.exists(filepath):
            return [(0, "ERROR", "N/A", f"Log file '{filepath}' not found.")]

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
            findings.append((0, "ERROR", "N/A", f"Could not process the log file: {str(e)}"))

        return findings
