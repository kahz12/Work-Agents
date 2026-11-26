import datetime
import json
import uuid
from typing import Any, Dict, Optional


class StructuredLogger:
    """
    Formateador de logs estructurados en JSON en cumplimiento con estándares SRE/Observabilidad.
    Enriquece cada registro con ISO 8601, trace_id, level y enmascaramiento de datos sensibles.
    """

    SENSITIVE_KEYS = {"password", "secret", "token", "authorization", "api_key"}

    def __init__(self, service_name: str = "app-service"):
        self.service_name = service_name

    def _mask_sensitive_data(self, data: Any) -> Any:
        if isinstance(data, dict):
            masked = {}
            for k, v in data.items():
                if str(k).lower() in self.SENSITIVE_KEYS:
                    masked[k] = "***MASKED***"
                else:
                    masked[k] = self._mask_sensitive_data(v)
            return masked
        elif isinstance(data, list):
            return [self._mask_sensitive_data(item) for item in data]
        return data

    def format_log(
        self,
        level: str,
        message: str,
        context: Optional[Dict[str, Any]] = None,
        trace_id: Optional[str] = None
    ) -> str:
        """
        Formatea un mensaje de log en una cadena JSON estandarizada.
        """
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        log_entry = {
            "timestamp": now,
            "service": self.service_name,
            "level": level.upper(),
            "message": message,
            "trace_id": trace_id or str(uuid.uuid4()),
            "context": self._mask_sensitive_data(context or {})
        }
        return json.dumps(log_entry, default=str)

    def info(self, message: str, context: Optional[Dict[str, Any]] = None, trace_id: Optional[str] = None) -> str:
        return self.format_log("INFO", message, context, trace_id)

    def warning(self, message: str, context: Optional[Dict[str, Any]] = None, trace_id: Optional[str] = None) -> str:
        return self.format_log("WARN", message, context, trace_id)

    def error(self, message: str, context: Optional[Dict[str, Any]] = None, trace_id: Optional[str] = None) -> str:
        return self.format_log("ERROR", message, context, trace_id)

    def critical(self, message: str, context: Optional[Dict[str, Any]] = None, trace_id: Optional[str] = None) -> str:
        return self.format_log("CRITICAL", message, context, trace_id)
