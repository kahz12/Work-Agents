from typing import Tuple


class AlertingEngine:
    """
    Motor de alertas por umbral de SLA (SRE Alerting Engine).
    Evalúa la tasa de errores en logs y dispara alertas si supera los límites definidos.
    """

    @staticmethod
    def evaluate_error_rate(total_requests: int, error_requests: int, max_error_rate_pct: float = 5.0) -> Tuple[bool, str]:
        """
        Evalúa si la tasa de errores excede el SLA permitido.
        Retorna (Hay_Alerta, Mensaje_Alerta).
        """
        if total_requests <= 0:
            return False, "Sin tráfico registrado."

        error_rate = (error_requests / total_requests) * 100.0
        if error_rate > max_error_rate_pct:
            return True, f"ALERTA CRÍTICA SLA: Tasa de errores en {error_rate:.2f}% excede el límite del {max_error_rate_pct}%."

        return False, f"OK: Tasa de errores en {error_rate:.2f}% está dentro del SLA ({max_error_rate_pct}%)."
