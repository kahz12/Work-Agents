from typing import Tuple


class AlertingEngine:
    """
    SLA threshold alerting: compares an error rate with the maximum the SLA allows.
    """

    @staticmethod
    def evaluate_error_rate(total_requests: int, error_requests: int, max_error_rate_pct: float = 5.0) -> Tuple[bool, str]:
        """
        Check whether the error rate exceeds the SLA. Returns (alert_fired, message).
        With no traffic there is no rate to judge, so no alert fires.
        """
        if total_requests <= 0:
            return False, "No traffic recorded."

        error_rate = (error_requests / total_requests) * 100.0
        if error_rate > max_error_rate_pct:
            return True, f"CRITICAL SLA ALERT: error rate {error_rate:.2f}% exceeds the {max_error_rate_pct}% limit."

        return False, f"OK: error rate {error_rate:.2f}% is within the SLA ({max_error_rate_pct}%)."
