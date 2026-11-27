#!/usr/bin/env python3
import os

from ..common.workspace import agent_output_dir
from .alerting_engine import AlertingEngine
from .health_checker import SystemHealthChecker
from .log_anomaly_auditor import LogAnomalyAuditor
from .prometheus_exporter import PrometheusExporter
from .structured_logger import StructuredLogger


def print_header(title: str):
    print("\n" + "=" * 65)
    print(f" {title.upper()}")
    print("=" * 65)

def main():
    print_header("SRE, Observability and Monitoring Agent")
    print("Loaded modules: Prometheus exporter, health checker, log auditor and SLA alerting engine.")

    current_dir = agent_output_dir(__file__)

    # Structured JSON events; sensitive fields are masked automatically.
    print_header("Demo 1: Structured JSON logs")

    logger = StructuredLogger(service_name="payment-gateway")
    print(logger.info("Transaction processed successfully", context={"user_id": 404, "amount": 99.0}))
    print(logger.warning("Sensitive credentials are masked", context={"password": "secret_password_123"}))

    # Scan a log for tracebacks, memory exhaustion and 5xx responses.
    print_header("Demo 2: Log anomaly and incident audit")

    sample_log_path = os.path.join(current_dir, "sample_app.log")
    log_data = """2026-07-28T12:00:01Z [INFO] Service started on port 8080
2026-07-28T12:01:15Z [ERROR] Authentication failed for user 'admin'
2026-07-28T12:02:30Z [ERROR] Traceback (most recent call last): File 'main.py', line 45, in <module>
2026-07-28T12:03:00Z [WARN] OutOfMemoryError: Java heap space exhausted
2026-07-28T12:04:10Z "GET /api/data HTTP/1.1" 500 1024
"""
    with open(sample_log_path, "w", encoding="utf-8") as f:
        f.write(log_data)

    findings = LogAnomalyAuditor.audit_log_file(sample_log_path)
    print(f"Auditing log file: {sample_log_path}...")
    for line, level, desc, snippet in findings:
        print(f"Line {line} [{level}] -> {desc}")

    # Readiness check: free disk space and system load.
    print_header("Demo 3: Health probe (readiness)")

    health = SystemHealthChecker.check_health(min_free_mb=1.0)
    print(f"Overall status: {health['status']}")
    for check in health.get("checks", []):
        print(f"  - [{check.get('name')}] ok={check.get('ok')} → {check.get('detail')}")

    # Counters and gauges in Prometheus' text exposition format.
    print_header("Demo 4: Prometheus metrics exporter (/metrics)")

    prom_metrics = PrometheusExporter.generate_metrics(requests_total=1050, errors_total=12, uptime_seconds=3600.0)
    print("Prometheus metrics (exposition format 0.0.4):")
    print("-" * 50)
    print(prom_metrics.strip())
    print("-" * 50)

    # Error budget check: the alert fires once the SLA threshold is exceeded.
    print_header("Demo 5: SLA error-rate alerting engine")

    alert_triggered, msg = AlertingEngine.evaluate_error_rate(total_requests=100, error_requests=8, max_error_rate_pct=5.0)
    print("Traffic evaluation (8% errors / 5% max):")
    print(f"  Result: {msg}")

    print("\n" + "=" * 65)
    print(" SRE agent finished successfully.")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    main()
