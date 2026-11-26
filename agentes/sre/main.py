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
    print_header("Agente SRE, Observabilidad y Monitoreo")
    print("Módulos Prometheus Exporter, Health Checker, Log Auditor y Motor de Alertas SLA cargados.")

    current_dir = agent_output_dir(__file__)

    # Emisión de eventos JSON estructurados con enmascaramiento automático de campos sensibles.
    print_header("Demostración 1: Formateo de Logs Estructurados JSON (SRE Standard)")

    logger = StructuredLogger(service_name="payment-gateway")
    print(logger.info("Transacción procesada correctamente", context={"user_id": 404, "amount": 99.0}))
    print(logger.warning("Credenciales sensibles enmascaradas", context={"password": "secret_password_123"}))

    # Inspección automatizada de registros en busca de trazas de fallo, saturación de memoria y respuestas 5xx.
    print_header("Demostración 2: Auditoría SRE de Anomalías e Incidentes en Logs")

    sample_log_path = os.path.join(current_dir, "sample_app.log")
    log_data = """2026-07-28T12:00:01Z [INFO] Servicio iniciado en puerto 8080
2026-07-28T12:01:15Z [ERROR] Authentication failed for user 'admin'
2026-07-28T12:02:30Z [ERROR] Traceback (most recent call last): File 'main.py', line 45, in <module>
2026-07-28T12:03:00Z [WARN] OutOfMemoryError: Java heap space exhausted
2026-07-28T12:04:10Z "GET /api/data HTTP/1.1" 500 1024
"""
    with open(sample_log_path, "w", encoding="utf-8") as f:
        f.write(log_data)

    findings = LogAnomalyAuditor.audit_log_file(sample_log_path)
    print(f"Auditando archivo de log: {sample_log_path}...")
    for line, level, desc, snippet in findings:
        print(f"Línea {line} [{level}] -> {desc}")

    # Evaluación de preparación operativa verificando espacio disponible en disco y estado del entorno.
    print_header("Demostración 3: Sonda de Salud y Métricas SRE (Readiness Probe)")

    health = SystemHealthChecker.check_health(min_free_mb=1.0)
    print(f"Status global: {health['status']}")
    for check in health.get("checks", []):
        print(f"  - [{check.get('name')}] ok={check.get('ok')} → {check.get('detail')}")

    # Serialización de contadores y calibradores en el formato de exposición textual de Prometheus.
    print_header("Demostración 4: Exportador de Métricas Prometheus (/metrics)")

    prom_metrics = PrometheusExporter.generate_metrics(requests_total=1050, errors_total=12, uptime_seconds=3600.0)
    print("Métricas Prometheus (Exposition Format 0.0.4):")
    print("-" * 50)
    print(prom_metrics.strip())
    print("-" * 50)

    # Evaluación de presupuesto de fallos y disparo de alertas cuando se supera el umbral SLA.
    print_header("Demostración 5: Motor de Alertas de Tasa de Errores SLA")

    alert_triggered, msg = AlertingEngine.evaluate_error_rate(total_requests=100, error_requests=8, max_error_rate_pct=5.0)
    print("Evaluación de Tráfico (8% de Errores / Máx 5%):")
    print(f"  Resultado: {msg}")

    print("\n" + "=" * 65)
    print(" Agente SRE ejecutado exitosamente.")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    main()
