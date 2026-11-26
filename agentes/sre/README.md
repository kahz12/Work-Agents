# Agente SRE, Observabilidad y Monitoreo

Logs estructurados, anomalías, health real, Prometheus y alertas SLA.

## Estructura

- `structured_logger.py` — JSON ISO-8601, trace_id, máscara de secretos.
- `log_anomaly_auditor.py` — Traceback, 5xx, OOM, auth, conectividad.
- `health_checker.py` — Disco / TCP / HTTP → HEALTHY|DEGRADED|UNHEALTHY.
- `prometheus_exporter.py` — Texto `/metrics` y **servidor vivo** `/metrics` + `/healthz`.
- `alerting_engine.py` — Alertas por tasa de error SLA.
- `main.py` — Demo.

## Uso

```bash
agentes demo sre               # demo con datos de ejemplo
python -m agentes.sre.main     # lo mismo, sin pasar por el CLI
agentes serve --port 9100
agentes health --tcp localhost:5432
```

