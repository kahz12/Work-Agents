# SRE, Observability and Monitoring Agent

Structured logs, log anomaly detection, real health checks, Prometheus metrics and SLA alerting.

## Layout

- `structured_logger.py` — JSON logs with ISO 8601 timestamps, a trace_id and masking of sensitive keys.
- `log_anomaly_auditor.py` — Tracebacks, 5xx responses, OOM, authentication failures and connectivity errors.
- `health_checker.py` — Disk / load / TCP / HTTP probes → HEALTHY | DEGRADED | UNHEALTHY.
- `prometheus_exporter.py` — `/metrics` text output and a **live server** for `/metrics` + `/healthz`.
- `alerting_engine.py` — SLA error-rate alerts.
- `main.py` — Demo.

## Usage

```bash
agentes demo sre               # demo on sample data
python -m agentes.sre.main     # the same, without going through the CLI
agentes serve --port 9100
agentes health --tcp localhost:5432
```
