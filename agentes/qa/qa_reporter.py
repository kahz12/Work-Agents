import html
import os
from typing import Any, Dict, List


class QAReporter:
    """
    Generador de informes de pruebas y QA Adversario en Markdown y HTML.
    """

    @staticmethod
    def generate_markdown_report(unit_test_results: Dict[str, Any], api_results: List[Dict[str, Any]], output_filepath: str) -> str:
        """
        Genera un informe detallado de QA en formato Markdown.
        """
        lines = [
            "# Informe Ejecutivo de Pruebas y Aseguramiento de Calidad (QA)",
            "",
            "## 1. Resumen de Pruebas Unitarias",
            f"- **Archivo de Pruebas**: `{unit_test_results.get('test_file', 'N/A')}`",
            f"- **Duración Total**: `{unit_test_results.get('duration_seconds', 0)}s`",
            f"- **Pruebas Ejecutadas**: `{unit_test_results.get('tests_run', 0)}`",
            f"- **Pruebas Exitosas (Passed)**: `{unit_test_results.get('passed', 0)}`",
            f"- **Fallos / Errores**: `{unit_test_results.get('failures', 0) + unit_test_results.get('errors', 0)}`",
            f"- **Tasa de Éxito**: `{unit_test_results.get('pass_rate_percentage', 0)}%`",
            "",
            "## 2. Resumen de Pruebas de Contrato de API",
            "| Endpoint | SLA (ms) | Resultado |",
            "| :--- | :---: | :---: |",
        ]

        for res in api_results:
            status_str = "APROBADO" if res.get("passed") else "FALLO"
            lines.append(f"| `{res.get('endpoint')}` | `{res.get('elapsed_ms')}ms` | {status_str} |")

        lines.extend([
            "",
            "## 3. Detalles de Aseveraciones de API",
        ])

        for res in api_results:
            lines.append(f"### Endpoint: `{res.get('endpoint')}`")
            for ass_name, ass_status, ass_msg in res.get("assertions", []):
                icon = "[OK]" if ass_status == "OK" else "[FALLO]"
                lines.append(f"- {icon} **{ass_name}**: {ass_msg}")

        report_str = "\n".join(lines)
        with open(output_filepath, "w", encoding="utf-8") as f:
            f.write(report_str)

        return output_filepath

    @staticmethod
    def generate_adversarial_qa_report(
        source_filepath: str,
        output_test_filepath: str,
        output_report_filepath: str,
    ) -> str:
        """
        Construye la suite pytest adversaria junto con un reporte técnico en Markdown
        que reúne defectos de testabilidad, matriz de escenarios y código de pruebas generado.
        """
        from .test_generator import QATestGenerator

        testability_findings = QATestGenerator.audit_testability(source_filepath)
        scenarios = QATestGenerator.build_scenario_matrix(source_filepath)
        suite_path = QATestGenerator.generate_pytest_suite(source_filepath, output_test_filepath)

        suite_code = ""
        if suite_path:
            with open(suite_path, "r", encoding="utf-8") as sf:
                suite_code = sf.read()

        lines: List[str] = [
            f"# Auditoría SDET y QA Adversario: `{os.path.basename(source_filepath)}`",
            "",
            "## 1. Defectos de Testabilidad (Code Smells para QA)",
        ]

        if not testability_findings:
            lines.append("- Sin defectos críticos de testabilidad detectados (código desacoplado y determinista).")
        else:
            for line, code, level, msg in testability_findings:
                lines.append(f"- **Línea {line} [{code}] [{level}]**: {msg}")

        lines.extend([
            "",
            "## 2. Matriz de Escenarios de Prueba",
            "| Objetivo | Categoría | Escenario | Entradas / Fallo Simulado | Contrato Esperado |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])

        for sc in scenarios:
            inp = sc["input_summary"].replace("|", "\\|")
            exp = sc["expected"].replace("|", "\\|")
            lines.append(
                f"| `{sc['target']}` | {sc['category']} | `{sc['scenario']}` | `{inp}` | {exp} |"
            )

        lines.extend([
            "",
            f"## 3. Suite de Pruebas Lista para Producción (`{os.path.basename(output_test_filepath)}`)",
            "```python",
            suite_code.rstrip(),
            "```",
            "",
        ])

        with open(output_report_filepath, "w", encoding="utf-8") as rf:
            rf.write("\n".join(lines))

        return output_report_filepath

    @staticmethod
    def generate_html_report(unit_test_results: Dict[str, Any], api_results: List[Dict[str, Any]], output_filepath: str) -> str:
        """
        Genera un informe HTML interactivo con estilos modernos y escape XSS para QA.
        """
        tests_run = html.escape(str(unit_test_results.get("tests_run", 0)))
        passed = html.escape(str(unit_test_results.get("passed", 0)))
        fail_err = html.escape(str(unit_test_results.get("failures", 0) + unit_test_results.get("errors", 0)))
        pass_rate = html.escape(str(unit_test_results.get("pass_rate_percentage", 0)))

        html_template = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Reporte de Aseguramiento de Calidad (QA)</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }}
        .container {{ max-width: 900px; margin: 0 auto; background: #1e293b; border-radius: 10px; padding: 30px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
        h1 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
        h2 {{ color: #a78bfa; margin-top: 30px; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
        .metric-card {{ background: #334155; padding: 15px; border-radius: 8px; text-align: center; }}
        .metric-value {{ font-size: 24px; font-weight: bold; color: #4ade80; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px; border: 1px solid #334155; text-align: left; }}
        th {{ background: #0f172a; color: #38bdf8; }}
        .pass {{ color: #4ade80; font-weight: bold; }}
        .fail {{ color: #f87171; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Informe de Aseguramiento de Calidad (QA)</h1>

        <h2>1. Métricas de Pruebas Unitarias</h2>
        <div class="metrics-grid">
            <div class="metric-card"><div>Ejecutadas</div><div class="metric-value">{tests_run}</div></div>
            <div class="metric-card"><div>Exitosas</div><div class="metric-value" style="color:#4ade80">{passed}</div></div>
            <div class="metric-card"><div>Fallos</div><div class="metric-value" style="color:#f87171">{fail_err}</div></div>
            <div class="metric-card"><div>Tasa de Éxito</div><div class="metric-value">{pass_rate}%</div></div>
        </div>

        <h2>2. Pruebas de Contrato de API</h2>
        <table>
            <thead>
                <tr><th>Endpoint</th><th>Latencia (SLA)</th><th>Resultado</th></tr>
            </thead>
            <tbody>
"""
        for r in api_results:
            cls = "pass" if r.get("passed") else "fail"
            txt = "PASSED" if r.get("passed") else "FAILED"
            endpoint_safe = html.escape(str(r.get("endpoint", "")))
            elapsed_safe = html.escape(str(r.get("elapsed_ms", 0)))
            html_template += f"<tr><td>{endpoint_safe}</td><td>{elapsed_safe}ms</td><td class='{cls}'>{txt}</td></tr>\n"

        html_template += """
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        with open(output_filepath, "w", encoding="utf-8") as f:
            f.write(html_template)

        return output_filepath
