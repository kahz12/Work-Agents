#!/usr/bin/env python3
import json
import os
import shutil
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from ..common.workspace import agent_output_dir
from .api_contract_testing import APIContractTester
from .qa_reporter import QAReporter
from .test_generator import QATestGenerator
from .test_runner import QATestRunner


def print_header(title: str):
    print("\n" + "=" * 65)
    print(f" {title.upper()}")
    print("=" * 65)


def main():
    print_header("Agente QA y Automatización de Pruebas")
    print("Módulos de Generación, Ejecución, API Testing HTTP y Reportes QA cargados.")

    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    current_dir = agent_output_dir(__file__)
    fixtures_dir = os.path.join(pkg_dir, "fixtures")

    # -----------------------------------------------------------------
    # Copia el fixture sample_app.py al directorio de trabajo y genera su suite
    # unittest, la suite pytest adversaria, la auditoría de testabilidad y la
    # matriz de escenarios.
    # -----------------------------------------------------------------
    print_header("Demostración 1: Generación Automatizada de Suite de Pruebas Unitarias")

    fixture_app = os.path.join(fixtures_dir, "sample_app.py")
    source_app = os.path.join(current_dir, "sample_app.py")
    shutil.copy2(fixture_app, source_app)

    test_file = os.path.join(current_dir, "test_sample_app.py")
    generated_path = QATestGenerator.generate_test_suite(source_app, test_file)
    print(f"Fixture fuente: {fixture_app}")
    print(f"Suite de pruebas generada en: {generated_path}")

    testability = QATestGenerator.audit_testability(source_app)
    scenarios = QATestGenerator.build_scenario_matrix(source_app)
    pytest_adv = os.path.join(current_dir, "test_sample_app_pytest.py")
    adv_report = os.path.join(current_dir, "qa_adversarial_report.md")
    QAReporter.generate_adversarial_qa_report(source_app, pytest_adv, adv_report)
    print(f"Defectos de testabilidad detectados: {len(testability)} | Escenarios adversarios: {len(scenarios)}")
    print(f"Suite pytest generada: {pytest_adv} | Reporte SDET: {adv_report}")

    # -----------------------------------------------------------------
    # Ejecuta la suite unittest generada y muestra cuántas pruebas pasan, fallan
    # y cuánto tarda.
    # -----------------------------------------------------------------
    print_header("Demostración 2: Ejecución Dinámica de Suite de Pruebas")

    unit_results = QATestRunner.run_unittest_suite(test_file)
    print(f"Pruebas ejecutadas: {unit_results.get('tests_run')}")
    print(f"Pruebas pasadas: {unit_results.get('passed')}")
    print(f"Fallos/Errores: {unit_results.get('failures') + unit_results.get('errors')}")
    print(f"Tasa de Éxito: {unit_results.get('pass_rate_percentage')}%")
    print(f"Duración: {unit_results.get('duration_seconds')}s")

    # -----------------------------------------------------------------
    # Contratos de API: valida dos respuestas simuladas (la segunda supera a
    # propósito el SLA de 500 ms) y una petición real a un servidor HTTP local
    # que escucha en un puerto libre de 127.0.0.1.
    # -----------------------------------------------------------------
    print_header("Demostración 3: Pruebas de Contrato de API e Integración SLA")

    api_results = []

    res1 = APIContractTester.validate_api_response(
        endpoint="/api/v1/users",
        response_status=200,
        response_data={"id": 1, "username": "admin_qa"},
        response_headers={"Content-Type": "application/json"},
        elapsed_ms=120.5,
        expected_status=200,
        expected_schema={"id": int, "username": str},
        max_sla_ms=300.0
    )
    api_results.append(res1)

    res2 = APIContractTester.validate_api_response(
        endpoint="/api/v1/reports",
        response_status=200,
        response_data={"report_id": 100, "status": "completed"},
        response_headers={"Content-Type": "application/json"},
        elapsed_ms=650.0,
        expected_status=200,
        expected_schema={"report_id": int, "status": str},
        max_sla_ms=500.0
    )
    api_results.append(res2)

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def do_GET(self):
            body = json.dumps({"id": 1, "name": "local"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        http_res = APIContractTester.request_and_validate(
            f"http://127.0.0.1:{port}/users",
            expected_status=200,
            expected_schema={"id": int, "name": str},
            max_sla_ms=1000.0,
        )
        api_results.append(http_res)
    finally:
        server.shutdown()

    for r in api_results:
        estado = "PASSED" if r["passed"] else "FAILED"
        print(f"Endpoint '{r['endpoint']}' [{r['elapsed_ms']}ms] -> {estado}")

    # -----------------------------------------------------------------
    # Informe de QA en Markdown y en HTML con los resultados de la suite y de
    # los contratos de API.
    # -----------------------------------------------------------------
    print_header("Demostración 4: Generación de Informes QA")

    md_report = os.path.join(current_dir, "qa_report.md")
    html_report = os.path.join(current_dir, "qa_report.html")

    QAReporter.generate_markdown_report(unit_results, api_results, md_report)
    QAReporter.generate_html_report(unit_results, api_results, html_report)

    print(f"Informe QA en Markdown generado: {md_report}")
    print(f"Informe QA en HTML interactivo generado: {html_report}")

    print("\n" + "=" * 65)
    print(" Agente QA ejecutado exitosamente.")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
