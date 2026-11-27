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
    print_header("QA and Test Automation Agent")
    print("Loaded modules: test generation, test execution, HTTP API testing and QA reports.")

    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    current_dir = agent_output_dir(__file__)
    fixtures_dir = os.path.join(pkg_dir, "fixtures")

    # -----------------------------------------------------------------
    # Copy the sample_app.py fixture into the working directory and generate
    # its unittest suite, the adversarial pytest suite, the testability audit
    # and the scenario matrix.
    # -----------------------------------------------------------------
    print_header("Demo 1: Automatic unit test suite generation")

    fixture_app = os.path.join(fixtures_dir, "sample_app.py")
    source_app = os.path.join(current_dir, "sample_app.py")
    shutil.copy2(fixture_app, source_app)

    test_file = os.path.join(current_dir, "test_sample_app.py")
    generated_path = QATestGenerator.generate_test_suite(source_app, test_file)
    print(f"Source fixture: {fixture_app}")
    print(f"Test suite written to: {generated_path}")

    testability = QATestGenerator.audit_testability(source_app)
    scenarios = QATestGenerator.build_scenario_matrix(source_app)
    pytest_adv = os.path.join(current_dir, "test_sample_app_pytest.py")
    adv_report = os.path.join(current_dir, "qa_adversarial_report.md")
    QAReporter.generate_adversarial_qa_report(source_app, pytest_adv, adv_report)
    print(f"Testability defects found: {len(testability)} | Adversarial scenarios: {len(scenarios)}")
    print(f"pytest suite: {pytest_adv} | SDET report: {adv_report}")

    # -----------------------------------------------------------------
    # Run the generated unittest suite and report how many tests pass and fail,
    # and how long it takes.
    # -----------------------------------------------------------------
    print_header("Demo 2: Running the test suite")

    unit_results = QATestRunner.run_unittest_suite(test_file)
    print(f"Tests run: {unit_results.get('tests_run')}")
    print(f"Tests passed: {unit_results.get('passed')}")
    print(f"Failures/errors: {unit_results.get('failures') + unit_results.get('errors')}")
    print(f"Pass rate: {unit_results.get('pass_rate_percentage')}%")
    print(f"Duration: {unit_results.get('duration_seconds')}s")

    # -----------------------------------------------------------------
    # API contracts: validate two simulated responses (the second one breaks
    # the 500 ms SLA on purpose) and a real request to a local HTTP server
    # listening on a free 127.0.0.1 port.
    # -----------------------------------------------------------------
    print_header("Demo 3: API contract and SLA tests")

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
            # Keep the demo output clean: no per-request log line on stderr.
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
        status = "PASSED" if r["passed"] else "FAILED"
        print(f"Endpoint '{r['endpoint']}' [{r['elapsed_ms']}ms] -> {status}")

    # -----------------------------------------------------------------
    # QA report in Markdown and HTML with the suite and API contract results.
    # -----------------------------------------------------------------
    print_header("Demo 4: QA reports")

    md_report = os.path.join(current_dir, "qa_report.md")
    html_report = os.path.join(current_dir, "qa_report.html")

    QAReporter.generate_markdown_report(unit_results, api_results, md_report)
    QAReporter.generate_html_report(unit_results, api_results, html_report)

    print(f"Markdown QA report written to: {md_report}")
    print(f"HTML QA report written to: {html_report}")

    print("\n" + "=" * 65)
    print(" QA agent finished successfully.")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
