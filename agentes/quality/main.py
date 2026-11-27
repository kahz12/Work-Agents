#!/usr/bin/env python3
import os

from ..common.workspace import agent_output_dir
from .dependency_auditor import DependencyAuditor
from .linter_config import LinterConfigGenerator
from .static_checker import StaticCodeAnalyzer


def print_header(title: str):
    print("\n" + "=" * 65)
    print(f" {title.upper()}")
    print("=" * 65)

def main():
    print_header("Code Quality and SAST Agent")
    print("Loaded modules: Bandit analysis, SARIF exporter and dependency auto-fixer.")

    current_dir = agent_output_dir(__file__)

    # Baseline configuration files for linters and formatters.
    print_header("Demo 1: Linter configuration files")

    f8_file = LinterConfigGenerator.generate_flake8_config(current_dir)
    toml_file = LinterConfigGenerator.generate_pyproject_toml(current_dir)
    eslint_file = LinterConfigGenerator.generate_eslint_config(current_dir)

    print(f"Flake8 file created: {f8_file}")
    print(f"pyproject.toml file created: {toml_file}")
    print(f"ESLint file created: {eslint_file}")

    # Audit a Python requirements manifest, then pin its versions from PyPI.
    print_header("Demo 2: requirements.txt audit and auto-fixer")

    req_file = os.path.join(current_dir, "requirements_sample.txt")
    with open(req_file, "w", encoding="utf-8") as f:
        f.write("requests\nflask>=2.0.0\nnumpy==1.24.0\n")

    print(f"Auditing manifest: {req_file}...")
    findings = DependencyAuditor.audit_requirements_txt(req_file)
    for pkg, level, rec in findings:
        print(f"[{level}] Package: {pkg} -> {rec}")

    print("\nResolving versions to pin (latest PyPI release that satisfies each requirement)...")
    plan = DependencyAuditor.plan_requirements_fix(req_file)
    plan.apply()
    for line, old, new in plan.changes:
        print(f"  Line {line}: {old} -> {new}")
    for line, package, reason in plan.unresolved:
        print(f"  Line {line}: {package} unchanged ({reason})")
    print(f"Auto-fixer finished: {len(plan.changes)} package(s) pinned.")

    # SAST scan of deliberately vulnerable sample code, exported as SARIF.
    print_header("Demo 3: Bandit SAST analysis and SARIF 2.1.0 export")

    sample_code_file = os.path.join(current_dir, "sample_code.py")
    sample_code = '''import subprocess
import pickle

def dangerous_function(user_command, data):
    # eval() on external input runs arbitrary expressions.
    result = eval(user_command)

    # pickle.loads() on untrusted bytes allows remote code execution.
    obj = pickle.loads(data)

    # A shell-interpreted subprocess built from user input allows command injection.
    subprocess.Popen("ls -la " + user_command, shell=True)

try:
    pass
except:
    pass
'''
    with open(sample_code_file, "w", encoding="utf-8") as f:
        f.write(sample_code)

    print(f"Analysing code with the SAST rules: {sample_code_file}...")
    issues = StaticCodeAnalyzer.analyze_python_file(sample_code_file)
    for line, level, desc in issues:
        print(f"Line {line} [{level}]: {desc}")

    # SARIF 2.1.0 is what GitHub Code Scanning and most CI dashboards ingest.
    sarif_output = os.path.join(current_dir, "results.sarif")
    StaticCodeAnalyzer.export_to_sarif(sample_code_file, issues, sarif_output)
    print(f"\nAnalysis report exported as SARIF: {sarif_output}")

    print("\n" + "=" * 65)
    print(" Code quality agent finished successfully.")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    main()
