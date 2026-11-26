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
    print_header("Agente de Calidad de Código y Auditoría SAST")
    print("Módulos de análisis Bandit, exportador SARIF y Auto-Fixer cargados.")

    current_dir = agent_output_dir(__file__)

    # Emisión de archivos de configuración estándar para herramientas de análisis estático y formato.
    print_header("Demostración 1: Generación de Archivos de Configuración Linter")

    f8_file = LinterConfigGenerator.generate_flake8_config(current_dir)
    toml_file = LinterConfigGenerator.generate_pyproject_toml(current_dir)
    eslint_file = LinterConfigGenerator.generate_eslint_config(current_dir)

    print(f"Archivo Flake8 creado: {f8_file}")
    print(f"Archivo pyproject.toml creado: {toml_file}")
    print(f"Archivo ESLint creado: {eslint_file}")

    # Auditoría de manifiesto de paquetes Python y fijación determinista de versiones declaradas.
    print_header("Demostración 2: Auditoría y Auto-Fixer de Manifiesto (requirements.txt)")

    req_file = os.path.join(current_dir, "requirements_sample.txt")
    with open(req_file, "w", encoding="utf-8") as f:
        f.write("requests\nflask>=2.0.0\nnumpy==1.24.0\n")

    print(f"Auditando manifiesto: {req_file}...")
    findings = DependencyAuditor.audit_requirements_txt(req_file)
    for pkg, nivel, rec in findings:
        print(f"[{nivel}] Paquete/Línea: {pkg} -> {rec}")

    print("\nCalculando versiones a fijar (última versión publicada en PyPI que cumple cada requisito)...")
    plan = DependencyAuditor.plan_requirements_fix(req_file)
    plan.apply()
    for line, old, new in plan.changes:
        print(f"  Línea {line}: {old} -> {new}")
    for line, package, reason in plan.unresolved:
        print(f"  Línea {line}: {package} sin cambios ({reason})")
    print(f"Auto-Fixer completado: {len(plan.changes)} paquete(s) corregido(s).")

    # Escaneo SAST sobre código de muestra intencionalmente vulnerable y exportación en formato SARIF.
    print_header("Demostración 3: Análisis Bandit SAST y Exportación SARIF v2.1.0")

    sample_code_file = os.path.join(current_dir, "sample_code.py")
    sample_code = '''import subprocess
import pickle

def funcion_peligrosa(comando_usuario, datos):
    # Ejecución dinámica de expresiones arbitrarias mediante eval() sobre entrada externa.
    resultado = eval(comando_usuario)

    # Deserialización binaria mediante pickle sobre bytes no confiables expone ejecución remota de código.
    obj = pickle.loads(datos)

    # Invocación de subproceso interpretado por shell del sistema facilita inyección de comandos.
    subprocess.Popen("ls -la " + comando_usuario, shell=True)

try:
    pass
except:
    pass
'''
    with open(sample_code_file, "w", encoding="utf-8") as f:
        f.write(sample_code)

    print(f"Analizando código con reglas Bandit SAST: {sample_code_file}...")
    issues = StaticCodeAnalyzer.analyze_python_file(sample_code_file)
    for line, nivel, desc in issues:
        print(f"Línea {line} [{nivel}]: {desc}")

    # Exportar los hallazgos consolidados en formato SARIF v2.1.0 para integración con repositorios Git.
    sarif_output = os.path.join(current_dir, "results.sarif")
    StaticCodeAnalyzer.export_to_sarif(sample_code_file, issues, sarif_output)
    print(f"\nReporte de análisis exportado en formato estándar SARIF: {sarif_output}")

    print("\n" + "=" * 65)
    print(" Agente de Calidad de Código ejecutado correctamente.")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    main()
