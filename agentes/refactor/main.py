#!/usr/bin/env python3
import os

from ..common.workspace import agent_output_dir
from .architecture_diagram import ArchitectureDiagramGenerator
from .code_metrics import CodeMetricsCalculator
from .refactor_suggester import RefactorSuggester
from .solid_checker import SOLIDChecker


def print_header(title: str):
    print("\n" + "=" * 65)
    print(f" {title.upper()}")
    print("=" * 65)

def main():
    print_header("Agente de Refactorización y Arquitectura")
    print("Módulos de Complejidad Cognitiva y Diagramas Mermaid.js cargados.")

    current_dir = agent_output_dir(__file__)

    # Análisis estructural de métricas ciclomáticas, complejidad cognitiva y rendimiento algorítmico.
    print_header("Demostración 1: Métricas de Código y Complejidad Cognitiva")

    sample_file = os.path.join(current_dir, "sample_monolith.py")
    monolith_code = '''class MonolithicService:
    def __init__(self):
        self.db = DatabaseClient()
        self.logger = FileLogger()

    def procesar_datos(self, tipo, datos):
        if tipo == "A":
            if datos:
                for x in datos:
                    if x > 10 and x < 100:
                        print(x)
        elif tipo == "B":
            while datos:
                datos.pop()

    def m1(self): pass
    def m2(self): pass
    def m3(self): pass
    def m4(self): pass
    def m5(self): pass
    def m6(self): pass
    def m7(self): pass
    def m8(self): pass
    def m9(self): pass
    def m10(self): pass
    def m11(self): pass
'''
    with open(sample_file, "w", encoding="utf-8") as f:
        f.write(monolith_code)

    metrics = CodeMetricsCalculator.calculate_file_metrics(sample_file)
    print(f"Archivo analizado: {metrics['filepath']}")
    print(f"Líneas Totales: {metrics['total_lines']} | Líneas de Código (LOC): {metrics['code_loc']}")
    print(f"Complejidad Ciclomática Promedio: {metrics['avg_cyclomatic_complexity']}")
    print(f"Complejidad Cognitiva Promedio: {metrics['avg_cognitive_complexity']}")

    # Construcción de diagrama de clases y jerarquía de herencia en sintaxis Mermaid.js.
    print_header("Demostración 2: Generación de Diagrama Mermaid.js")

    diagram = ArchitectureDiagramGenerator.generate_mermaid_diagram(sample_file)
    print("Diagrama de Clases Mermaid.js:")
    print("-" * 50)
    print(diagram)
    print("-" * 50)

    # Evaluación de principios SOLID, fiabilidad y síntesis de recomendaciones de refactorización.
    print_header("Demostración 3: Auditoría SOLID y Recomendaciones")

    solid_findings = SOLIDChecker.audit_file(sample_file)
    for line, principle, level, msg in solid_findings:
        print(f"Línea {line} [{principle}] [{level}]: {msg}")

    for line, cat, level, msg in metrics.get("performance_findings", []):
        print(f"Línea {line} [{cat}] [{level}]: {msg}")

    recs = RefactorSuggester.generate_recommendations(metrics, solid_findings)
    print("\nPlan de Refactorización Recomendado:")
    for idx, rec in enumerate(recs, 1):
        print(f"  {idx}. {rec}")

    print("\n" + "=" * 65)
    print(" Agente de Refactorización ejecutado exitosamente.")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    main()
