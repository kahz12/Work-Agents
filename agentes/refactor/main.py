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
    print_header("Refactoring and Architecture Agent")
    print("Loaded modules: cognitive complexity and Mermaid.js diagrams.")

    current_dir = agent_output_dir(__file__)

    # Cyclomatic and cognitive complexity plus the performance audit, on a deliberately messy class.
    print_header("Demo 1: Code metrics and cognitive complexity")

    sample_file = os.path.join(current_dir, "sample_monolith.py")
    monolith_code = '''class MonolithicService:
    def __init__(self):
        self.db = DatabaseClient()
        self.logger = FileLogger()

    def process_data(self, kind, data):
        if kind == "A":
            if data:
                for x in data:
                    if x > 10 and x < 100:
                        print(x)
        elif kind == "B":
            while data:
                data.pop()

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
    print(f"Analysed file: {metrics['filepath']}")
    print(f"Total lines: {metrics['total_lines']} | Lines of code (LOC): {metrics['code_loc']}")
    print(f"Average cyclomatic complexity: {metrics['avg_cyclomatic_complexity']}")
    print(f"Average cognitive complexity: {metrics['avg_cognitive_complexity']}")

    # Class diagram and inheritance hierarchy in Mermaid.js syntax.
    print_header("Demo 2: Mermaid.js diagram")

    diagram = ArchitectureDiagramGenerator.generate_mermaid_diagram(sample_file)
    print("Mermaid.js class diagram:")
    print("-" * 50)
    print(diagram)
    print("-" * 50)

    # SOLID and reliability audit, then the refactoring plan built from all findings.
    print_header("Demo 3: SOLID audit and recommendations")

    solid_findings = SOLIDChecker.audit_file(sample_file)
    for line, principle, level, msg in solid_findings:
        print(f"Line {line} [{principle}] [{level}]: {msg}")

    for line, cat, level, msg in metrics.get("performance_findings", []):
        print(f"Line {line} [{cat}] [{level}]: {msg}")

    recs = RefactorSuggester.generate_recommendations(metrics, solid_findings)
    print("\nRecommended refactoring plan:")
    for idx, rec in enumerate(recs, 1):
        print(f"  {idx}. {rec}")

    print("\n" + "=" * 65)
    print(" Refactoring agent finished successfully.")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    main()
