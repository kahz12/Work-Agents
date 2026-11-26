import ast
from typing import List, Tuple


class ArchitectureDiagramGenerator:
    """Generador automatizado de diagramas de arquitectura de clases en formato Mermaid.js."""

    @staticmethod
    def generate_mermaid_diagram(filepath: str) -> str:
        """Analiza un archivo Python y genera un diagrama de clases Mermaid.js."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            tree = ast.parse(content, filename=filepath)
        except FileNotFoundError:
            return "%% Archivo no encontrado %%"
        except (IsADirectoryError, PermissionError, OSError, SyntaxError, UnicodeDecodeError, ValueError, TypeError, RecursionError) as e:
            return f"%% Error al generar diagrama: {e} %%"

        classes_info: List[Tuple[str, List[str], List[str]]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                class_name = node.name
                bases = [b.id for b in node.bases if isinstance(b, ast.Name)]
                methods = [m.name for m in node.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
                classes_info.append((class_name, bases, methods))

        mermaid_lines = ["classDiagram"]
        for name, bases, methods in classes_info:
            mermaid_lines.append(f"    class {name} {{")
            # Acotar la representación visual a cinco métodos públicos/privados para mantener legibilidad en el grafo Mermaid.
            for m in methods[:5]:
                mermaid_lines.append(f"        +{m}()")
            mermaid_lines.append("    }")
            if len(methods) > 5:
                mermaid_lines.append(f"    %% +{len(methods) - 5} métodos adicionales en {name}")

            for b in bases:
                mermaid_lines.append(f"    {b} <|-- {name}")

        return "\n".join(mermaid_lines)
