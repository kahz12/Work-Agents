import ast
from typing import List, Tuple


class ArchitectureDiagramGenerator:
    """Builds Mermaid.js class diagrams from Python source, without importing it."""

    @staticmethod
    def generate_mermaid_diagram(filepath: str) -> str:
        """
        Mermaid class diagram for the classes in a Python file, with their methods and
        inheritance. Errors come back as a Mermaid comment (%% ... %%), so the result is always
        valid Mermaid.
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            tree = ast.parse(content, filename=filepath)
        except FileNotFoundError:
            return "%% File not found %%"
        except (IsADirectoryError, PermissionError, OSError, SyntaxError, UnicodeDecodeError, ValueError, TypeError, RecursionError) as e:
            return f"%% Could not generate the diagram: {e} %%"

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
            # Show at most five methods per class so large classes do not swamp the diagram.
            for m in methods[:5]:
                mermaid_lines.append(f"        +{m}()")
            mermaid_lines.append("    }")
            if len(methods) > 5:
                mermaid_lines.append(f"    %% +{len(methods) - 5} more methods in {name}")

            for b in bases:
                mermaid_lines.append(f"    {b} <|-- {name}")

        return "\n".join(mermaid_lines)
