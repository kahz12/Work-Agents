import ast
import os


class MarkdownDocGenerator:
    """
    Generador automatizado de documentación técnica en Markdown para proyectos de software.
    """

    @staticmethod
    def generate_module_docs(source_filepath: str, output_filepath: str) -> str:
        """
        Analiza un archivo Python y produce un manual de referencia en Markdown.
        """
        if not os.path.exists(source_filepath):
            return ""

        with open(source_filepath, "r", encoding="utf-8") as f:
            content = f.read()

        filename = os.path.basename(source_filepath)
        tree = ast.parse(content, filename=source_filepath)
        module_doc = ast.get_docstring(tree) or "Sin documentación de módulo."

        lines = [
            f"# Documentación Técnica: `{filename}`",
            "",
            "## Descripción General",
            module_doc,
            "",
            "## Clases y Métodos",
        ]

        classes_found = False
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                classes_found = True
                c_doc = ast.get_docstring(node) or "Sin descripción."
                lines.append(f"### Clase `class {node.name}`")
                lines.append(f"> {c_doc}")
                lines.append("")
                lines.append("#### Métodos:")
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        m_doc = ast.get_docstring(item) or "Sin docstring."
                        args = [a.arg for a in item.args.args]
                        lines.append(f"- **`{item.name}({', '.join(args)})`**: {m_doc}")
                lines.append("")

        if not classes_found:
            lines.append("*No se detectaron clases en este archivo.*")

        lines.extend([
            "## Funciones Globales",
        ])

        funcs_found = False
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs_found = True
                f_doc = ast.get_docstring(node) or "Sin docstring."
                args = [a.arg for a in node.args.args]
                lines.append(f"- **`{node.name}({', '.join(args)})`**: {f_doc}")

        if not funcs_found:
            lines.append("*No se detectaron funciones globales.*")

        doc_str = "\n".join(lines)
        os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)
        with open(output_filepath, "w", encoding="utf-8") as f:
            f.write(doc_str)

        return output_filepath
