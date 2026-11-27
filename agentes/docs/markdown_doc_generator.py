import ast
import os


class MarkdownDocGenerator:
    """
    Builds a Markdown reference manual from a Python module's docstrings, without importing it.
    """

    @staticmethod
    def generate_module_docs(source_filepath: str, output_filepath: str) -> str:
        """
        Write a Markdown reference for the classes, methods and top-level functions of a
        Python file. Returns the output path, or "" when the source file does not exist.
        """
        if not os.path.exists(source_filepath):
            return ""

        with open(source_filepath, "r", encoding="utf-8") as f:
            content = f.read()

        filename = os.path.basename(source_filepath)
        tree = ast.parse(content, filename=source_filepath)
        module_doc = ast.get_docstring(tree) or "No module documentation."

        lines = [
            f"# Technical Documentation: `{filename}`",
            "",
            "## Overview",
            module_doc,
            "",
            "## Classes and Methods",
        ]

        classes_found = False
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                classes_found = True
                c_doc = ast.get_docstring(node) or "No description."
                lines.append(f"### Class `class {node.name}`")
                lines.append(f"> {c_doc}")
                lines.append("")
                lines.append("#### Methods:")
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        m_doc = ast.get_docstring(item) or "No docstring."
                        args = [a.arg for a in item.args.args]
                        lines.append(f"- **`{item.name}({', '.join(args)})`**: {m_doc}")
                lines.append("")

        if not classes_found:
            lines.append("*No classes found in this file.*")

        lines.extend([
            "## Module-Level Functions",
        ])

        funcs_found = False
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs_found = True
                f_doc = ast.get_docstring(node) or "No docstring."
                args = [a.arg for a in node.args.args]
                lines.append(f"- **`{node.name}({', '.join(args)})`**: {f_doc}")

        if not funcs_found:
            lines.append("*No module-level functions found.*")

        doc_str = "\n".join(lines)
        os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)
        with open(output_filepath, "w", encoding="utf-8") as f:
            f.write(doc_str)

        return output_filepath
