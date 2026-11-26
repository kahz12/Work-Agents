import ast
import json
import os
from typing import Any, Dict, List, Optional, Tuple, Union

_TYPE_MAP = {
    "str": {"type": "string"},
    "int": {"type": "integer"},
    "float": {"type": "number"},
    "bool": {"type": "boolean"},
    "dict": {"type": "object"},
    "list": {"type": "array"},
    "Any": {},
}


def _ann_to_openapi(annotation: Optional[ast.AST]) -> Dict[str, Any]:
    if annotation is None:
        return {"type": "string"}
    if isinstance(annotation, ast.Name):
        return dict(_TYPE_MAP.get(annotation.id, {"type": "string"}))
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        return dict(_TYPE_MAP.get(annotation.value, {"type": "string"}))
    if isinstance(annotation, ast.Subscript) and isinstance(annotation.value, ast.Name):
        root = annotation.value.id
        if root in ("List", "list"):
            item = _ann_to_openapi(annotation.slice)
            return {"type": "array", "items": item}
        if root in ("Optional",):
            return _ann_to_openapi(annotation.slice)
        if root in ("Dict", "dict"):
            return {"type": "object"}
    return {"type": "string"}


class OpenAPIGenerator:
    """
    Generador automatizado de especificaciones OpenAPI 3.0.3 (Swagger)
    mediante análisis AST. Incluye parámetros, requestBody y schemas básicos.
    """

    @staticmethod
    def _build_operation(node: Union[ast.FunctionDef, ast.AsyncFunctionDef], fname: str, method: str) -> Dict[str, Any]:
        doc = ast.get_docstring(node) or "Endpoint de servicio"
        args = [a for a in node.args.args if a.arg != "self"]
        defaults_offset = len(args) - len(node.args.defaults)
        required_body_props = []
        properties = {}
        parameters = []

        for idx, arg in enumerate(args):
            schema = _ann_to_openapi(arg.annotation)
            has_default = idx >= defaults_offset
            if method in ("get", "delete"):
                parameters.append({
                    "name": arg.arg,
                    "in": "query",
                    "required": not has_default,
                    "schema": schema,
                })
            else:
                properties[arg.arg] = schema
                if not has_default:
                    required_body_props.append(arg.arg)

        operation: Dict[str, Any] = {
            "summary": fname.replace("_", " ").title(),
            "description": doc,
            "responses": {
                "200": {
                    "description": "Operación exitosa",
                    "content": {
                        "application/json": {
                            "schema": {"type": "object"}
                        }
                    }
                }
            }
        }

        if parameters:
            operation["parameters"] = parameters

        if method in ("post", "put", "patch") and properties:
            schema_name = f"{fname}_Request"
            operation["requestBody"] = {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": properties,
                            "required": required_body_props or list(properties.keys()),
                        }
                    }
                }
            }
            # Exponer metadatos auxiliares para que el ensamblador OpenAPI registre el esquema en components.schemas.
            operation["_request_schema_name"] = schema_name
            operation["_request_schema"] = {
                "type": "object",
                "properties": properties,
                "required": required_body_props or list(properties.keys()),
            }

        return operation

    @staticmethod
    def _decorator_route(node: ast.AST) -> Optional[Tuple[str, str]]:
        """
        Detecta @app.route('/x', methods=['POST']) (Flask) y @app.get('/x') (FastAPI).
        Retorna (path, method) o None.
        """
        for dec in getattr(node, "decorator_list", []):
            # Decoradores abreviados estilo FastAPI o APIRouter (por ejemplo, @app.get("/users")).
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                http_verb = dec.func.attr.lower()
                if http_verb in ("get", "post", "put", "delete", "patch", "options", "head"):
                    if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                        return dec.args[0].value, http_verb
                # Decoradores clásicos de Flask con ruta posicional y lista explícita de verbos en methods=[...].
                if http_verb == "route":
                    path = None
                    method = "get"
                    if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                        path = dec.args[0].value
                    for kw in dec.keywords:
                        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                            for elt in kw.value.elts:
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                    method = elt.value.lower()
                                    break
                    if path:
                        return path, method
            # Ignorar decoradores sin invocación explícita (ast.Attribute/ast.Name sin argumentos de ruta).
        return None

    @staticmethod
    def _collect_from_file(
        source_filepath: str,
        paths: Dict[str, Any],
        components_schemas: Dict[str, Any],
        errors: List[str],
        naming_convention: bool = True,
    ) -> None:
        """Extrae rutas y schemas de un único archivo Python hacia los acumuladores."""
        if not os.path.exists(source_filepath):
            errors.append(f"El archivo '{source_filepath}' no existe.")
            return

        try:
            with open(source_filepath, "r", encoding="utf-8") as f:
                content = f.read()
            tree = ast.parse(content, filename=source_filepath)
        except (SyntaxError, UnicodeDecodeError, OSError) as exc:
            # Propagar el diagnóstico en la colección errors en lugar de abortar el recorrido completo del pipeline.
            errors.append(f"No se pudo analizar '{source_filepath}': {exc}")
            return

        method_prefixes = (
            ("delete_", "delete"),
            ("post_", "post"),
            ("put_", "put"),
            ("patch_", "patch"),
            ("get_", "get"),
            ("api_", "get"),
        )
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            fname = node.name
            route_info = OpenAPIGenerator._decorator_route(node)
            matched = None
            clean_route = None
            method = None

            if route_info:
                clean_route, method = route_info
                if not clean_route.startswith("/"):
                    clean_route = "/" + clean_route
            elif not naming_convention:
                continue
            else:
                for prefix, http_method in method_prefixes:
                    if fname.startswith(prefix):
                        matched = (prefix, http_method)
                        break
                if not matched:
                    continue
                prefix, method = matched
                clean_route = "/" + fname[len(prefix):]

            operation = OpenAPIGenerator._build_operation(node, fname, method)

            schema_name = operation.pop("_request_schema_name", None)
            schema_body = operation.pop("_request_schema", None)
            if schema_name and schema_body:
                components_schemas[schema_name] = schema_body
                operation["requestBody"]["content"]["application/json"]["schema"] = {
                    "$ref": f"#/components/schemas/{schema_name}"
                }

            paths.setdefault(clean_route, {})[method] = operation

    @staticmethod
    def generate_openapi_spec_from_files(
        filepaths: List[str],
        title: str = "API Servicio",
        version: str = "1.0.0",
        *,
        naming_convention: bool = True,
    ) -> Dict[str, Any]:
        """
        Analiza múltiples archivos Python y combina sus rutas y schemas en una
        única especificación OpenAPI 3.0.3.

        Las rutas salen de los decoradores de Flask y FastAPI. Con naming_convention=True
        (el valor por defecto de la API, por compatibilidad) también de las funciones
        get_/post_/put_/delete_, algo que en un proyecto que no es web inventa rutas.
        Si no hay ninguna ruta, paths queda vacío: no se inventa un /health.
        """
        paths: Dict[str, Any] = {}
        components_schemas: Dict[str, Any] = {}
        errors: List[str] = []

        for fp in filepaths:
            OpenAPIGenerator._collect_from_file(fp, paths, components_schemas, errors, naming_convention)

        spec: Dict[str, Any] = {
            "openapi": "3.0.3",
            "info": {
                "title": title,
                "version": version,
                "description": "Especificación de API generada automáticamente por el Agente de Documentación."
            },
            "paths": paths,
        }
        if components_schemas:
            spec["components"] = {"schemas": components_schemas}
        if errors:
            # Los archivos que no se pudieron analizar van en una extensión de proveedor (x-),
            # válida en OpenAPI 3.x, para que el diagnóstico viaje dentro del contrato
            # generado y no se descarte silenciosamente si un modulo no pudo parsearse.
            spec["x-agentes-errors"] = errors
        return spec

    @staticmethod
    def generate_openapi_spec(
        source_filepath: str,
        title: str = "API Servicio",
        version: str = "1.0.0",
        *,
        naming_convention: bool = True,
    ) -> Dict[str, Any]:
        """
        Analiza un archivo Python y genera una especificación OpenAPI 3.0.3 válida.
        Soporta decoradores Flask/FastAPI y, con naming_convention, la convención get_/post_.
        """
        return OpenAPIGenerator.generate_openapi_spec_from_files(
            [source_filepath], title=title, version=version, naming_convention=naming_convention,
        )

    WEB_FRAMEWORKS = (
        "fastapi", "flask", "starlette", "django", "aiohttp", "bottle", "sanic", "tornado",
        "falcon", "quart", "litestar", "pyramid", "cherrypy", "connexion", "responder",
    )

    @staticmethod
    def detect_web_frameworks(filepaths: List[str]) -> List[str]:
        """Frameworks web importados en los archivos. Sin ninguno, no tiene sentido generar OpenAPI."""
        found = set()
        for fp in filepaths:
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    tree = ast.parse(f.read(), filename=fp)
            except (SyntaxError, UnicodeDecodeError, OSError, ValueError):
                continue
            for node in ast.walk(tree):
                names: List[str] = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    names = [node.module]
                for name in names:
                    root = name.split(".")[0]
                    if root in OpenAPIGenerator.WEB_FRAMEWORKS:
                        found.add(root)
        return sorted(found)

    @staticmethod
    def export_spec_to_json(spec: Dict[str, Any], output_filepath: str) -> str:
        """
        Guarda la especificación OpenAPI en un archivo JSON.
        """
        os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)
        with open(output_filepath, "w", encoding="utf-8") as f:
            json.dump(spec, f, indent=2)
        return output_filepath

    @staticmethod
    def export_spec_to_yaml(spec: Dict[str, Any], output_filepath: str) -> str:
        """
        Guarda la especificación OpenAPI en formato YAML nativo.
        """
        def dict_to_yaml(data, indent=0):
            lines = []
            prefix = " " * indent
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, (dict, list)):
                        lines.append(f"{prefix}{k}:")
                        lines.append(dict_to_yaml(v, indent + 2))
                    else:
                        lines.append(f"{prefix}{k}: {json.dumps(v)}")
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, (dict, list)):
                        lines.append(f"{prefix}-")
                        lines.append(dict_to_yaml(item, indent + 2))
                    else:
                        lines.append(f"{prefix}- {json.dumps(item)}")
            return "\n".join(lines)

        yaml_content = "# Especificación OpenAPI 3.0.3 generada por agentes (agente docs).\n" + dict_to_yaml(spec)
        os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)
        with open(output_filepath, "w", encoding="utf-8") as f:
            f.write(yaml_content)

        return output_filepath
