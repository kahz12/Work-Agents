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
    """OpenAPI schema for a type annotation. Unknown or missing annotations default to string."""
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
    Builds OpenAPI 3.0.3 (Swagger) specifications from Python source through static AST
    analysis; the code is never imported. Produces query parameters, request bodies and basic
    component schemas from the functions' signatures and type hints.
    """

    @staticmethod
    def _build_operation(node: Union[ast.FunctionDef, ast.AsyncFunctionDef], fname: str, method: str) -> Dict[str, Any]:
        """
        OpenAPI operation for one endpoint function. GET and DELETE arguments become query
        parameters; for POST, PUT and PATCH they become JSON request-body properties.
        Arguments without a default are required.
        """
        doc = ast.get_docstring(node) or "Service endpoint"
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
                    "description": "Successful operation",
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
            # Temporary keys: _collect_from_file pops them, moves the schema into
            # components.schemas and replaces the inline schema with a $ref.
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
        Detect @app.route('/x', methods=['POST']) (Flask) and @app.get('/x') (FastAPI).
        Returns (path, method) or None. With several methods, the first one listed is used.
        """
        for dec in getattr(node, "decorator_list", []):
            # FastAPI / APIRouter shorthand decorators, e.g. @app.get("/users").
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                http_verb = dec.func.attr.lower()
                if http_verb in ("get", "post", "put", "delete", "patch", "options", "head"):
                    if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                        return dec.args[0].value, http_verb
                # Classic Flask decorators: positional path plus an optional methods=[...] list.
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
            # Bare decorators (no call, hence no path) cannot declare a route and are skipped.
        return None

    @staticmethod
    def _collect_from_file(
        source_filepath: str,
        paths: Dict[str, Any],
        components_schemas: Dict[str, Any],
        errors: List[str],
        naming_convention: bool = True,
    ) -> None:
        """Collect the routes and schemas of one Python file into the shared accumulators."""
        if not os.path.exists(source_filepath):
            errors.append(f"File '{source_filepath}' does not exist.")
            return

        try:
            with open(source_filepath, "r", encoding="utf-8") as f:
                content = f.read()
            tree = ast.parse(content, filename=source_filepath)
        except (SyntaxError, UnicodeDecodeError, OSError) as exc:
            # Record the problem and carry on: one unparsable module must not abort the whole run.
            errors.append(f"Could not parse '{source_filepath}': {exc}")
            return

        # Naming convention, used when naming_convention=True: the prefix gives the HTTP method
        # and the rest of the name the path (post_create_user -> POST /create_user).
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
        title: str = "Service API",
        version: str = "1.0.0",
        *,
        naming_convention: bool = True,
    ) -> Dict[str, Any]:
        """
        Analyse several Python files and merge their routes and schemas into a single
        OpenAPI 3.0.3 specification.

        Routes come from Flask and FastAPI decorators. With naming_convention=True (the
        library default, kept so existing callers behave the same) they also come from
        get_/post_/put_/delete_ functions, which invents routes in a project that is not a
        web service; the CLI and the pipeline therefore pass False. When no route is found,
        paths stays empty rather than inventing a /health endpoint.
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
                "description": "API specification generated automatically by the agentes docs agent."
            },
            "paths": paths,
        }
        if components_schemas:
            spec["components"] = {"schemas": components_schemas}
        if errors:
            # Files that could not be parsed are listed under a vendor extension (x-...), which
            # OpenAPI 3.x allows, so the diagnostic travels with the generated contract instead
            # of being silently dropped.
            spec["x-agentes-errors"] = errors
        return spec

    @staticmethod
    def generate_openapi_spec(
        source_filepath: str,
        title: str = "Service API",
        version: str = "1.0.0",
        *,
        naming_convention: bool = True,
    ) -> Dict[str, Any]:
        """
        Build an OpenAPI 3.0.3 specification from a single Python file. Supports Flask and
        FastAPI decorators and, with naming_convention, the get_/post_ naming convention.
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
        """Web frameworks imported by the files. With none, generating OpenAPI makes no sense."""
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
        Write the specification as indented JSON and return the path.
        """
        os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)
        with open(output_filepath, "w", encoding="utf-8") as f:
            json.dump(spec, f, indent=2)
        return output_filepath

    @staticmethod
    def export_spec_to_yaml(spec: Dict[str, Any], output_filepath: str) -> str:
        """
        Write the specification as YAML and return the path.

        Uses a small built-in serialiser so the docs agent does not need PyYAML at runtime.
        Scalars are emitted through json.dumps, which always produces valid YAML flow scalars.
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

        yaml_content = "# OpenAPI 3.0.3 specification generated by agentes (docs agent).\n" + dict_to_yaml(spec)
        os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)
        with open(output_filepath, "w", encoding="utf-8") as f:
            f.write(yaml_content)

        return output_filepath
