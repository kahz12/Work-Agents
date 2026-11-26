import json
import os


class SwaggerUIGenerator:
    """
    Generador de visor HTML interactivo embebido Swagger UI para especificaciones OpenAPI 3.0.
    """

    SWAGGER_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Swagger UI - Documentación Interactiva de API</title>
    <link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.18.3/swagger-ui.css">
    <style>
        html {{ box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }}
        *, *:before, *:after {{ box-sizing: inherit; }}
        body {{ margin: 0; background: #fafafa; }}
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.18.3/swagger-ui-bundle.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.18.3/swagger-ui-standalone-preset.js"></script>
    <script>
    window.onload = function() {{
        const spec = {spec_json};
        window.ui = SwaggerUIBundle({{
            spec: spec,
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIStandalonePreset
            ],
            plugins: [
                SwaggerUIBundle.plugins.DownloadUrl
            ],
            layout: "StandaloneLayout"
        }});
    }};
    </script>
</body>
</html>
"""

    @staticmethod
    def generate_swagger_ui_html(spec_dict: dict, output_filepath: str) -> str:
        """
        Genera un archivo HTML con Swagger UI embebido autónomo.
        """
        spec_json_str = json.dumps(spec_dict)
        html_content = SwaggerUIGenerator.SWAGGER_HTML_TEMPLATE.format(spec_json=spec_json_str)

        os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)
        with open(output_filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_filepath
