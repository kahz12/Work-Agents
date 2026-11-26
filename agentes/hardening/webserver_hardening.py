from typing import Dict, List, Tuple


class WebServerHardening:
    """
    Generador y verificador defensivo de configuraciones seguras para servidores web (Nginx / Caddy)
    y cabeceras de seguridad HTTP (CSP, HSTS, X-Frame-Options, etc.).
    """

    DEFAULT_HTTP_HEADERS = {
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none';",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
    }

    NGINX_HARDENED_TEMPLATE = """# Configuración defensiva de Nginx fortalecida (Hardened)
server {{
    listen 443 ssl http2;
    server_name {domain};

    # Cifrado TLS Seguro (TLS 1.2 y TLS 1.3)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;

    # Ocultar versión del servidor (Server Tokens)
    server_tokens off;

    # Cabeceras de Seguridad HTTP Defensivas
    add_header Content-Security-Policy "{csp}" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    # Prevención de ataques de fuerza bruta / desbordamiento de búfer
    client_body_buffer_size 1k;
    client_header_buffer_size 1k;
    client_max_body_size 10m;
    large_client_header_buffers 2 1k;

    location / {{
        root /var/www/html;
        index index.html;
    }}
}}
"""

    CADDY_HARDENED_TEMPLATE = """# Configuración defensiva Caddyfile fortalecida (Hardened Caddy)
{domain} {{
    # HTTPS y TLS (sintaxis Caddy v2: protocols dentro del bloque tls)
    tls {{
        protocols tls1.2 tls1.3
    }}

    # Cabeceras defensivas de seguridad
    header {{
        Content-Security-Policy "{csp}"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "geolocation=(), microphone=(), camera=()"
        -Server
    }}

    file_server
}}
"""

    @staticmethod
    def generate_nginx_config(domain: str, csp_policy: str = "default-src 'self';") -> str:
        """
        Genera un bloque de configuración de Nginx con fortalecimiento defensivo.
        """
        return WebServerHardening.NGINX_HARDENED_TEMPLATE.format(
            domain=domain,
            csp=csp_policy
        )

    @staticmethod
    def generate_caddy_config(domain: str, csp_policy: str = "default-src 'self';") -> str:
        """
        Genera una configuración Caddyfile con fortalecimiento defensivo.
        """
        return WebServerHardening.CADDY_HARDENED_TEMPLATE.format(
            domain=domain,
            csp=csp_policy
        )

    @staticmethod
    def audit_http_headers(headers: Dict[str, str]) -> List[Tuple[str, str, str]]:
        """
        Audita una lista/diccionario de cabeceras HTTP presentes en un servidor.
        Retorna (Cabecera, Nivel_Riesgo, Recomendación).
        """
        findings = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header_name, recommended_val in WebServerHardening.DEFAULT_HTTP_HEADERS.items():
            h_lower = header_name.lower()
            if h_lower not in headers_lower:
                findings.append((
                    header_name,
                    "ALTO" if header_name in ["Content-Security-Policy", "X-Frame-Options"] else "MEDIO",
                    f"Falta la cabecera defensiva '{header_name}'. Valor recomendado: '{recommended_val}'"
                ))

        if not findings:
            findings.append(("CABECERAS", "OK", "Todas las cabeceras defensivas de seguridad están presentes."))

        return findings
