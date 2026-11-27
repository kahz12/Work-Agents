from typing import Dict, List, Tuple


class WebServerHardening:
    """
    Generates hardened web server configurations (Nginx / Caddy) and audits HTTP security
    headers (CSP, HSTS, X-Frame-Options, etc.).
    """

    DEFAULT_HTTP_HEADERS = {
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none';",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
    }

    NGINX_HARDENED_TEMPLATE = """# Hardened Nginx configuration
server {{
    listen 443 ssl http2;
    server_name {domain};

    # TLS 1.2 and 1.3 only, with forward-secret AEAD ciphers
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;

    # Do not advertise the Nginx version
    server_tokens off;

    # HTTP security headers
    add_header Content-Security-Policy "{csp}" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    # Small request buffers and a body size cap limit the damage of oversized requests
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

    CADDY_HARDENED_TEMPLATE = """# Hardened Caddyfile
{domain} {{
    # HTTPS and TLS (Caddy v2 syntax: protocols goes inside the tls block)
    tls {{
        protocols tls1.2 tls1.3
    }}

    # HTTP security headers; -Server removes the Server header
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
        Hardened Nginx server block for domain, with csp_policy as Content-Security-Policy.
        """
        return WebServerHardening.NGINX_HARDENED_TEMPLATE.format(
            domain=domain,
            csp=csp_policy
        )

    @staticmethod
    def generate_caddy_config(domain: str, csp_policy: str = "default-src 'self';") -> str:
        """
        Hardened Caddyfile site block for domain, with csp_policy as Content-Security-Policy.
        """
        return WebServerHardening.CADDY_HARDENED_TEMPLATE.format(
            domain=domain,
            csp=csp_policy
        )

    @staticmethod
    def audit_http_headers(headers: Dict[str, str]) -> List[Tuple[str, str, str]]:
        """
        Check a server's HTTP response headers for the recommended security headers. Header
        names are compared case-insensitively. Returns (header, risk level, recommendation).
        """
        findings = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header_name, recommended_val in WebServerHardening.DEFAULT_HTTP_HEADERS.items():
            h_lower = header_name.lower()
            if h_lower not in headers_lower:
                findings.append((
                    header_name,
                    "HIGH" if header_name in ["Content-Security-Policy", "X-Frame-Options"] else "MEDIUM",
                    f"Missing security header '{header_name}'. Recommended value: '{recommended_val}'"
                ))

        if not findings:
            findings.append(("HEADERS", "OK", "Every recommended security header is present."))

        return findings
