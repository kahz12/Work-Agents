#!/usr/bin/env python3
from .auth_manager import AuthManager, RateLimiter
from .config_manager import ConfigManager
from .input_sanitizer import InputSanitizer


def print_header(title: str):
    print("\n" + "=" * 65)
    print(f" {title.upper()}")
    print("=" * 65)

def main():
    print_header("Agente de Seguridad Defensiva y Desarrollo Seguro")
    print(f"Backend Criptográfico Activo: {AuthManager.get_available_crypto_backend()}")
    print("1. Sanitización de Entradas, XSS, Path Traversal y Esquemas JSON")
    print("2. Hashing (Argon2/Bcrypt/PBKDF2), Tokens CSRF, Rate Limiting y RBAC")
    print("3. Carga Segura y Auditoría Estática de Secretos")

    # Sanitización de cadenas HTML, contención de rutas y validación estructural JSON Schema.
    print_header("Demostración 1: Sanitización de Entradas y Esquemas JSON")

    raw_html_input = "<script>alert('xss')</script><b>Hola</b>"
    clean_html = InputSanitizer.sanitize_html(raw_html_input)
    print(f"Entrada HTML cruda: {raw_html_input}")
    print(f"Entrada Sanitizada: {clean_html}")

    path_traversal_input = "../../etc/passwd"
    clean_filename = InputSanitizer.sanitize_filename(path_traversal_input)
    print(f"\nRuta archivo de entrada: {path_traversal_input}")
    print(f"Nombre sanitizado seguro: {clean_filename}")

    # Validación tipada de carga útil JSON respetando tipos estrictos en esquema de entrada.
    json_payload = {"username": "admin", "age": 30, "is_active": True}
    schema = {"username": str, "age": int, "is_active": bool}
    valid_json, errors = InputSanitizer.validate_json_schema(json_payload, schema)
    print(f"\nValidación de Payload JSON defensivo -> Válido: {valid_json}")

    # Autenticación criptográfica, protección HMAC anti-CSRF, limitación de tasa y permisos RBAC.
    print_header("Demostración 2: Autenticación, Tokens Anti-CSRF y Rate Limiting")

    password = "PasswordInsegura123!"
    score, feedback = AuthManager.evaluate_password_strength(password)
    print(f"Evaluación Contraseña '{password}': Puntaje {score}/6")

    print(f"\nGenerando Hash defensivo con backend [{AuthManager.get_available_crypto_backend()}]...")
    secure_hash = AuthManager.hash_password(password)
    print(f"Hash Generado: {secure_hash[:55]}...")

    match = AuthManager.verify_password(password, secure_hash)
    print(f"Verificación Contraseña Correcta: {match}")

    # Emisión y validación HMAC de token CSRF ligado a la sesión del usuario.
    secret = "mi_secreto_super_seguro_12345"
    session_id = "sess_987654321"
    csrf_token = AuthManager.create_csrf_token(secret, session_id)
    print(f"\nToken Anti-CSRF Generado: {csrf_token[:40]}...")
    is_valid_csrf = AuthManager.verify_csrf_token(csrf_token, secret, session_id)
    print(f"Verificación Token CSRF para sesión '{session_id}': {is_valid_csrf}")

    # Control de frecuencia por ventana deslizante para mitigar abusos por IP.
    print("\nProbando Rate Limiter (Máximo 3 peticiones por ventana):")
    limiter = RateLimiter(max_requests=3, window_seconds=10)
    for i in range(1, 5):
        allowed = limiter.is_allowed("client_ip_127.0.0.1")
        status = "PERMITIDO" if allowed else "BLOQUEADO (RATE LIMIT EXCEEDED)"
        print(f"  Petición {i}: {status}")

    # Auditoría estática de diccionarios de configuración y exposición de secretos en memoria.
    print_header("Demostración 3: Auditoría Defensiva de Configuración")

    config_ejemplo = {
        "SECRET_KEY": "123456",
        "DEBUG": "True",
        "DATABASE_URL": "postgresql://root:root@localhost/db"
    }

    print("Auditando diccionario de configuración en memoria...")
    hallazgos = ConfigManager.audit_config_dict(config_ejemplo)
    for clave, nivel, rec in hallazgos:
        print(f"[{nivel}] Clave: {clave} -> {rec}")

    print("\n" + "=" * 65)
    print(" Agente Defensivo ejecutado correctamente.")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    main()
