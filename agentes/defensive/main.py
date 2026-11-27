#!/usr/bin/env python3
from .auth_manager import AuthManager, RateLimiter
from .config_manager import ConfigManager
from .input_sanitizer import InputSanitizer


def print_header(title: str):
    print("\n" + "=" * 65)
    print(f" {title.upper()}")
    print("=" * 65)

def main():
    print_header("Defensive Security and Secure Development Agent")
    print(f"Active crypto backend: {AuthManager.get_available_crypto_backend()}")
    print("1. Input sanitisation, XSS, path traversal and JSON schemas")
    print("2. Hashing (Argon2/bcrypt/PBKDF2), CSRF tokens, rate limiting and RBAC")
    print("3. Safe configuration loading and static secret auditing")

    # HTML escaping, path containment and structural validation against a typed schema.
    print_header("Demo 1: Input sanitisation and JSON schemas")

    raw_html_input = "<script>alert('xss')</script><b>Hello</b>"
    clean_html = InputSanitizer.sanitize_html(raw_html_input)
    print(f"Raw HTML input:  {raw_html_input}")
    print(f"Sanitised input: {clean_html}")

    path_traversal_input = "../../etc/passwd"
    clean_filename = InputSanitizer.sanitize_filename(path_traversal_input)
    print(f"\nInput file path:     {path_traversal_input}")
    print(f"Safe sanitised name: {clean_filename}")

    # Strict typing: bool must not pass as int, and every declared field must be present.
    json_payload = {"username": "admin", "age": 30, "is_active": True}
    schema = {"username": str, "age": int, "is_active": bool}
    valid_json, errors = InputSanitizer.validate_json_schema(json_payload, schema)
    print(f"\nDefensive JSON payload validation -> valid: {valid_json}")

    # Password hashing, HMAC anti-CSRF tokens, rate limiting and RBAC permissions.
    print_header("Demo 2: Authentication, anti-CSRF tokens and rate limiting")

    password = "InsecurePassword123!"
    score, feedback = AuthManager.evaluate_password_strength(password)
    print(f"Strength of '{password}': score {score}/6")

    print(f"\nHashing with the [{AuthManager.get_available_crypto_backend()}] backend...")
    secure_hash = AuthManager.hash_password(password)
    print(f"Generated hash: {secure_hash[:55]}...")

    match = AuthManager.verify_password(password, secure_hash)
    print(f"Correct password verifies: {match}")

    # The CSRF token is an HMAC bound to the user's session ID.
    secret = "csrf_signing_key_8f3a9c2e1b"
    session_id = "sess_987654321"
    csrf_token = AuthManager.create_csrf_token(secret, session_id)
    print(f"\nGenerated anti-CSRF token: {csrf_token[:40]}...")
    is_valid_csrf = AuthManager.verify_csrf_token(csrf_token, secret, session_id)
    print(f"CSRF token check for session '{session_id}': {is_valid_csrf}")

    # Sliding-window rate limiting per client IP: the fourth request inside the window is refused.
    print("\nRate limiter (at most 3 requests per window):")
    limiter = RateLimiter(max_requests=3, window_seconds=10)
    for i in range(1, 5):
        allowed = limiter.is_allowed("client_ip_127.0.0.1")
        status = "ALLOWED" if allowed else "BLOCKED (RATE LIMIT EXCEEDED)"
        print(f"  Request {i}: {status}")

    # Static audit of an in-memory configuration mapping.
    print_header("Demo 3: Defensive configuration audit")

    sample_config = {
        "SECRET_KEY": "123456",
        "DEBUG": "True",
        "DATABASE_URL": "postgresql://root:root@localhost/db"
    }

    print("Auditing an in-memory configuration mapping...")
    findings = ConfigManager.audit_config_dict(sample_config)
    for key, level, recommendation in findings:
        print(f"[{level}] Key: {key} -> {recommendation}")

    print("\n" + "=" * 65)
    print(" Defensive agent finished successfully.")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    main()
