"""
Tests del agente defensive: tokens firmados, tokens CSRF, RBAC, limitador de frecuencia,
hashing de contraseñas, esquemas tipados y saneamiento de entrada.

Las comprobaciones de seguridad se prueban sobre todo por el lado del rechazo: un token
manipulado, caducado o de otra sesión tiene que fallar, y un valor fuera de la lista blanca no
puede pasar por un detalle de la expresión regular.
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import types

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentes.common.schema import matches_schema_type, validate_typed_schema  # noqa: E402
from agentes.defensive import auth_manager  # noqa: E402
from agentes.defensive.auth_manager import AuthManager, RateLimiter  # noqa: E402
from agentes.defensive.input_sanitizer import InputSanitizer  # noqa: E402

KEY = "clave-de-prueba"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _signed(header, payload, key=KEY) -> str:
    """Token con la firma correcta para un header y un payload arbitrarios (para probar el rechazo)."""
    head = _b64(json.dumps(header).encode())
    body = _b64(json.dumps(payload).encode())
    sig = hmac.new(key.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64(sig)}"


# --- Tokens firmados (HS256) ---------------------------------------------------------------

def test_token_firmado_ida_y_vuelta_sin_tocar_el_payload_original():
    payload = {"sub": "ana", "rol": "admin"}
    token = AuthManager.create_secure_token(payload, KEY, expires_in_seconds=60)
    ok, data, msg = AuthManager.verify_secure_token(token, KEY)
    assert (ok, msg) == (True, "Token válido")
    assert data["sub"] == "ana" and isinstance(data["exp"], int)
    assert payload == {"sub": "ana", "rol": "admin"}, "create_secure_token no debe añadir exp al dict del llamador"


def test_token_firmado_con_otra_clave_o_manipulado_se_rechaza():
    token = AuthManager.create_secure_token({"sub": "ana", "rol": "user"}, KEY)
    head, body, sig = token.split(".")
    otro_payload = _b64(json.dumps({"sub": "ana", "rol": "admin", "exp": 4102444800}).encode())
    firma_cambiada = ("A" if sig[0] != "A" else "B") + sig[1:]
    for candidato, clave in [(token, "otra-clave"), (f"{head}.{otro_payload}.{sig}", KEY),
                             (f"{head}.{body}.{firma_cambiada}", KEY)]:
        ok, data, msg = AuthManager.verify_secure_token(candidato, clave)
        assert (ok, data) == (False, None)
        assert msg == "Firma del token no válida (posible manipulación)"


def test_token_firmado_caducado():
    token = AuthManager.create_secure_token({"sub": "ana"}, KEY, expires_in_seconds=-1)
    assert AuthManager.verify_secure_token(token, KEY) == (False, None, "Token expirado")


@pytest.mark.parametrize("token, msg", [
    ("", "Formato de token inválido"),
    ("a.b", "Formato de token inválido"),
    ("a.b.c.d", "Formato de token inválido"),
    ("%%%.%%%.%%%", "Error en verificación: token malformado"),
    (_signed({"alg": "HS512"}, {"sub": "x"}), "Algoritmo de token no soportado"),
    (_signed(["HS256"], {"sub": "x"}), "Algoritmo de token no soportado"),
    (_signed({"alg": "HS256"}, ["no", "es", "un", "objeto"]), "Error en verificación: token malformado"),
    (_signed({"alg": "HS256"}, {"exp": "mañana"}), "Error en verificación: token malformado"),
    (_signed({"alg": "HS256"}, {"exp": True}), "Error en verificación: token malformado"),
])
def test_token_firmado_malformado_se_rechaza_sin_excepciones(token, msg):
    assert AuthManager.verify_secure_token(token, KEY) == (False, None, msg)


def test_token_firmado_sin_exp_es_valido_si_la_firma_cuadra():
    """create_secure_token siempre añade exp; sin él, solo la firma decide."""
    ok, data, _ = AuthManager.verify_secure_token(_signed({"alg": "HS256"}, {"sub": "x"}), KEY)
    assert ok and data == {"sub": "x"}


# --- Tokens CSRF ----------------------------------------------------------------------------

def test_csrf_valido_solo_para_su_sesion_y_su_clave():
    token = AuthManager.create_csrf_token(KEY, "sesion:con:dos:puntos")
    assert AuthManager.verify_csrf_token(token, KEY, "sesion:con:dos:puntos")
    assert not AuthManager.verify_csrf_token(token, KEY, "otra-sesion")
    assert not AuthManager.verify_csrf_token(token, "otra-clave", "sesion:con:dos:puntos")


def test_csrf_caducado_o_con_la_firma_cambiada_se_rechaza():
    caducado = AuthManager.create_csrf_token(KEY, "s1", expires_in_seconds=-1)
    assert not AuthManager.verify_csrf_token(caducado, KEY, "s1")
    token = AuthManager.create_csrf_token(KEY, "s1")
    alterado = token[:-1] + ("0" if token[-1] != "0" else "1")
    assert not AuthManager.verify_csrf_token(alterado, KEY, "s1")


@pytest.mark.parametrize("token", [
    "", "s1", "s1:123", "s1:no-es-numero:" + "a" * 64, "s1:4102444800:corta", None, 12345,
])
def test_csrf_malformado_se_rechaza(token):
    assert AuthManager.verify_csrf_token(token, KEY, "s1") is False


# --- RBAC -----------------------------------------------------------------------------------

ROLES = {"admin": ["*"], "editor": ["leer", "escribir"], "lector": ["leer"]}


@pytest.mark.parametrize("roles, permiso, esperado", [
    (["lector"], "leer", True),
    (["lector"], "escribir", False),
    (["lector", "editor"], "escribir", True),
    (["admin"], "borrar", True),
    (["desconocido"], "leer", False),
    ([], "leer", False),
])
def test_rbac(roles, permiso, esperado):
    assert AuthManager.check_permission(roles, permiso, ROLES) is esperado


# --- Limitador de frecuencia ----------------------------------------------------------------

@pytest.fixture
def reloj(monkeypatch):
    """Reloj controlado para auth_manager: el test avanza el tiempo sin esperar."""
    ahora = [1000.0]
    monkeypatch.setattr(auth_manager, "time", types.SimpleNamespace(time=lambda: ahora[0]))
    return ahora


def test_rate_limiter_bloquea_al_superar_el_maximo_y_libera_al_pasar_la_ventana(reloj):
    rl = RateLimiter(max_requests=3, window_seconds=60)
    assert [rl.is_allowed("ip") for _ in range(4)] == [True, True, True, False]
    assert rl.is_allowed("otra-ip"), "cada identificador tiene su propio cupo"
    reloj[0] += 59
    assert not rl.is_allowed("ip")
    reloj[0] += 1
    assert rl.is_allowed("ip"), "las peticiones de hace 60 segundos ya no cuentan"


def test_rate_limiter_acotado_descarta_antes_lo_caducado_que_lo_reciente(reloj):
    rl = RateLimiter(max_requests=1, window_seconds=10, max_tracked_keys=2)
    rl.is_allowed("viejo")
    reloj[0] += 20
    rl.is_allowed("reciente")
    rl.is_allowed("nuevo")
    assert set(rl.requests) == {"reciente", "nuevo"}
    assert not rl.is_allowed("reciente"), "el reciente conserva su historial"


def test_rate_limiter_sin_cupo_no_guarda_nada(reloj):
    rl = RateLimiter(max_requests=0)
    assert not rl.is_allowed("ip")
    assert rl.requests == {}


# --- Hashing de contraseñas -----------------------------------------------------------------

@pytest.fixture
def sin_backends(monkeypatch):
    monkeypatch.setattr(auth_manager, "HAS_ARGON2", False)
    monkeypatch.setattr(auth_manager, "HAS_BCRYPT", False)


def test_pbkdf2_cuando_no_hay_argon2_ni_bcrypt(sin_backends):
    assert AuthManager.get_available_crypto_backend() == "pbkdf2:sha256"
    stored = AuthManager.hash_password("Correcta-123", iterations=1000)
    assert stored.startswith("pbkdf2:sha256:1000:")
    assert AuthManager.verify_password("Correcta-123", stored)
    assert not AuthManager.verify_password("Incorrecta-123", stored)


@pytest.mark.parametrize("stored, esperado", [
    ("pbkdf2:sha256:600000:c2Fs:aGFzaA==", False),
    ("pbkdf2:sha256:1000:c2Fs:aGFzaA==", True),
    ("pbkdf2:sha256", True),
    ("pbkdf2:sha256:muchas:c2Fs:aGFzaA==", True),
    ("argon2:$argon2id$...", False),
])
def test_needs_rehash_sin_un_algoritmo_mejor(sin_backends, stored, esperado):
    assert AuthManager.needs_rehash(stored) is esperado


def test_needs_rehash_pide_cambiar_pbkdf2_si_hay_un_algoritmo_mejor(monkeypatch):
    monkeypatch.setattr(auth_manager, "HAS_ARGON2", True)
    assert AuthManager.needs_rehash("pbkdf2:sha256:600000:c2Fs:aGFzaA==")


def test_bcrypt_cuando_no_hay_argon2(monkeypatch):
    pytest.importorskip("bcrypt")
    monkeypatch.setattr(auth_manager, "HAS_ARGON2", False)
    monkeypatch.setattr(auth_manager, "HAS_BCRYPT", True)
    assert AuthManager.get_available_crypto_backend() == "bcrypt"
    stored = AuthManager.hash_password("Correcta-123")
    assert stored.startswith("bcrypt:$2")
    assert AuthManager.verify_password("Correcta-123", stored)
    assert not AuthManager.verify_password("Incorrecta-123", stored)


@pytest.mark.parametrize("stored", [
    "", "nada", "argon2:no-es-un-hash", "bcrypt:no-es-un-hash", "pbkdf2:sha256:1000:%%%:%%%",
    "pbkdf2:md99:1000:c2Fs:aGFzaA==", "a:b:c",
])
def test_verify_password_con_un_hash_ilegible_devuelve_false(stored):
    assert AuthManager.verify_password("x", stored) is False


def test_contrasena_sin_minusculas_lo_dice():
    _, feedback = AuthManager.evaluate_password_strength("SOLOMAYUS-9")
    assert "Incluye al menos una letra minúscula." in feedback


# --- Esquemas tipados ------------------------------------------------------------------------

@pytest.mark.parametrize("valor, tipo, esperado", [
    (1.5, float, True), (1, float, False), (True, float, False),
    (1, int, True), (True, int, False), (False, bool, True), ("x", str, True), ([], list, True),
])
def test_tipos_estrictos(valor, tipo, esperado):
    assert matches_schema_type(valor, tipo) is esperado


@pytest.mark.parametrize("payload, schema, mensaje", [
    ([], {"id": int}, "El payload recibido no es un objeto JSON (diccionario)."),
    ({}, {"id": int}, "Falta el campo requerido: 'id'"),
    ({"user": "ana"}, {"user": {"name": str}}, "'user' debe ser un objeto, se recibió str"),
    ({"tags": "a,b"}, {"tags": [str]}, "'tags' debe ser una lista, se recibió str"),
    ({"tags": ["a", 2]}, {"tags": [str]}, "tags[1]"),
    ({"x": 1}, {"x": "int"}, "Esquema no soportado en 'x'"),
])
def test_esquema_explica_cada_error(payload, schema, mensaje):
    ok, errors = validate_typed_schema(payload, schema)
    assert not ok
    assert any(mensaje in e for e in errors), errors


def test_esquema_valido_con_listas_y_anidados():
    schema = {"id": int, "tags": [str], "owner": {"name": str, "score": float}}
    assert validate_typed_schema({"id": 1, "tags": [], "owner": {"name": "a", "score": 1.0}}, schema) == (True, [])


# --- Saneamiento de entrada ------------------------------------------------------------------

def test_sanitize_html_escapa_y_no_acepta_otros_tipos():
    assert InputSanitizer.sanitize_html('  <img src=x onerror="alert(1)">  ') == \
        "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;"
    assert InputSanitizer.sanitize_html(None) == ""


@pytest.mark.parametrize("email, esperado", [
    ("ana@example.com", True), ("  ana.b+tag@sub.example.org ", True), ("ana@", False),
    ("@example.com", False), ("ana example@x.com", False), ("", False), (None, False),
])
def test_validate_email(email, esperado):
    assert InputSanitizer.validate_email(email) is esperado


@pytest.mark.parametrize("nombre, esperado", [
    ("informe.pdf", "informe.pdf"), ("../../etc/passwd", "passwd"), ("", "file_default"),
    (None, "file_default"),
])
def test_sanitize_filename(nombre, esperado):
    assert InputSanitizer.sanitize_filename(nombre) == esperado


def test_ruta_segura_rechaza_lo_que_sale_de_la_base(tmp_path):
    base = str(tmp_path)
    assert InputSanitizer.validate_safe_path(base, "sub/a.txt") == str(tmp_path / "sub" / "a.txt")
    assert InputSanitizer.validate_safe_path(base, "../fuera.txt") is None
    assert InputSanitizer.validate_safe_path(base, "/etc/passwd") is None
    assert InputSanitizer.validate_safe_path(base, None) is None
    assert InputSanitizer.validate_safe_path(base, "a\x00b") is None


@pytest.mark.parametrize("texto, permitidos, esperado", [
    ("usuario_1", r"a-zA-Z0-9_", True),
    ("usuario 1", r"a-zA-Z0-9_", False),
    ("", r"a-z", True),
    (None, r"a-z", False),
    # `$` en Python también acepta un salto de línea final: "admin\n" no debe pasar una lista de solo letras.
    ("admin\n", r"a-z", False),
    ("con espacio\n", r"a-z\s", True),
])
def test_lista_blanca(texto, permitidos, esperado):
    assert InputSanitizer.validate_string_whitelist(texto, permitidos) is esperado


@pytest.mark.parametrize("valor, minimo, maximo, esperado", [
    ("42", None, None, 42), (42, 0, 100, 42), (-1, 0, 100, None), (101, 0, 100, None),
    ("x", None, None, None), (None, None, None, None), (True, None, None, None), (3.9, None, None, 3),
])
def test_sanitize_integer(valor, minimo, maximo, esperado):
    assert InputSanitizer.sanitize_integer(valor, minimo, maximo) == esperado


def test_validate_json_schema_delega_en_el_esquema():
    assert InputSanitizer.validate_json_schema({"id": 1}, {"id": int}) == (True, [])
    ok, _ = InputSanitizer.validate_json_schema({"id": 1, "extra": 2}, {"id": int}, reject_extra_keys=True)
    assert not ok
