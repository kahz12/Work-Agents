"""
Tests for the defensive agent: signed tokens, CSRF tokens, RBAC, the rate limiter, password
hashing, typed schemas and input sanitisation.

Security checks are tested mostly from the rejection side: a tampered, expired or
other-session token has to fail, and a value outside the allow-list must not slip through
because of a regular-expression detail.
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

KEY = "test-key"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _signed(header, payload, key=KEY) -> str:
    """A correctly signed token for an arbitrary header and payload (to test rejection paths)."""
    head = _b64(json.dumps(header).encode())
    body = _b64(json.dumps(payload).encode())
    sig = hmac.new(key.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64(sig)}"


# --- Signed tokens (HS256) -----------------------------------------------------------------

def test_signed_token_round_trip_leaves_the_original_payload_untouched():
    payload = {"sub": "ana", "role": "admin"}
    token = AuthManager.create_secure_token(payload, KEY, expires_in_seconds=60)
    ok, data, msg = AuthManager.verify_secure_token(token, KEY)
    assert (ok, msg) == (True, "Valid token")
    assert data["sub"] == "ana" and isinstance(data["exp"], int)
    assert payload == {"sub": "ana", "role": "admin"}, "create_secure_token must not add exp to the caller's dict"


def test_signed_token_with_another_key_or_tampered_is_rejected():
    token = AuthManager.create_secure_token({"sub": "ana", "role": "user"}, KEY)
    head, body, sig = token.split(".")
    other_payload = _b64(json.dumps({"sub": "ana", "role": "admin", "exp": 4102444800}).encode())
    changed_signature = ("A" if sig[0] != "A" else "B") + sig[1:]
    for candidate, key in [(token, "other-key"), (f"{head}.{other_payload}.{sig}", KEY),
                           (f"{head}.{body}.{changed_signature}", KEY)]:
        ok, data, msg = AuthManager.verify_secure_token(candidate, key)
        assert (ok, data) == (False, None)
        assert msg == "Invalid token signature (possible tampering)"


def test_expired_signed_token():
    token = AuthManager.create_secure_token({"sub": "ana"}, KEY, expires_in_seconds=-1)
    assert AuthManager.verify_secure_token(token, KEY) == (False, None, "Token expired")


@pytest.mark.parametrize("token, msg", [
    ("", "Invalid token format"),
    ("a.b", "Invalid token format"),
    ("a.b.c.d", "Invalid token format"),
    ("%%%.%%%.%%%", "Verification error: malformed token"),
    (_signed({"alg": "HS512"}, {"sub": "x"}), "Unsupported token algorithm"),
    (_signed(["HS256"], {"sub": "x"}), "Unsupported token algorithm"),
    (_signed({"alg": "HS256"}, ["not", "an", "object"]), "Verification error: malformed token"),
    (_signed({"alg": "HS256"}, {"exp": "tomorrow"}), "Verification error: malformed token"),
    (_signed({"alg": "HS256"}, {"exp": True}), "Verification error: malformed token"),
])
def test_malformed_signed_token_is_rejected_without_raising(token, msg):
    assert AuthManager.verify_secure_token(token, KEY) == (False, None, msg)


def test_signed_token_without_exp_is_valid_when_the_signature_matches():
    """create_secure_token always adds exp; without it, only the signature decides."""
    ok, data, _ = AuthManager.verify_secure_token(_signed({"alg": "HS256"}, {"sub": "x"}), KEY)
    assert ok and data == {"sub": "x"}


# --- CSRF tokens ----------------------------------------------------------------------------

def test_csrf_token_is_valid_only_for_its_session_and_key():
    token = AuthManager.create_csrf_token(KEY, "session:with:colons")
    assert AuthManager.verify_csrf_token(token, KEY, "session:with:colons")
    assert not AuthManager.verify_csrf_token(token, KEY, "other-session")
    assert not AuthManager.verify_csrf_token(token, "other-key", "session:with:colons")


def test_expired_or_altered_csrf_token_is_rejected():
    expired = AuthManager.create_csrf_token(KEY, "s1", expires_in_seconds=-1)
    assert not AuthManager.verify_csrf_token(expired, KEY, "s1")
    token = AuthManager.create_csrf_token(KEY, "s1")
    altered = token[:-1] + ("0" if token[-1] != "0" else "1")
    assert not AuthManager.verify_csrf_token(altered, KEY, "s1")


@pytest.mark.parametrize("token", [
    "", "s1", "s1:123", "s1:not-a-number:" + "a" * 64, "s1:4102444800:short", None, 12345,
])
def test_malformed_csrf_token_is_rejected(token):
    assert AuthManager.verify_csrf_token(token, KEY, "s1") is False


# --- RBAC -----------------------------------------------------------------------------------

ROLES = {"admin": ["*"], "editor": ["read", "write"], "reader": ["read"]}


@pytest.mark.parametrize("roles, permission, expected", [
    (["reader"], "read", True),
    (["reader"], "write", False),
    (["reader", "editor"], "write", True),
    (["admin"], "delete", True),
    (["unknown"], "read", False),
    ([], "read", False),
])
def test_rbac(roles, permission, expected):
    assert AuthManager.check_permission(roles, permission, ROLES) is expected


# --- Rate limiter --------------------------------------------------------------------------

@pytest.fixture
def clock(monkeypatch):
    """Controlled clock for auth_manager: the test moves time forward without waiting."""
    now = [1000.0]
    monkeypatch.setattr(auth_manager, "time", types.SimpleNamespace(time=lambda: now[0]))
    return now


def test_rate_limiter_blocks_above_the_limit_and_releases_after_the_window(clock):
    rl = RateLimiter(max_requests=3, window_seconds=60)
    assert [rl.is_allowed("ip") for _ in range(4)] == [True, True, True, False]
    assert rl.is_allowed("other-ip"), "each identifier has its own quota"
    clock[0] += 59
    assert not rl.is_allowed("ip")
    clock[0] += 1
    assert rl.is_allowed("ip"), "requests from 60 seconds ago no longer count"


def test_bounded_rate_limiter_evicts_stale_entries_before_recent_ones(clock):
    rl = RateLimiter(max_requests=1, window_seconds=10, max_tracked_keys=2)
    rl.is_allowed("old")
    clock[0] += 20
    rl.is_allowed("recent")
    rl.is_allowed("new")
    assert set(rl.requests) == {"recent", "new"}
    assert not rl.is_allowed("recent"), "the recent identifier keeps its history"


def test_rate_limiter_with_no_quota_stores_nothing(clock):
    rl = RateLimiter(max_requests=0)
    assert not rl.is_allowed("ip")
    assert rl.requests == {}


# --- Password hashing ---------------------------------------------------------------------

@pytest.fixture
def no_backends(monkeypatch):
    monkeypatch.setattr(auth_manager, "HAS_ARGON2", False)
    monkeypatch.setattr(auth_manager, "HAS_BCRYPT", False)


def test_pbkdf2_when_neither_argon2_nor_bcrypt_is_available(no_backends):
    assert AuthManager.get_available_crypto_backend() == "pbkdf2:sha256"
    stored = AuthManager.hash_password("Correct-123", iterations=1000)
    assert stored.startswith("pbkdf2:sha256:1000:")
    assert AuthManager.verify_password("Correct-123", stored)
    assert not AuthManager.verify_password("Wrong-123", stored)


@pytest.mark.parametrize("stored, expected", [
    ("pbkdf2:sha256:600000:c2Fs:aGFzaA==", False),
    ("pbkdf2:sha256:1000:c2Fs:aGFzaA==", True),
    ("pbkdf2:sha256", True),
    ("pbkdf2:sha256:many:c2Fs:aGFzaA==", True),
    ("argon2:$argon2id$...", False),
])
def test_needs_rehash_without_a_stronger_algorithm(no_backends, stored, expected):
    assert AuthManager.needs_rehash(stored) is expected


def test_needs_rehash_asks_to_replace_pbkdf2_when_a_stronger_algorithm_exists(monkeypatch):
    monkeypatch.setattr(auth_manager, "HAS_ARGON2", True)
    assert AuthManager.needs_rehash("pbkdf2:sha256:600000:c2Fs:aGFzaA==")


def test_bcrypt_when_argon2_is_not_available(monkeypatch):
    pytest.importorskip("bcrypt")
    monkeypatch.setattr(auth_manager, "HAS_ARGON2", False)
    monkeypatch.setattr(auth_manager, "HAS_BCRYPT", True)
    assert AuthManager.get_available_crypto_backend() == "bcrypt"
    stored = AuthManager.hash_password("Correct-123")
    assert stored.startswith("bcrypt:$2")
    assert AuthManager.verify_password("Correct-123", stored)
    assert not AuthManager.verify_password("Wrong-123", stored)


@pytest.mark.parametrize("stored", [
    "", "nothing", "argon2:not-a-hash", "bcrypt:not-a-hash", "pbkdf2:sha256:1000:%%%:%%%",
    "pbkdf2:md99:1000:c2Fs:aGFzaA==", "a:b:c",
])
def test_verify_password_with_an_unreadable_hash_returns_false(stored):
    assert AuthManager.verify_password("x", stored) is False


def test_password_without_lowercase_says_so():
    _, feedback = AuthManager.evaluate_password_strength("UPPERCASE-9")
    assert "Include at least one lowercase letter." in feedback


# --- Typed schemas ---------------------------------------------------------------------------

@pytest.mark.parametrize("value, type_, expected", [
    (1.5, float, True), (1, float, False), (True, float, False),
    (1, int, True), (True, int, False), (False, bool, True), ("x", str, True), ([], list, True),
])
def test_strict_types(value, type_, expected):
    assert matches_schema_type(value, type_) is expected


@pytest.mark.parametrize("payload, schema, message", [
    ([], {"id": int}, "The payload is not a JSON object (dict)."),
    ({}, {"id": int}, "Missing required field: 'id'"),
    ({"user": "ana"}, {"user": {"name": str}}, "'user' must be an object, got str"),
    ({"tags": "a,b"}, {"tags": [str]}, "'tags' must be a list, got str"),
    ({"tags": ["a", 2]}, {"tags": [str]}, "tags[1]"),
    ({"x": 1}, {"x": "int"}, "Unsupported schema at 'x'"),
])
def test_schema_explains_every_error(payload, schema, message):
    ok, errors = validate_typed_schema(payload, schema)
    assert not ok
    assert any(message in e for e in errors), errors


def test_valid_schema_with_lists_and_nested_objects():
    schema = {"id": int, "tags": [str], "owner": {"name": str, "score": float}}
    assert validate_typed_schema({"id": 1, "tags": [], "owner": {"name": "a", "score": 1.0}}, schema) == (True, [])


# --- Input sanitisation ---------------------------------------------------------------------

def test_sanitize_html_escapes_and_rejects_other_types():
    assert InputSanitizer.sanitize_html('  <img src=x onerror="alert(1)">  ') == \
        "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;"
    assert InputSanitizer.sanitize_html(None) == ""


@pytest.mark.parametrize("email, expected", [
    ("ana@example.com", True), ("  ana.b+tag@sub.example.org ", True), ("ana@", False),
    ("@example.com", False), ("ana example@x.com", False), ("", False), (None, False),
])
def test_validate_email(email, expected):
    assert InputSanitizer.validate_email(email) is expected


@pytest.mark.parametrize("name, expected", [
    ("report.pdf", "report.pdf"), ("../../etc/passwd", "passwd"), ("", "file_default"),
    (None, "file_default"),
])
def test_sanitize_filename(name, expected):
    assert InputSanitizer.sanitize_filename(name) == expected


def test_safe_path_rejects_anything_outside_the_base(tmp_path):
    base = str(tmp_path)
    assert InputSanitizer.validate_safe_path(base, "sub/a.txt") == str(tmp_path / "sub" / "a.txt")
    assert InputSanitizer.validate_safe_path(base, "../outside.txt") is None
    assert InputSanitizer.validate_safe_path(base, "/etc/passwd") is None
    assert InputSanitizer.validate_safe_path(base, None) is None
    assert InputSanitizer.validate_safe_path(base, "a\x00b") is None


@pytest.mark.parametrize("text, allowed, expected", [
    ("user_1", r"a-zA-Z0-9_", True),
    ("user 1", r"a-zA-Z0-9_", False),
    ("", r"a-z", True),
    (None, r"a-z", False),
    # In Python `$` also matches before a trailing newline: "admin\n" must not pass a letters-only allow-list.
    ("admin\n", r"a-z", False),
    ("with space\n", r"a-z\s", True),
])
def test_allow_list(text, allowed, expected):
    assert InputSanitizer.validate_string_whitelist(text, allowed) is expected


@pytest.mark.parametrize("value, minimum, maximum, expected", [
    ("42", None, None, 42), (42, 0, 100, 42), (-1, 0, 100, None), (101, 0, 100, None),
    ("x", None, None, None), (None, None, None, None), (True, None, None, None), (3.9, None, None, 3),
])
def test_sanitize_integer(value, minimum, maximum, expected):
    assert InputSanitizer.sanitize_integer(value, minimum, maximum) == expected


def test_validate_json_schema_delegates_to_the_schema_module():
    assert InputSanitizer.validate_json_schema({"id": 1}, {"id": int}) == (True, [])
    ok, _ = InputSanitizer.validate_json_schema({"id": 1, "extra": 2}, {"id": int}, reject_extra_keys=True)
    assert not ok
