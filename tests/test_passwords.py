"""Tests for the password policy, Have I Been Pwned (simulated) and PBKDF2."""
import base64
import hashlib
import io
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentes.defensive import auth_manager, password_policy  # noqa: E402
from agentes.defensive.auth_manager import AuthManager  # noqa: E402


@pytest.mark.parametrize("password", [
    "Password123!", "Qwerty12345!", "Admin2026!!!", "P4ssw0rd!2024", "Adm1n-Panel",
    "Princesa2001", "aaaaaaaaaaaaaaaaaaaaaa", "abcabcabcabcabcabc", "passwordpasswordpassword", "abc",
])
def test_well_known_or_predictable_passwords_are_weak(password):
    score, feedback = AuthManager.evaluate_password_strength(password)
    assert score < 5, (password, score)
    assert feedback


@pytest.mark.parametrize("password", ["Tr0mb0ne-Blue-Rain", "kX9#mQ2$vL7!", "correct horse battery staple", "Abc123!@#Secure"])
def test_strong_passwords_and_long_passphrases_are_acceptable(password):
    score, _ = AuthManager.evaluate_password_strength(password)
    assert score >= 5, (password, score)


def test_long_passphrase_does_not_ask_for_symbols():
    _, feedback = AuthManager.evaluate_password_strength("correct horse battery staple")
    assert feedback == []


def test_base_word_trims_before_undoing_leetspeak():
    assert password_policy.base_word("Admin2026!!!") == "admin"
    assert password_policy.base_word("P4ssw0rd!2024") == "password"
    assert password_policy.keyboard_sequence("xx4321yy") == "4321"
    assert password_policy.year("Key1999x") == "1999"
    assert password_policy.year("Key19995") is None


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_pwned_count_uses_k_anonymity(monkeypatch):
    monkeypatch.delenv("AGENTES_OFFLINE", raising=False)
    digest = hashlib.sha1(b"Password123!", usedforsecurity=False).hexdigest().upper()
    sent = []

    def urlopen(req, timeout):
        sent.append(req.full_url)
        assert req.headers.get("Add-padding") == "true"
        body = f"0000000000000000000000000000000000A:0\n{digest[5:]}:295527\n"
        return _Response(body.encode())

    monkeypatch.setattr(password_policy.urllib.request, "urlopen", urlopen)
    assert password_policy.pwned_count("Password123!") == 295527
    assert sent == [f"https://api.pwnedpasswords.com/range/{digest[:5]}"], "only the prefix is sent"
    assert password_policy.pwned_count("some-other-password") == 0


def test_pwned_count_without_network_returns_none(monkeypatch):
    assert password_policy.pwned_count("Password123!") is None  # AGENTES_OFFLINE=1, set by conftest
    monkeypatch.delenv("AGENTES_OFFLINE", raising=False)

    def down(req, timeout):
        raise OSError("no network")

    monkeypatch.setattr(password_policy.urllib.request, "urlopen", down)
    assert password_policy.pwned_count("Password123!") is None


def test_pbkdf2_uses_600000_iterations_and_detects_old_hashes(monkeypatch):
    monkeypatch.setattr(auth_manager, "HAS_ARGON2", False)
    monkeypatch.setattr(auth_manager, "HAS_BCRYPT", False)
    new = AuthManager.hash_password("Tr0mb0ne-Blue-Rain")
    assert new.startswith("pbkdf2:sha256:600000:")
    assert AuthManager.verify_password("Tr0mb0ne-Blue-Rain", new)
    assert not AuthManager.needs_rehash(new)

    salt = os.urandom(16)
    old_digest = hashlib.pbkdf2_hmac("sha256", b"secret", salt, 100_000)
    old = f"pbkdf2:sha256:100000:{base64.b64encode(salt).decode()}:{base64.b64encode(old_digest).decode()}"
    assert AuthManager.verify_password("secret", old), "old hashes still verify"
    assert AuthManager.needs_rehash(old)

    monkeypatch.setattr(auth_manager, "HAS_BCRYPT", True)
    assert AuthManager.needs_rehash(new), "with a stronger algorithm available, PBKDF2 hashes are regenerated"


def test_cli_password_check_fails_when_the_password_was_breached(monkeypatch, capsys):
    from agentes import cli

    monkeypatch.setattr(password_policy, "pwned_count", lambda password, timeout=5.0: 12)
    monkeypatch.setattr(sys, "stdin", io.StringIO("Tr0mb0ne-Blue-Rain\n"))
    code = cli.main(["password", "check", "--stdin"])
    out = capsys.readouterr().out
    assert code == 1, "a breached password is rejected however high it scores"
    assert "12 times" in out
