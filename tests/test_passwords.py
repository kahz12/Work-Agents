"""Tests de la política de contraseñas, Have I Been Pwned (simulado) y PBKDF2."""
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
def test_contrasenas_conocidas_o_predecibles_son_debiles(password):
    score, feedback = AuthManager.evaluate_password_strength(password)
    assert score < 5, (password, score)
    assert feedback


@pytest.mark.parametrize("password", ["Tr0mb0n-Azul-Lluvia", "kX9#mQ2$vL7!", "caballo correcto pila grapa", "Abc123!@#Seguro"])
def test_contrasenas_robustas_y_frases_largas_son_aceptables(password):
    score, _ = AuthManager.evaluate_password_strength(password)
    assert score >= 5, (password, score)


def test_frase_larga_no_pide_simbolos():
    _, feedback = AuthManager.evaluate_password_strength("caballo correcto pila grapa")
    assert feedback == []


def test_base_word_recorta_antes_de_deshacer_el_leet():
    assert password_policy.base_word("Admin2026!!!") == "admin"
    assert password_policy.base_word("P4ssw0rd!2024") == "password"
    assert password_policy.keyboard_sequence("xx4321yy") == "4321"
    assert password_policy.year("Clave1999x") == "1999"
    assert password_policy.year("Clave19995") is None


class _Respuesta(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_pwned_count_por_k_anonimato(monkeypatch):
    monkeypatch.delenv("AGENTES_OFFLINE", raising=False)
    digest = hashlib.sha1(b"Password123!", usedforsecurity=False).hexdigest().upper()
    enviados = []

    def urlopen(req, timeout):
        enviados.append(req.full_url)
        assert req.headers.get("Add-padding") == "true"
        cuerpo = f"0000000000000000000000000000000000A:0\n{digest[5:]}:295527\n"
        return _Respuesta(cuerpo.encode())

    monkeypatch.setattr(password_policy.urllib.request, "urlopen", urlopen)
    assert password_policy.pwned_count("Password123!") == 295527
    assert enviados == [f"https://api.pwnedpasswords.com/range/{digest[:5]}"], "solo se envía el prefijo"
    assert password_policy.pwned_count("otra-clave-distinta") == 0


def test_pwned_count_sin_red_devuelve_none(monkeypatch):
    assert password_policy.pwned_count("Password123!") is None  # AGENTES_OFFLINE=1 por conftest
    monkeypatch.delenv("AGENTES_OFFLINE", raising=False)

    def caido(req, timeout):
        raise OSError("sin red")

    monkeypatch.setattr(password_policy.urllib.request, "urlopen", caido)
    assert password_policy.pwned_count("Password123!") is None


def test_pbkdf2_usa_600000_iteraciones_y_detecta_hashes_antiguos(monkeypatch):
    monkeypatch.setattr(auth_manager, "HAS_ARGON2", False)
    monkeypatch.setattr(auth_manager, "HAS_BCRYPT", False)
    nuevo = AuthManager.hash_password("Tr0mb0n-Azul-Lluvia")
    assert nuevo.startswith("pbkdf2:sha256:600000:")
    assert AuthManager.verify_password("Tr0mb0n-Azul-Lluvia", nuevo)
    assert not AuthManager.needs_rehash(nuevo)

    sal = os.urandom(16)
    viejo_hash = hashlib.pbkdf2_hmac("sha256", b"clave", sal, 100_000)
    viejo = f"pbkdf2:sha256:100000:{base64.b64encode(sal).decode()}:{base64.b64encode(viejo_hash).decode()}"
    assert AuthManager.verify_password("clave", viejo), "los hashes antiguos siguen verificando"
    assert AuthManager.needs_rehash(viejo)

    monkeypatch.setattr(auth_manager, "HAS_BCRYPT", True)
    assert AuthManager.needs_rehash(nuevo), "con un algoritmo mejor disponible, PBKDF2 se regenera"


def test_cli_password_check_falla_si_esta_filtrada(monkeypatch, capsys):
    from agentes import cli

    monkeypatch.setattr(password_policy, "pwned_count", lambda password, timeout=5.0: 12)
    monkeypatch.setattr(sys, "stdin", io.StringIO("Tr0mb0n-Azul-Lluvia\n"))
    code = cli.main(["password", "check", "--stdin"])
    out = capsys.readouterr().out
    assert code == 1, "aunque la puntuación sea alta, una contraseña filtrada no se acepta"
    assert "12 veces" in out
