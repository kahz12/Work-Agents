"""
Comprobaciones de contraseñas que van más allá de contar tipos de carácter.

`Password123!` cumple cualquier regla de composición (mayúscula, minúscula, número,
símbolo, 12 caracteres) y es de las primeras que prueba un atacante. Aquí se detecta:

- Bases muy conocidas, también con sustituciones típicas (P4ssw0rd, Adm1n).
- Secuencias de teclado o alfabéticas (qwerty, 1234, abcd).
- Repeticiones (aaaa, abcabcabc).
- Años (2026), que se adivinan con facilidad.
- Apariciones en filtraciones conocidas, con la API de Have I Been Pwned por k-anonimato:
  solo se envían los 5 primeros caracteres del hash SHA-1, nunca la contraseña.
"""
from __future__ import annotations

import hashlib
import re
import urllib.error
import urllib.request
from typing import Optional

from ..common.network import is_offline

PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"

# Bases que aparecen una y otra vez en las listas de contraseñas filtradas, en inglés y en
# castellano. Se comparan después de quitar números y símbolos de los extremos.
COMMON_BASES = frozenset("""
password passwort passwd pass contraseña contrasena clave secreto secret letmein welcome
bienvenido admin administrator administrador root user usuario login guest invitado test
qwerty qwertz azerty asdf zxcvbnm abc abcd abcde iloveyou teamo tequiero amor love
monkey dragon master shadow sunshine princess princesa football futbol baseball soccer
superman batman starwars pokemon hello hola trustno freedom whatever michael jessica
charlie daniel maria jose juan carlos andrea alejandro barcelona madrid realmadrid
mexico argentina colombia espana españa chile peru america samsung apple google
computer ordenador internet linux windows changeme cambiame default demo company empresa
summer winter spring autumn verano invierno primavera otoño
""".split())

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
_SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjklñ", "zxcvbnm", "01234567890", "qwertzuiop", "azertyuiop")


def base_word(password: str) -> str:
    """La palabra que queda al quitar números y símbolos de los extremos y deshacer el leet."""
    # Primero se recortan los extremos ("Admin2026!!!" -> "Admin") y después se deshacen las
    # sustituciones del interior ("P4ssw0rd" -> "password"). Al revés, los "!!!" finales
    # pasarían a "iii" y la base dejaría de reconocerse.
    core = re.sub(r"^[^A-Za-zÑñ]+|[^A-Za-zÑñ]+$", "", password)
    return core.lower().translate(_LEET)


def common_base(password: str) -> Optional[str]:
    """La base conocida en la que se apoya la contraseña, o None."""
    candidates = {base_word(password), password.lower()}
    repeated = re.fullmatch(r"(.+?)\1+", password.lower())
    if repeated:
        candidates.add(base_word(repeated.group(1)))
    for word in candidates:
        if word in COMMON_BASES:
            return word
    # También una base conocida seguida de otra palabra corta: "adminpanel", "passwordfuerte".
    word = base_word(password)
    for known in COMMON_BASES:
        if len(known) >= 5 and word.startswith(known) and len(word) - len(known) <= 6:
            return known
    return None


def keyboard_sequence(password: str, min_len: int = 4) -> Optional[str]:
    """La primera secuencia de teclado o alfabética de al menos min_len caracteres, o None."""
    low = password.lower()
    for seq in _SEQUENCES:
        for source in (seq, seq[::-1]):
            for start in range(len(source) - min_len + 1):
                chunk = source[start:start + min_len]
                if chunk in low:
                    return chunk
    return None


def is_short_block_repeated(password: str) -> bool:
    """La contraseña entera es un bloque de hasta 4 caracteres repetido: "aaaaaaaa", "abcabcabc"."""
    return re.fullmatch(r"(.{1,4})\1+", password) is not None


def repetition(password: str) -> Optional[str]:
    """Un carácter repetido tres o más veces seguidas, o la contraseña entera como bloque repetido."""
    run = re.search(r"(.)\1{2,}", password)
    if run:
        return run.group(0)
    block = re.fullmatch(r"(.{1,8}?)\1+", password)
    return block.group(0) if block else None


def year(password: str) -> Optional[str]:
    match = re.search(r"(?<!\d)(19[5-9]\d|20[0-4]\d)(?!\d)", password)
    return match.group(0) if match else None


def pwned_count(password: str, *, timeout: float = 5.0) -> Optional[int]:
    """
    Veces que la contraseña aparece en filtraciones conocidas (Have I Been Pwned).
    0 si no aparece; None si no se pudo consultar o está activo el modo sin conexión.
    """
    if is_offline():
        return None
    # SHA-1 es lo que exige la API de rangos; aquí no protege nada, solo identifica.
    digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    req = urllib.request.Request(
        PWNED_RANGE_URL.format(prefix=prefix),
        headers={"User-Agent": "agentes-devsecops", "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - URL fija https
            body = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None
    for line in body.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate == suffix:
            return int(count or 0)  # el relleno (Add-Padding) llega con recuento 0
    return 0
