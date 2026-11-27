"""
Password checks that go beyond counting character classes.

`Password123!` satisfies every composition rule (uppercase, lowercase, digit, symbol,
12 characters) and is still one of the first passwords an attacker tries. This module detects:

- Very common base words, including typical substitutions (P4ssw0rd, Adm1n).
- Keyboard or alphabetical sequences (qwerty, 1234, abcd).
- Repetitions (aaaa, abcabcabc).
- Years (2026), which are easy to guess.
- Appearances in known breaches, through the Have I Been Pwned API with k-anonymity: only
  the first 5 characters of the SHA-1 hash are sent, never the password.
"""
from __future__ import annotations

import hashlib
import re
import urllib.error
import urllib.request
from typing import Optional

from ..common.network import is_offline

PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"

# Base words that show up again and again in leaked password lists, in English and Spanish
# (the tool is used on both). They are compared after stripping leading and trailing digits
# and symbols.
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
    """The word left after stripping digits and symbols from both ends and undoing leetspeak."""
    # Trim the ends first ("Admin2026!!!" -> "Admin"), then undo substitutions inside the word
    # ("P4ssw0rd" -> "password"). The other way round, a trailing "!!!" would turn into "iii"
    # and the base word would no longer be recognised.
    core = re.sub(r"^[^A-Za-zÑñ]+|[^A-Za-zÑñ]+$", "", password)
    return core.lower().translate(_LEET)


def common_base(password: str) -> Optional[str]:
    """The well-known base word the password is built on, or None."""
    candidates = {base_word(password), password.lower()}
    repeated = re.fullmatch(r"(.+?)\1+", password.lower())
    if repeated:
        candidates.add(base_word(repeated.group(1)))
    for word in candidates:
        if word in COMMON_BASES:
            return word
    # Also a known base followed by another short word: "adminpanel", "passwordstrong".
    word = base_word(password)
    for known in COMMON_BASES:
        if len(known) >= 5 and word.startswith(known) and len(word) - len(known) <= 6:
            return known
    return None


def keyboard_sequence(password: str, min_len: int = 4) -> Optional[str]:
    """The first keyboard or alphabetical sequence of at least min_len characters, or None."""
    low = password.lower()
    for seq in _SEQUENCES:
        for source in (seq, seq[::-1]):
            for start in range(len(source) - min_len + 1):
                chunk = source[start:start + min_len]
                if chunk in low:
                    return chunk
    return None


def is_short_block_repeated(password: str) -> bool:
    """True when the whole password is one block of up to 4 characters repeated: "aaaaaaaa", "abcabcabc"."""
    return re.fullmatch(r"(.{1,4})\1+", password) is not None


def repetition(password: str) -> Optional[str]:
    """A character repeated three or more times in a row, or the whole password as a repeated block."""
    run = re.search(r"(.)\1{2,}", password)
    if run:
        return run.group(0)
    block = re.fullmatch(r"(.{1,8}?)\1+", password)
    return block.group(0) if block else None


def year(password: str) -> Optional[str]:
    """A plausible year (1950-2049) standing on its own, not as part of a longer number."""
    match = re.search(r"(?<!\d)(19[5-9]\d|20[0-4]\d)(?!\d)", password)
    return match.group(0) if match else None


def pwned_count(password: str, *, timeout: float = 5.0) -> Optional[int]:
    """
    How many times the password appears in known breaches (Have I Been Pwned).
    0 when it does not appear; None when the lookup failed or offline mode is on.
    """
    if is_offline():
        return None
    # The range API is keyed by SHA-1. It protects nothing here, it only identifies the password.
    digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    req = urllib.request.Request(
        PWNED_RANGE_URL.format(prefix=prefix),
        # Add-Padding pads the response with fake entries so its size does not leak the prefix.
        headers={"User-Agent": "agentes-devsecops", "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URL
            body = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None
    for line in body.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate == suffix:
            return int(count or 0)  # padding entries come back with a count of 0
    return 0
