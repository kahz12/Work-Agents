import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple, Type

from . import password_policy

# Argon2 and bcrypt are optional (the "crypto" extra). Without them, PBKDF2-HMAC-SHA256 is used.
try:
    import argon2
except ImportError:
    argon2 = None  # type: ignore[assignment]

try:
    import bcrypt
except ImportError:
    bcrypt = None  # type: ignore[assignment]

HAS_ARGON2 = argon2 is not None
HAS_BCRYPT = bcrypt is not None
_ARGON2_ERRORS: Tuple[Type[BaseException], ...] = (argon2.exceptions.Argon2Error,) if argon2 is not None else ()
# What verifying a malformed hash can raise. Such a hash simply does not match; nothing propagates.
_VERIFY_ERRORS: Tuple[Type[BaseException], ...] = (*_ARGON2_ERRORS, ValueError, TypeError, IndexError)

# OWASP (2023) recommended minimum for PBKDF2-HMAC-SHA256.
PBKDF2_ITERATIONS = 600_000


class RateLimiter:
    """
    In-memory sliding-window rate limiter.

    Slows down brute-force attempts against sensitive endpoints. The number of tracked
    identifiers is capped at max_tracked_keys: stale identifiers are evicted first, then the
    oldest ones, so an attacker rotating identifiers cannot grow memory without bound.
    """
    def __init__(self, max_requests: int = 5, window_seconds: int = 60, max_tracked_keys: int = 10000):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_tracked_keys = max(1, max_tracked_keys)
        self.requests: Dict[str, List[float]] = {}

    def _evict_stale(self, now: float) -> None:
        expired = [
            key for key, ts in self.requests.items()
            if not ts or now - ts[-1] >= self.window_seconds
        ]
        for key in expired:
            del self.requests[key]
        while len(self.requests) >= self.max_tracked_keys:
            oldest_key = next(iter(self.requests))
            del self.requests[oldest_key]

    def is_allowed(self, identifier: str) -> bool:
        now = time.time()
        timestamps = [t for t in self.requests.get(identifier, []) if now - t < self.window_seconds]

        if len(timestamps) < self.max_requests:
            if identifier not in self.requests and len(self.requests) >= self.max_tracked_keys:
                self._evict_stale(now)
            timestamps.append(now)
            self.requests[identifier] = timestamps
            return True

        if timestamps:
            self.requests[identifier] = timestamps
        else:
            self.requests.pop(identifier, None)
        return False


class AuthManager:
    """
    Authentication helpers: password hashing (Argon2 / bcrypt / PBKDF2), anti-CSRF tokens,
    HMAC-signed tokens, password strength scoring and role-based access control.
    """

    @staticmethod
    def get_available_crypto_backend() -> str:
        """
        Name of the password hashing backend in use, best available first.
        """
        if HAS_ARGON2:
            return "argon2"
        elif HAS_BCRYPT:
            return "bcrypt"
        return "pbkdf2:sha256"

    @staticmethod
    def evaluate_password_strength(password: str) -> Tuple[int, List[str]]:
        """
        Score a password from 0 to 6 and explain how to improve it. 5 is acceptable.

        Besides composition, it penalises what attackers try first: well-known base words,
        keyboard sequences, repetitions and years. A long passphrase (16 characters or more)
        counts as acceptable even without symbols or digits.
        It makes no network calls; password_policy.pwned_count does that.
        """
        score, feedback = AuthManager._composition_score(password)
        if len(password) >= 16:
            # In a long passphrase, length makes up for composition, so no symbols are demanded.
            feedback = []

        if len(password) >= 20:
            score = max(score, 6)
        elif len(password) >= 16:
            score = max(score, 5)

        common = password_policy.common_base(password)
        if common:
            score = min(score, 2)
            feedback.insert(0, f"It is based on a very common password ('{common}'): one of the first an attacker tries.")
        sequence = password_policy.keyboard_sequence(password)
        if sequence:
            score -= 2
            feedback.append(f"It contains a predictable sequence ('{sequence}').")
        repeated = password_policy.repetition(password)
        if repeated:
            score -= 1
            feedback.append(f"It repeats characters or blocks ('{repeated}').")
            if password_policy.is_short_block_repeated(password):
                score = min(score, 1)
        year = password_policy.year(password)
        if year:
            score -= 1
            feedback.append(f"It includes a year ('{year}'), which is easy to guess.")
        return max(0, min(6, score)), feedback

    @staticmethod
    def _composition_score(password: str) -> Tuple[int, List[str]]:
        """Score from length and character classes alone (0 to 6)."""
        score = 0
        feedback = []

        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("Use at least 12 characters.")

        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Include at least one uppercase letter.")

        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Include at least one lowercase letter.")

        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Include at least one digit.")

        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        else:
            feedback.append("Include at least one special character.")

        return score, feedback

    @staticmethod
    def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
        """
        Hash a password with Argon2 or bcrypt when installed, otherwise with PBKDF2-HMAC-SHA256,
        a random 16-byte salt and `iterations` rounds (600,000 by default).

        The result is prefixed with its backend ("argon2:", "bcrypt:", "pbkdf2:sha256:...") so
        verify_password knows how to check it.
        """
        if HAS_ARGON2:
            ph = argon2.PasswordHasher()
            return f"argon2:{ph.hash(password)}"
        elif HAS_BCRYPT:
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            return f"bcrypt:{hashed.decode('ascii')}"

        salt = os.urandom(16)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
        return f"pbkdf2:sha256:{iterations}:{base64.b64encode(salt).decode('ascii')}:{base64.b64encode(pwd_hash).decode('ascii')}"

    @staticmethod
    def needs_rehash(stored_hash_str: str) -> bool:
        """
        True for a PBKDF2 hash with fewer iterations than recommended, or for any PBKDF2 hash
        when a stronger algorithm is available. Rehash it after the user's next login.
        """
        if not stored_hash_str.startswith("pbkdf2:"):
            return False
        if HAS_ARGON2 or HAS_BCRYPT:
            return True
        try:
            return int(stored_hash_str.split(":")[2]) < PBKDF2_ITERATIONS
        except (IndexError, ValueError):
            return True

    @staticmethod
    def verify_password(password: str, stored_hash_str: str) -> bool:
        """
        Check a password against its stored hash using a constant-time comparison. A malformed
        hash returns False instead of raising.
        """
        try:
            if stored_hash_str.startswith("argon2:") and HAS_ARGON2:
                ph = argon2.PasswordHasher()
                return ph.verify(stored_hash_str[7:], password)
            elif stored_hash_str.startswith("bcrypt:") and HAS_BCRYPT:
                return bcrypt.checkpw(password.encode('utf-8'), stored_hash_str[7:].encode('ascii'))

            algorithm, hash_name, iterations_str, salt_b64, hash_b64 = stored_hash_str.split(':')
            iterations = int(iterations_str)
            salt = base64.b64decode(salt_b64)
            expected_hash = base64.b64decode(hash_b64)

            calculated_hash = hashlib.pbkdf2_hmac(hash_name, password.encode('utf-8'), salt, iterations)
            return hmac.compare_digest(calculated_hash, expected_hash)
        except _VERIFY_ERRORS:
            return False

    @staticmethod
    def create_csrf_token(secret_key: str, session_id: str, expires_in_seconds: int = 1800) -> str:
        """
        Create an HMAC-based anti-CSRF token bound to the session ID.
        Format: {session_id}:{exp}:{sig}. session_id may itself contain ':' because
        verification splits from the right (exp and sig are always the last two fields).
        """
        exp = int(time.time()) + expires_in_seconds
        msg = f"{session_id}:{exp}".encode('utf-8')
        sig = hmac.new(secret_key.encode('utf-8'), msg, hashlib.sha256).hexdigest()
        return f"{session_id}:{exp}:{sig}"

    @staticmethod
    def verify_csrf_token(token: str, secret_key: str, current_session_id: str) -> bool:
        """
        Check an anti-CSRF token's signature, session binding and expiry.
        Uses rsplit(':', 2) so session IDs containing colons are supported.
        """
        try:
            parts = token.rsplit(':', 2)
            if len(parts) != 3:
                return False
            session_id, exp_str, sig = parts
            if not exp_str.isdigit() or len(sig) != 64:
                return False
            exp = int(exp_str)

            if session_id != current_session_id:
                return False
            if time.time() > exp:
                return False

            msg = f"{session_id}:{exp}".encode('utf-8')
            expected_sig = hmac.new(secret_key.encode('utf-8'), msg, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected_sig, sig)
        except (ValueError, TypeError, AttributeError):
            return False

    @staticmethod
    def create_secure_token(payload: Dict[str, Any], secret_key: str, expires_in_seconds: int = 3600) -> str:
        """
        Create a JWT-shaped token signed with HMAC-SHA256. An `exp` claim is always added.
        """
        payload_copy = payload.copy()
        payload_copy['exp'] = int(time.time()) + expires_in_seconds

        header = {"alg": "HS256", "typ": "JWT"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload_copy).encode()).decode().rstrip('=')

        signature_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        signature = hmac.new(secret_key.encode('utf-8'), signature_input, hashlib.sha256).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')

        return f"{header_b64}.{payload_b64}.{signature_b64}"

    @staticmethod
    def verify_secure_token(token: str, secret_key: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """
        Check a token's algorithm, signature and expiry. Returns (valid, payload, reason).
        Only HS256 is accepted, which rules out "alg: none" and algorithm-confusion attacks.
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return False, None, "Invalid token format"

            header_b64, payload_b64, signature_b64 = parts

            def pad_b64(str_val: str) -> str:
                return str_val + '=' * (-len(str_val) % 4)

            header_json = base64.urlsafe_b64decode(pad_b64(header_b64)).decode('utf-8')
            header = json.loads(header_json)
            if not isinstance(header, dict) or header.get('alg') != 'HS256':
                return False, None, "Unsupported token algorithm"

            signature_input = f"{header_b64}.{payload_b64}".encode('utf-8')
            expected_sig = hmac.new(secret_key.encode('utf-8'), signature_input, hashlib.sha256).digest()
            actual_sig = base64.urlsafe_b64decode(pad_b64(signature_b64))

            if not hmac.compare_digest(expected_sig, actual_sig):
                return False, None, "Invalid token signature (possible tampering)"

            payload_json = base64.urlsafe_b64decode(pad_b64(payload_b64)).decode('utf-8')
            payload = json.loads(payload_json)
            if not isinstance(payload, dict):
                return False, None, "Verification error: malformed token"

            if 'exp' in payload:
                exp_val = payload['exp']
                if isinstance(exp_val, bool) or not isinstance(exp_val, (int, float)):
                    return False, None, "Verification error: malformed token"
                if time.time() > exp_val:
                    return False, None, "Token expired"

            return True, payload, "Valid token"
        except (ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeDecodeError):
            return False, None, "Verification error: malformed token"

    @staticmethod
    def check_permission(user_roles: List[str], required_permission: str, role_permissions_map: Dict[str, List[str]]) -> bool:
        """
        Role-based access control: True when any of the user's roles grants the permission.
        Unknown roles grant nothing; "*" in a role's list grants everything.
        """
        for role in user_roles:
            allowed_permissions = role_permissions_map.get(role, [])
            if required_permission in allowed_permissions or "*" in allowed_permissions:
                return True
        return False
