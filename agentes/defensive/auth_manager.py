import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple, Type

from . import password_policy

# Argon2 y bcrypt son opcionales (extra "crypto"). Sin ellos se usa PBKDF2-HMAC-SHA256.
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
# Lo que puede lanzar la verificación de un hash mal formado: no coincide, no se lanza.
_VERIFY_ERRORS: Tuple[Type[BaseException], ...] = (*_ARGON2_ERRORS, ValueError, TypeError, IndexError)

# Mínimo recomendado por OWASP (2023) para PBKDF2-HMAC-SHA256.
PBKDF2_ITERATIONS = 600_000


class RateLimiter:
    """
    Limitador de frecuencia por ventana deslizante (*Sliding Window Rate Limiter*) en memoria.
    Previene ataques de fuerza bruta en endpoints sensibles y limita la memoria rastreada.
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
    Módulo para autenticación segura, hashing defensivo de contraseñas (Argon2 / Bcrypt / PBKDF2),
    tokens anti-CSRF, tokens HMAC, verificación de fuerza de clave y RBAC.
    """

    @staticmethod
    def get_available_crypto_backend() -> str:
        """
        Retorna el motor criptográfico activo para hashing de contraseñas.
        """
        if HAS_ARGON2:
            return "argon2"
        elif HAS_BCRYPT:
            return "bcrypt"
        return "pbkdf2:sha256"

    @staticmethod
    def evaluate_password_strength(password: str) -> Tuple[int, List[str]]:
        """
        Puntúa una contraseña de 0 a 6 y explica cómo mejorarla. 5 es aceptable.

        Además de la composición, penaliza lo que un atacante prueba primero: bases muy
        conocidas, secuencias de teclado, repeticiones y años. Una frase larga (16 o más
        caracteres) cuenta como aceptable aunque no tenga símbolos ni números.
        No consulta la red; para eso está password_policy.pwned_count.
        """
        score, feedback = AuthManager._composition_score(password)
        if len(password) >= 16:
            # En una frase larga la longitud compensa la composición: no se piden símbolos.
            feedback = []

        if len(password) >= 20:
            score = max(score, 6)
        elif len(password) >= 16:
            score = max(score, 5)

        common = password_policy.common_base(password)
        if common:
            score = min(score, 2)
            feedback.insert(0, f"Se basa en una contraseña muy conocida ('{common}'): es de las primeras que se prueban.")
        sequence = password_policy.keyboard_sequence(password)
        if sequence:
            score -= 2
            feedback.append(f"Contiene una secuencia predecible ('{sequence}').")
        repeated = password_policy.repetition(password)
        if repeated:
            score -= 1
            feedback.append(f"Repite caracteres o bloques ('{repeated}').")
            if password_policy.is_short_block_repeated(password):
                score = min(score, 1)
        year = password_policy.year(password)
        if year:
            score -= 1
            feedback.append(f"Incluye un año ('{year}'), fácil de adivinar.")
        return max(0, min(6, score)), feedback

    @staticmethod
    def _composition_score(password: str) -> Tuple[int, List[str]]:
        """Puntuación por longitud y tipos de carácter (0 a 6)."""
        score = 0
        feedback = []

        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("La contraseña debe tener al menos 12 caracteres.")

        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Incluye al menos una letra mayúscula.")

        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Incluye al menos una letra minúscula.")

        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Incluye al menos un número.")

        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        else:
            feedback.append("Incluye al menos un carácter especial.")

        return score, feedback

    @staticmethod
    def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
        """
        Genera un hash con Argon2 o bcrypt si están instalados y, si no, con
        PBKDF2-HMAC-SHA256, sal aleatoria e iterations iteraciones (600 000 por defecto).
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
        True si el hash es de PBKDF2 con menos iteraciones de las recomendadas, o de PBKDF2
        cuando hay disponible un algoritmo mejor. Conviene regenerarlo tras el próximo login.
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
        Verifica una contraseña contra su hash almacenado usando comparación en tiempo constante.
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
        Crea un token anti-CSRF basado en HMAC ligado al ID de sesión.
        Formato: {session_id}:{exp}:{sig}. session_id puede contener ':' porque
        la verificación usa rsplit desde la derecha (exp y sig son los 2 últimos campos).
        """
        exp = int(time.time()) + expires_in_seconds
        msg = f"{session_id}:{exp}".encode('utf-8')
        sig = hmac.new(secret_key.encode('utf-8'), msg, hashlib.sha256).hexdigest()
        return f"{session_id}:{exp}:{sig}"

    @staticmethod
    def verify_csrf_token(token: str, secret_key: str, current_session_id: str) -> bool:
        """
        Verifica la autenticidad y validez temporal de un token anti-CSRF.
        Usa rsplit(':', 2) para soportar session_id con dos puntos.
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
        Crea un token firmado con HMAC-SHA256 con tiempo de expiración.
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
        Verifica la firma y la validez temporal de un token.
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return False, None, "Formato de token inválido"

            header_b64, payload_b64, signature_b64 = parts

            def pad_b64(str_val: str) -> str:
                return str_val + '=' * (-len(str_val) % 4)

            header_json = base64.urlsafe_b64decode(pad_b64(header_b64)).decode('utf-8')
            header = json.loads(header_json)
            if not isinstance(header, dict) or header.get('alg') != 'HS256':
                return False, None, "Algoritmo de token no soportado"

            signature_input = f"{header_b64}.{payload_b64}".encode('utf-8')
            expected_sig = hmac.new(secret_key.encode('utf-8'), signature_input, hashlib.sha256).digest()
            actual_sig = base64.urlsafe_b64decode(pad_b64(signature_b64))

            if not hmac.compare_digest(expected_sig, actual_sig):
                return False, None, "Firma del token no válida (posible manipulación)"

            payload_json = base64.urlsafe_b64decode(pad_b64(payload_b64)).decode('utf-8')
            payload = json.loads(payload_json)
            if not isinstance(payload, dict):
                return False, None, "Error en verificación: token malformado"

            if 'exp' in payload:
                exp_val = payload['exp']
                if isinstance(exp_val, bool) or not isinstance(exp_val, (int, float)):
                    return False, None, "Error en verificación: token malformado"
                if time.time() > exp_val:
                    return False, None, "Token expirado"

            return True, payload, "Token válido"
        except (ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeDecodeError):
            return False, None, "Error en verificación: token malformado"

    @staticmethod
    def check_permission(user_roles: List[str], required_permission: str, role_permissions_map: Dict[str, List[str]]) -> bool:
        """
        Sistema de Control de Acceso Basado en Roles (RBAC) defensivo.
        """
        for role in user_roles:
            allowed_permissions = role_permissions_map.get(role, [])
            if required_permission in allowed_permissions or "*" in allowed_permissions:
                return True
        return False
