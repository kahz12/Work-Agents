import os
import re
from typing import Any, Dict, List, Optional, Tuple


class ConfigManager:
    """
    Módulo para carga segura de configuración y detección defensiva de
    secretos o credenciales incrustadas (hardcoded) en código o configuraciones.
    """

    # Nombres de clave que sugieren un secreto. \w* al final para que
    # 'aws_secret_access_key' entre por 'secret'. Para 'auth' exigimos fin de
    # palabra o sufijo de credencial para no marcar 'AUTHENTIC' o 'AUTHOR'.
    _SECRET_KEY_NAMES = (
        r'(?:api[_-]?key|secret|password|passwd|passphrase|token'
        r'|auth(?:[_-]?(?:token|key|secret|code|header|pw|pass)\w*)?(?![A-Za-z0-9])'
        r'|credential|access[_-]?key|client[_-]?secret|private[_-]?key)\w*'
    )

    # 'password_field_name' nombra un campo; no es donde vive un secreto.
    _NOMBRA_UN_CAMPO_RE = re.compile(
        r'(?i)_(?:name|names|field|fields|label|column|header|key_name|param|attr)$'
    )

    # Expresión de descartes para valores que corresponden a plantillas de configuración,
    # referencias a variables de entorno o rellenos ilustrativos de documentación.
    _PLACEHOLDER_RE = re.compile(
        r"^(?:"
        r"\s*"                                       # Cadena vacía o compuesta únicamente por espacios en blanco.
        r"|[xX*.\-_]+"                               # Rellenos repetitivos usados para ocultar ejemplos (xxxx, ****, ----).
        r"|<[^>]*>"                                  # Etiquetas delimitadoras de sustitución manual (<tu-password>).
        r"|\{\{?[^}]*\}?\}"                          # Marcadores de interpolación de plantillas ({{var}}, {var}).
        r"|%[sdrf]"                                  # Especificadores de formato posicional heredados estilo printf (%s).
        r"|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"           # Referencias simbólicas a variables de entorno ($VAR, ${VAR}).
        r"|(?:tu|your|my|the)[-_ ].*"                # Fórmulas posesivas habituales en archivos de ejemplo (your-secret-here).
        r"|.*(?:aqui|here|placeholder|example|ejemplo|changeme|change[-_]me"
        r"|replace[-_]me|todo|tbd|dummy|sample|fake|redacted).*"
        r"|(?:none|null|nil|false|true|test|demo)"
        r"|.{0,7}"                                   # Cadenas menores a ocho caracteres carecen de longitud mínima útil como secreto.
        r")$",
        re.IGNORECASE,
    )

    SECRET_PATTERNS = [
        # --- Proveedores concretos: su prefijo propio hace que casi nunca se confundan con otra cosa ---
        (r'\bAKIA[0-9A-Z]{16}\b', "Clave de acceso AWS (AKIA)"),
        (r'\bASIA[0-9A-Z]{16}\b', "Clave de acceso temporal AWS (ASIA)"),
        (r'(?i)aws[\w-]*(?:secret|private)[\w-]*\s*[:=]\s*["\'][A-Za-z0-9/+=]{40}["\']',
         "Clave secreta de AWS"),
        (r'\bgh[pousr]_[A-Za-z0-9]{36,}\b', "Token de GitHub"),
        (r'\bgithub_pat_[A-Za-z0-9_]{22,}\b', "Token de GitHub (fine-grained)"),
        (r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b', "Token de Slack"),
        (r'hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}', "Webhook de Slack"),
        (r'\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b', "Clave de API de Stripe"),
        (r'\bAIza[0-9A-Za-z_-]{35}\b', "Clave de API de Google"),
        (r'\bsk-ant-[A-Za-z0-9_-]{20,}\b', "Clave de API de Anthropic"),
        (r'\bsk-(?!ant-)[A-Za-z0-9_-]{20,}\b', "Clave de API de OpenAI"),
        (r'\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b', "Clave de API de SendGrid"),
        (r'\bnpm_[A-Za-z0-9]{36}\b', "Token de npm"),
        (r'\bpypi-[A-Za-z0-9_-]{32,}\b', "Token de PyPI"),
        (r'\bglpat-[A-Za-z0-9_-]{20,}\b', "Token de GitLab"),

        # --- Firmas estructurales inequívocas: su sintaxis delata el secreto sin depender
        # del nombre de variable ni pasar por el filtro heurístico de descartes ---
        (r'-----BEGIN\s+(?:[A-Z]+\s+)?PRIVATE KEY-----', "Clave privada incrustada (PEM)"),
        (r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b', "JSON Web Token (JWT)"),
        (r'([a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27})', "Posible token tipo Discord"),
        (r'(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|ftp)://[^:@/\s]+:[^@/\s]+@',
         "Credencial dentro de una URL de conexion"),
        (r'(?i)(?:proxy-)?authorization\s*["\']?\s*[:=]\s*["\']\s*(?:basic|bearer)\s+[A-Za-z0-9._~+/=-]{16,}',
         "Credencial en cabecera Authorization"),

        # --- Genéricos por nombre de clave: se separan claves con comillas dobles,
        # simples y sin comillas para evitar saltos entre comillas en llamadas UI
        # como Label("Password:", classes="field-label") ---
        (r'(?i)"([A-Za-z0-9_-]*' + _SECRET_KEY_NAMES + r')"\s*:\s*["\']([^"\'\r\n]+)["\']',
         "Posible secreto incrustado"),
        (r"(?i)'([A-Za-z0-9_-]*" + _SECRET_KEY_NAMES + r")'\s*:\s*[\"']([^\"'\r\n]+)[\"']",
         "Posible secreto incrustado"),
        (r'(?i)(?:^|(?<=[\s,({\[;.]))([A-Za-z0-9_-]*' + _SECRET_KEY_NAMES + r')(?:\s*:\s+|\s*=\s*)["\']([^"\'\r\n]+)["\']',
         "Posible secreto incrustado"),
    ]

    # El filtro de descartes y valores de prueba solo aplica sobre los patrones genéricos
    # al final de la tupla: los de proveedor específico ya son inequívocos por su prefijo.
    _GENERIC_PATTERN_START = len(SECRET_PATTERNS) - 3
    _COMPILED_SECRET_PATTERNS = [(re.compile(pat), desc) for pat, desc in SECRET_PATTERNS]

    _PROTECTED_ENV_KEYS = {
        "PATH", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
        "LD_PRELOAD", "LD_LIBRARY_PATH", "IFS",
    }
    _VALID_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

    @staticmethod
    def parse_env_file(filepath: str) -> Dict[str, str]:
        """
        Lee y valida variables desde un archivo .env sin modificar os.environ.
        """
        env_vars: Dict[str, str] = {}
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.read().splitlines()
        except (FileNotFoundError, IsADirectoryError, OSError):
            return {}

        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            if not ConfigManager._VALID_ENV_KEY_RE.match(key):
                continue
            if key.upper() in ConfigManager._PROTECTED_ENV_KEYS:
                continue
            env_vars[key] = val.strip().strip('"').strip("'")
        return env_vars

    @staticmethod
    def load_env_file(filepath: str, *, override: bool = False) -> Dict[str, str]:
        """
        Lee un archivo .env y exporta sus variables a os.environ. Las que ya existen en el
        entorno se respetan salvo con override=True. Devuelve todas las leídas del archivo.
        """
        env_vars = ConfigManager.parse_env_file(filepath)
        for key, val in env_vars.items():
            if override or key not in os.environ:
                os.environ[key] = val
        return env_vars

    @staticmethod
    def audit_config_dict(config: Dict[str, Any]) -> List[Tuple[str, str, str]]:
        """
        Audita un diccionario de configuración buscando valores inseguros o claves débiles.
        Retorna una lista de tuplas: (Clave, Nivel_Riesgo, Recomendación).
        """
        findings = []

        for key, value in config.items():
            key_lower = str(key).lower()
            str_val = str(value)

            # Evaluar claves con semántica de credencial cuyo valor sea trivial, predeterminado o excesivamente corto.
            # Un valor vacío significa "sin definir" (lo normal en una plantilla), no una clave corta.
            if any(k in key_lower for k in ['secret', 'key', 'token', 'password']) and str_val.strip():
                if str_val.lower() in ['admin', '123456', 'secret', 'changeme', 'default', 'root']:
                    findings.append((key, "ALTO", f"El valor de '{key}' es inseguro o predeterminado ('{str_val}'). Usa variables de entorno."))
                elif len(str_val) < 16:
                    findings.append((key, "MEDIO", f"La clave o secreto '{key}' es corta ({len(str_val)} caracteres). Se recomiendan al menos 32 caracteres estocásticos."))

            # Alertar indicadores de depuración o pruebas habilitados en configuraciones productivas.
            if key_lower in ['debug', 'testing'] and str_val.lower() in ['true', '1', 'yes']:
                findings.append((key, "ALTO", f"La opción '{key}' está activada. En producción debe estar desactivada."))

        return findings

    @staticmethod
    def _redact_line(line: str, match: re.Match, is_generic: bool) -> str:
        """Reemplaza el valor secreto detectado por una versión redactada antes de truncar."""
        raw = line.rstrip("\r\n")
        if is_generic and match.lastindex and match.lastindex >= 2:
            val = match.group(2)
            redacted = (val[:3] + "***REDACTED***") if len(val) > 3 else "***REDACTED***"
            masked = raw[:match.start(2)] + redacted + raw[match.end(2):]
        else:
            matched_text = match.group(0)
            if "-----BEGIN" in matched_text:
                masked = raw
            elif "://" in matched_text and "@" in matched_text:
                scheme_user, _, _ = matched_text.rpartition(":")
                redacted = f"{scheme_user}:***REDACTED***@"
                masked = raw[:match.start(0)] + redacted + raw[match.end(0):]
            else:
                prefix = matched_text[:3] if len(matched_text) > 6 else ""
                redacted = f"{prefix}***REDACTED***"
                masked = raw[:match.start(0)] + redacted + raw[match.end(0):]
        stripped = masked.strip()
        return stripped[:60] + "..." if len(stripped) > 60 else stripped

    @staticmethod
    def _es_archivo_test(filepath: str) -> bool:
        """Detecta archivos de prueba por su nombre base (no por carpetas padre)."""
        name = filepath.replace("\\", "/").rsplit("/", 1)[-1].lower()
        return name == "conftest.py" or (
            name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))
        )

    @staticmethod
    def _match_secret_line(line: str, *, is_test_file: bool) -> Optional[Tuple[str, str]]:
        """Evalúa una línea buscando secretos; los de prefijo inequívoco también cuentan en comentarios."""
        is_comment = ConfigManager._es_comentario(line)
        for pos, (pattern, desc) in enumerate(ConfigManager._COMPILED_SECRET_PATTERNS):
            match = pattern.search(line)
            if not match:
                continue
            is_generic = pos >= ConfigManager._GENERIC_PATTERN_START
            if is_generic:
                if is_comment or is_test_file:
                    continue
                clave, valor = match.group(1), match.group(2)
                if (
                    clave.lower() == valor.strip().lower()
                    or ConfigManager._PLACEHOLDER_RE.match(valor)
                    or ConfigManager._NOMBRA_UN_CAMPO_RE.search(clave)
                ):
                    continue
            return desc, ConfigManager._redact_line(line, match, is_generic)
        return None

    @staticmethod
    def scan_file_for_secrets(filepath: str) -> List[Tuple[int, str, str]]:
        """
        Escanea defensivamente un archivo en busca de patrones de claves incrustadas.
        Retorna lista de (Número_Linea, Patrón_Detectado, Fragmento).
        """
        findings: List[Tuple[int, str, str]] = []
        is_test_file = ConfigManager._es_archivo_test(filepath)
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for idx, line in enumerate(f, 1):
                    hit = ConfigManager._match_secret_line(line, is_test_file=is_test_file)
                    if hit is not None:
                        desc, masked_line = hit
                        findings.append((idx, desc, masked_line))
        except FileNotFoundError:
            return [(0, "ERROR de lectura", f"El archivo '{filepath}' no existe.")]
        except OSError as exc:
            # Un archivo ilegible por permisos o codificación no debe devolver una lista vacía,
            # porque quien llama lo interpretaría como un archivo revisado y sin secretos.
            findings.append((0, "ERROR de lectura", str(exc)))

        return findings

    # Prefijos de comentario habituales en los formatos de configuración y código fuente
    # soportados (.py, .sh, .yml, .ini, .sql, .js, .c). El marcador '--' exige al menos un
    # espacio posterior para no confundir encabezados PEM ('-----BEGIN ... PRIVATE KEY-----').
    _COMENTARIO_RE = re.compile(r'^\s*(?:#|//|--\s|;|/\*|\*\s)')

    @staticmethod
    def _es_comentario(line: str) -> bool:
        return bool(ConfigManager._COMENTARIO_RE.match(line))
