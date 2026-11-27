import os
import re
from typing import Any, Dict, List, Optional, Tuple


class ConfigManager:
    """
    Safe configuration loading, plus detection of secrets and credentials hardcoded in source
    code or configuration files.
    """

    # Key names that suggest a secret. The trailing \w* lets 'aws_secret_access_key' match
    # through 'secret'. 'auth' must end the word or carry a credential suffix, so that
    # 'AUTHENTIC' or 'AUTHOR' are not flagged.
    _SECRET_KEY_NAMES = (
        r'(?:api[_-]?key|secret|password|passwd|passphrase|token'
        r'|auth(?:[_-]?(?:token|key|secret|code|header|pw|pass)\w*)?(?![A-Za-z0-9])'
        r'|credential|access[_-]?key|client[_-]?secret|private[_-]?key)\w*'
    )

    # 'password_field_name' holds the name of a field, not a secret.
    _NAMES_A_FIELD_RE = re.compile(
        r'(?i)_(?:name|names|field|fields|label|column|header|key_name|param|attr)$'
    )

    # Values that are not real secrets: configuration templates, environment variable
    # references and illustrative placeholders from documentation. Spanish placeholders
    # (tu-, aqui, ejemplo) are listed because the tool is also used on Spanish codebases.
    _PLACEHOLDER_RE = re.compile(
        r"^(?:"
        r"\s*"                                       # Empty or whitespace only.
        r"|[xX*.\-_]+"                               # Masking filler used in examples (xxxx, ****, ----).
        r"|<[^>]*>"                                  # Manual substitution markers (<your-password>).
        r"|\{\{?[^}]*\}?\}"                          # Template interpolation ({{var}}, {var}).
        r"|%[sdrf]"                                  # printf-style format specifiers (%s).
        r"|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"           # Environment variable references ($VAR, ${VAR}).
        r"|(?:tu|your|my|the)[-_ ].*"                # Possessive phrasing typical of sample files (your-secret-here).
        r"|.*(?:aqui|here|placeholder|example|ejemplo|changeme|change[-_]me"
        r"|replace[-_]me|todo|tbd|dummy|sample|fake|redacted).*"
        r"|(?:none|null|nil|false|true|test|demo)"
        r"|.{0,7}"                                   # Shorter than eight characters: too short to be a real secret.
        r")$",
        re.IGNORECASE,
    )

    SECRET_PATTERNS = [
        # --- Provider-specific tokens: their distinctive prefix makes false positives rare ---
        (r'\bAKIA[0-9A-Z]{16}\b', "AWS access key (AKIA)"),
        (r'\bASIA[0-9A-Z]{16}\b', "AWS temporary access key (ASIA)"),
        (r'(?i)aws[\w-]*(?:secret|private)[\w-]*\s*[:=]\s*["\'][A-Za-z0-9/+=]{40}["\']',
         "AWS secret key"),
        (r'\bgh[pousr]_[A-Za-z0-9]{36,}\b', "GitHub token"),
        (r'\bgithub_pat_[A-Za-z0-9_]{22,}\b', "GitHub token (fine-grained)"),
        (r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b', "Slack token"),
        (r'hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}', "Slack webhook"),
        (r'\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b', "Stripe API key"),
        (r'\bAIza[0-9A-Za-z_-]{35}\b', "Google API key"),
        (r'\bsk-ant-[A-Za-z0-9_-]{20,}\b', "Anthropic API key"),
        (r'\bsk-(?!ant-)[A-Za-z0-9_-]{20,}\b', "OpenAI API key"),
        (r'\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b', "SendGrid API key"),
        (r'\bnpm_[A-Za-z0-9]{36}\b', "npm token"),
        (r'\bpypi-[A-Za-z0-9_-]{32,}\b', "PyPI token"),
        (r'\bglpat-[A-Za-z0-9_-]{20,}\b', "GitLab token"),

        # --- Unambiguous structural signatures: the syntax alone gives the secret away, so
        # they do not depend on the variable name and skip the placeholder filter ---
        (r'-----BEGIN\s+(?:[A-Z]+\s+)?PRIVATE KEY-----', "Embedded private key (PEM)"),
        (r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b', "JSON Web Token (JWT)"),
        (r'([a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27})', "Possible Discord-style token"),
        (r'(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|ftp)://[^:@/\s]+:[^@/\s]+@',
         "Credential inside a connection URL"),
        (r'(?i)(?:proxy-)?authorization\s*["\']?\s*[:=]\s*["\']\s*(?:basic|bearer)\s+[A-Za-z0-9._~+/=-]{16,}',
         "Credential in an Authorization header"),

        # --- Generic, keyed by name. Double-quoted, single-quoted and bare keys use separate
        # patterns so a match cannot jump across quotes in UI calls such as
        # Label("Password:", classes="field-label") ---
        (r'(?i)"([A-Za-z0-9_-]*' + _SECRET_KEY_NAMES + r')"\s*:\s*["\']([^"\'\r\n]+)["\']',
         "Possible embedded secret"),
        (r"(?i)'([A-Za-z0-9_-]*" + _SECRET_KEY_NAMES + r")'\s*:\s*[\"']([^\"'\r\n]+)[\"']",
         "Possible embedded secret"),
        (r'(?i)(?:^|(?<=[\s,({\[;.]))([A-Za-z0-9_-]*' + _SECRET_KEY_NAMES + r')(?:\s*:\s+|\s*=\s*)["\']([^"\'\r\n]+)["\']',
         "Possible embedded secret"),
    ]

    # The placeholder filter only applies to the generic patterns at the end of the list;
    # provider-specific patterns are already unambiguous thanks to their prefix.
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
        Read and validate the variables in a .env file without touching os.environ.
        Invalid names and variables that could hijack the interpreter (PATH, LD_PRELOAD...)
        are skipped.
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
        Read a .env file and export its variables to os.environ. Variables already present in
        the environment are left alone unless override=True. Returns everything read from the
        file.
        """
        env_vars = ConfigManager.parse_env_file(filepath)
        for key, val in env_vars.items():
            if override or key not in os.environ:
                os.environ[key] = val
        return env_vars

    @staticmethod
    def audit_config_dict(config: Dict[str, Any]) -> List[Tuple[str, str, str]]:
        """
        Look for insecure values and weak keys in a configuration mapping.
        Returns a list of (key, risk level, recommendation) tuples.
        """
        findings = []

        for key, value in config.items():
            key_lower = str(key).lower()
            str_val = str(value)

            # Credential-like keys whose value is trivial, a well-known default, or too short.
            # An empty value means "not set" (normal in a template), not a short key.
            if any(k in key_lower for k in ['secret', 'key', 'token', 'password']) and str_val.strip():
                if str_val.lower() in ['admin', '123456', 'secret', 'changeme', 'default', 'root']:
                    findings.append((key, "HIGH", f"The value of '{key}' is insecure or a known default ('{str_val}'). Use environment variables."))
                elif len(str_val) < 16:
                    findings.append((key, "MEDIUM", f"The key or secret '{key}' is short ({len(str_val)} characters). Use at least 32 random characters."))

            # Debug or testing switches turned on, which must be off in production.
            if key_lower in ['debug', 'testing'] and str_val.lower() in ['true', '1', 'yes']:
                findings.append((key, "HIGH", f"The '{key}' option is enabled. It must be disabled in production."))

        return findings

    @staticmethod
    def _redact_line(line: str, match: re.Match, is_generic: bool) -> str:
        """Mask the detected secret in the line, then truncate the line for display."""
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
    def _is_test_file(filepath: str) -> bool:
        """Recognise test files by their base name only; parent directories do not count."""
        name = filepath.replace("\\", "/").rsplit("/", 1)[-1].lower()
        return name == "conftest.py" or (
            name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))
        )

    @staticmethod
    def _match_secret_line(line: str, *, is_test_file: bool) -> Optional[Tuple[str, str]]:
        """
        Look for a secret in one line and return (description, masked line), or None.
        Provider-specific matches count even inside comments; generic key-name matches are
        ignored in comments and test files, where sample credentials are expected.
        """
        is_comment = ConfigManager._is_comment(line)
        for pos, (pattern, desc) in enumerate(ConfigManager._COMPILED_SECRET_PATTERNS):
            match = pattern.search(line)
            if not match:
                continue
            is_generic = pos >= ConfigManager._GENERIC_PATTERN_START
            if is_generic:
                if is_comment or is_test_file:
                    continue
                key, value = match.group(1), match.group(2)
                if (
                    key.lower() == value.strip().lower()
                    or ConfigManager._PLACEHOLDER_RE.match(value)
                    or ConfigManager._NAMES_A_FIELD_RE.search(key)
                ):
                    continue
            return desc, ConfigManager._redact_line(line, match, is_generic)
        return None

    @staticmethod
    def scan_file_for_secrets(filepath: str) -> List[Tuple[int, str, str]]:
        """
        Scan a file for embedded keys and credentials.
        Returns a list of (line number, detected pattern, masked snippet). Line 0 marks a file
        that could not be read.
        """
        findings: List[Tuple[int, str, str]] = []
        is_test_file = ConfigManager._is_test_file(filepath)
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for idx, line in enumerate(f, 1):
                    hit = ConfigManager._match_secret_line(line, is_test_file=is_test_file)
                    if hit is not None:
                        desc, masked_line = hit
                        findings.append((idx, desc, masked_line))
        except FileNotFoundError:
            return [(0, "Read error", f"File '{filepath}' does not exist.")]
        except OSError as exc:
            # A file unreadable because of permissions or encoding must not produce an empty
            # list: the caller would take that as "scanned and clean".
            findings.append((0, "Read error", str(exc)))

        return findings

    # Comment prefixes of the supported source and configuration formats (.py, .sh, .yml,
    # .ini, .sql, .js, .c). '--' must be followed by whitespace so that PEM armour lines
    # ('-----BEGIN ... PRIVATE KEY-----') are not mistaken for comments.
    _COMMENT_RE = re.compile(r'^\s*(?:#|//|--\s|;|/\*|\*\s)')

    @staticmethod
    def _is_comment(line: str) -> bool:
        return bool(ConfigManager._COMMENT_RE.match(line))
