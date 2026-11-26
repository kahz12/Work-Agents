# Agente de Seguridad Defensiva

Controles defensivos de entrada, autenticación, CSRF, rate limiting, RBAC y auditoría de configuración.

## Estructura

- `input_sanitizer.py` — XSS (`html.escape`), path traversal, whitelist, enteros y **schema JSON** (plano/anidado, `reject_extra_keys`; bool ≠ int). Delega en `common.schema` cuando está disponible.
- `auth_manager.py` — Hashing Argon2 / Bcrypt / PBKDF2, **CSRF** (soporta `session_id` con `:` vía `rsplit`), tokens HMAC, RBAC y `RateLimiter` por ventana deslizante.
- `config_manager.py` — Carga de `.env` y auditoría de secretos / flags inseguros (`DEBUG`, `SECRET_KEY`, etc.).
- `main.py` — Demo ejecutable.

## Uso

```bash
agentes demo defensive               # demo con datos de ejemplo
python -m agentes.defensive.main     # lo mismo, sin pasar por el CLI
agentes secrets .
agentes password check
```

