# Defensive Security Agent

Defensive controls for input handling, authentication, CSRF, rate limiting, RBAC and configuration auditing.

## Layout

- `input_sanitizer.py` — XSS (`html.escape`), path traversal, allow-lists, integers and **JSON schemas** (flat or nested, `reject_extra_keys`; bool is never accepted as int). Schema validation is shared with QA through `common.schema`.
- `auth_manager.py` — Argon2 / bcrypt / PBKDF2 hashing, **CSRF** tokens (session IDs containing `:` are supported because verification uses `rsplit`), HMAC-signed tokens, RBAC and a sliding-window `RateLimiter`.
- `password_policy.py` — Strength checks beyond character classes: common base words, keyboard sequences, repetitions, years, and Have I Been Pwned lookups with k-anonymity.
- `config_manager.py` — `.env` loading plus detection of secrets and insecure flags (`DEBUG`, `SECRET_KEY`, etc.).
- `main.py` — Runnable demo.

## Usage

```bash
agentes demo defensive               # demo on sample data
python -m agentes.defensive.main     # the same, without going through the CLI
agentes secrets .
agentes password check
```
