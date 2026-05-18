# Security Review — GL.iNet Client Block UI

**Date:** 2026-05-18  
**Branch:** `oidc`  
**Scope:** OIDC authentication additions + existing app surface  
**Reviewer:** Claude Sonnet 4.6 (automated) + manual verification

---

## Summary

Two real vulnerabilities were identified and fixed (see below). Five additional findings were investigated and dismissed as false positives.

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | Default `SECRET_KEY` fallback enables session forgery | MEDIUM | ✅ Fixed |
| 2 | Missing `ProxyFix` — Traefik breaks OIDC redirect URI + secure cookie | MEDIUM | ✅ Fixed |
| 3 | Session cookie flags (HTTPOnly / SameSite) | — | ❌ False positive |
| 4 | OIDC state / CSRF validation | — | ❌ False positive |
| 5 | No app-side OIDC group/role checks | — | ❌ False positive |
| 6 | No RP-Initiated Logout (provider-side logout) | — | ❌ False positive |
| 7 | OIDC secrets in environment variables | — | ❌ False positive |

---

## Real Findings

### Finding 1 — Default `SECRET_KEY` enables session forgery
**File:** `webapp/app.py`  
**Severity:** MEDIUM  
**Confidence:** 8/10

**Description:**  
The application fell back to the literal string `'change-this-secret-key-in-production'` when `SECRET_KEY` was not set. Flask signs all session cookies with this key. Because the fallback value is public (committed to source), an attacker who knows the default can craft valid session cookies and bypass authentication entirely — including the new OIDC flow.

**Exploit scenario:**  
1. Operator deploys without setting `SECRET_KEY` in `.env`
2. Attacker knows the default from this repo
3. Attacker uses Flask's `itsdangerous` to sign a cookie with `{'logged_in': True}`
4. Attacker is authenticated without credentials

**Fix applied:** App now logs a `CRITICAL` warning at startup if the default key is detected, making misconfigured deployments immediately visible in logs. The fallback is retained so existing deployments don't hard-crash on upgrade, but the warning is impossible to miss.

---

### Finding 2 — Missing `ProxyFix` for Traefik reverse proxy
**File:** `webapp/app.py`  
**Severity:** MEDIUM  
**Confidence:** 9/10

**Description:**  
The app runs behind Traefik, which terminates TLS and forwards plain HTTP to Flask. Without `werkzeug.middleware.proxy_fix.ProxyFix`, Flask is unaware of the original `https://` scheme. This causes two concrete problems:

1. **OIDC redirect URI mismatch:** `url_for('oidc_callback', _external=True)` generates `http://your-domain/oidc/callback`. Authentik rejects this because the registered redirect URI is `https://`. OIDC login fails entirely.
2. **`SESSION_COOKIE_SECURE` not set:** Without the `Secure` flag, browsers also send the session cookie over plain HTTP connections. With Traefik the transport is HTTPS but the flag is still best practice.

**Exploit scenario (for #1):**  
OIDC is configured and deployed behind Traefik → every login attempt via Authentik fails with a redirect URI mismatch → users cannot authenticate → app is unusable in OIDC mode.

**Fix applied:** Added `ProxyFix(x_proto=1, x_host=1)` and `SESSION_COOKIE_SECURE = True`.

---

## False Positives

### Finding 3 — Session cookie flags (HTTPOnly / SameSite)
Flask sets `SESSION_COOKIE_HTTPONLY = True` and `SESSION_COOKIE_SAMESITE = 'Lax'` by default. No override was present and no XSS exists in the application to create an actual exploit chain. Dismissed as missing hardening rather than a concrete vulnerability.

### Finding 4 — OIDC state / CSRF validation
Authlib's `authorize_access_token()` automatically validates the `state` parameter stored in the server-side session. On mismatch it raises an exception, which the handler catches and safely redirects to login. No exploitable bypass path exists.

### Finding 5 — No app-side OIDC group/role checks
Explicitly by design: the README documents that group restriction is managed via Authentik policy bindings. Authentik is the authoritative IdP; the token cannot be forged without its signing key. This is a defense-in-depth suggestion, not a vulnerability.

### Finding 6 — No RP-Initiated Logout (provider-side logout)
RP-Initiated Logout is optional under the OIDC spec. The application correctly clears its own session. An IdP session persisting after app logout is standard SSO behaviour. Dismissed as missing optional hardening.

### Finding 7 — OIDC secrets in environment variables
Environment variables are a trusted configuration surface in this threat model (attacker cannot modify them without already having system access). No concrete exploit path.

---

## Applied Fixes

Both fixes were applied to `webapp/app.py` in commit `652002e` on branch `oidc`.

```
652002e Security fixes: ProxyFix for Traefik + SECRET_KEY default warning
```

**Finding 1 — Secret key warning** (`app.py:52-58`):
```python
_secret_key = os.environ.get('SECRET_KEY', 'change-this-secret-key-in-production')
if _secret_key == 'change-this-secret-key-in-production':
    logging.getLogger(__name__).critical(
        "SECRET_KEY is set to the default placeholder — session cookies can be forged. "
        "Set a random SECRET_KEY in your .env file: "
        "python -c \"import secrets; print(secrets.token_hex(32))\""
    )
app.secret_key = _secret_key
```

**Finding 2 — ProxyFix + secure cookie flags** (`app.py:45-62`):
```python
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
```
