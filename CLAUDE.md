# kvstore (/srv/apps/kvstore)

## Overview
Flask JSON API — per-user encrypted credential store and identity provider.
No HTML, no sessions, no server-side knowledge of encryption keys.
Acts as a federated identity provider: issues signed JWTs that any remote app
can verify locally without calling back to kvstore.

## Container
- Name: kvstore  Port: 5000 (internal only)
- Domain: kvstore.mooc.ca — LIVE, HTTPS via Caddy

## Network
- web (external) — shared with other apps

## CORS
Handled entirely in the Caddyfile (NOT flask-cors). flask-cors fails to inject headers
into Flask's automatic OPTIONS responses for blueprint routes. See /srv/proxy/Caddyfile
and /srv/shared/setup-notes.md for the standard pattern.

## Auth design (v0.3 — JWT federation)
See AUTH.md for the full authentication design and remote integration guide.

Client derives two keys from password + username:
- encKey   = PBKDF2(password, username+"_enc",  100k iters) — stays in browser, never sent
- authHash = PBKDF2(password, username+"_auth", 100k iters) — sent to server on login/register

Server stores bcrypt(authHash). Server NEVER sees the raw password or encKey.
On login: server issues a signed **ES256 JWT** (30-day expiry).
The JWT `iss` claim is set to `ISSUER_URL` (e.g. `https://kvstore.mooc.ca`).
Remote apps verify the JWT locally by fetching `<iss>/.well-known/jwks.json`.

Opaque tokens (`username:hex32`, SHA-256 hashed in DB) are still accepted for
backwards compatibility with existing CList/proxyp sessions but are no longer issued.

## JWKS endpoint
`GET /.well-known/jwks.json` — public, no auth required.
Returns the EC P-256 public key. Private key persisted to `/data/jwk_private.pem`.

## KV values
All values are AES-GCM encrypted client-side with encKey before being sent.
Server stores and returns opaque ciphertext blobs.

## Database
Per-user SQLite files in /data/{username}.db (Docker volume kvstore_data).
Tables: users (id, username, auth_hash, api_token_hash, token_expires), key_values (id, key, value).

## Language & Runtime
Python 3.11 / Flask / Gunicorn (1 worker).

## Environment variables (.env)
- SECRET_KEY  — Flask secret key (required, app refuses to start without it)
- CORS_ORIGIN — comma-separated allowed CORS origins (default: https://clist.mooc.ca)
- DATA_DIR    — path to SQLite DB and key directory (default: /data)
- ISSUER_URL  — public URL of this kvstore instance, embedded as JWT `iss` claim
                (default: https://kvstore.mooc.ca)

## Rate limiting
- /auth/login: 10/min (flask-limiter, in-memory)
- /auth/register: 5/hour (flask-limiter, in-memory)

## History
- v0.1: Original Flask app with HTML UI, JWT tokens, server-stored passphrase (insecure)
- v0.2: Rewritten as pure JSON API with PBKDF2 zero-knowledge auth and opaque long-lived tokens
- v0.3: JWT federation — login issues ES256 JWTs; remote apps verify via JWKS endpoint

## Still To Do
- Delete account endpoint + UI
- Multiple kvstore selection (user-configurable flaskSiteUrl in CList)
- Credential migration between kvstore instances
- App-scoped KV access (JWT `aud` claim or key namespacing — see /srv/TODO.md)
