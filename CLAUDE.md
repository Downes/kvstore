# kvstore (/srv/apps/kvstore)

## Overview
Flask JSON API — per-user encrypted credential store for CList.
No HTML, no sessions, no server-side knowledge of encryption keys.

## Container
- Name: kvstore  Port: 5000 (internal only)
- Domain: kvstore.mooc.ca — LIVE, HTTPS via Caddy

## Network
- web (external) — shared with other apps

## CORS
Handled entirely in the Caddyfile (NOT flask-cors). flask-cors fails to inject headers
into Flask's automatic OPTIONS responses for blueprint routes. See /srv/proxy/Caddyfile
and /srv/shared/setup-notes.md for the standard pattern.

## Auth design (v0.2 — PBKDF2 zero-knowledge)
Client derives two keys from password + username:
- encKey  = PBKDF2(password, username+"_enc",  100k iters) — stays in browser, never sent
- authHash = PBKDF2(password, username+"_auth", 100k iters) — sent to server on login/register

Server stores bcrypt(authHash). Server NEVER sees the raw password or encKey.
On login: server issues long-lived opaque token in format `username:hex32`.
Token stored hashed (SHA-256) in per-user SQLite DB, valid for 365 days.

## KV values
All values are AES-GCM encrypted client-side with encKey before being sent.
Server stores and returns opaque ciphertext blobs.

## Database
Per-user SQLite files in /data/{username}.db (Docker volume kvstore_data).
Tables: users (id, username, auth_hash, api_token_hash, token_expires), key_values (id, key, value).

## Language & Runtime
Python 3.11 / Flask / Gunicorn (2 workers).

## Environment variables (.env)
- SECRET_KEY  — Flask secret key (required, app refuses to start without it)
- CORS_ORIGIN — allowed CORS origin (default: https://clist.mooc.ca)
- DATA_DIR    — path to SQLite DB directory (default: /data)

## Rate limiting
- /auth/login: 10/min (flask-limiter, in-memory)
- /auth/register: 5/hour (flask-limiter, in-memory)

## History
- v0.1: Original Flask app with HTML UI, JWT tokens, server-stored passphrase (insecure)
- v0.2: Rewritten as pure JSON API with PBKDF2 zero-knowledge auth and opaque long-lived tokens

## Still To Do
- Delete account endpoint + UI
- Multiple kvstore selection (user-configurable flaskSiteUrl in CList)
- Credential migration between kvstore instances
- Add proxyp token auth (token fetched from kvstore after login)
- Extract discussions endpoint to its own app (/srv/apps/discussions/)
