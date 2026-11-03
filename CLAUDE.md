# kvstore (/srv/apps/kvstore)

## Overview
Flask JSON API — per-user encrypted credential store and identity provider.
No HTML, no sessions, no server-side knowledge of encryption keys.
Acts as a federated identity provider: issues signed JWTs that any remote app
can verify locally without calling back to kvstore.

## Container
- Name: kvstore  Port: 5000 (internal only)
- Domain: kvstore.mooc.ca — LIVE, HTTPS via Caddy

## IMPORTANT: Two instances share this code
A second instance runs from `/srv/apps/kvstore2/` (domain: kvstore.downes.ca).
Its `docker-compose.yml` builds from `../kvstore` — this directory.
**Any time you rebuild or update kvstore, you must also rebuild kvstore2:**
```bash
cd /srv/apps/kvstore  && docker compose up -d --build
cd /srv/apps/kvstore2 && docker compose up -d --build
```
**Exception: the `defaults.js` write-back feature (below) is kvstore-only.** It activates
purely because `CLIST_STATIC_DIR` is set in kvstore's `.env` and unset in kvstore2's — no
code branches on which instance it is. kvstore2 is an alternate backend for the same
clist.mooc.ca install kvstore already writes to, not a second CList install of its own.

## Network
- web (external) — shared with other apps

## Volumes
- `kvstore_data` (named volume) — per-user SQLite DBs and `_settings.db`, mounted at `/data`
- `/srv/www/clist.mooc.ca:/clist_static` (bind mount) — gives this container filesystem
  write access to CList's static directory, so it can rewrite `defaults.js` on disk
  (see "Admin settings" below). Covers the whole directory, not just `defaults.js`,
  because the atomic write (`os.replace()` of a temp file) requires the temp file and
  target to share a directory. kvstore2 does **not** have this mount.

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
Returns the EC P-256 public key, with a `kid` derived deterministically from
the public key itself (SHA-256 of x||y, truncated) — added 2026-10-23.
Required for `PyJWKClient`-style local JWKS verification: it filters out any
JWK lacking a `kid`, and matching a token to a key also requires the token's
own header to carry a `kid`, so `issue_jwt()` sets the same value in the JWT
header. Only one key exists today — see /srv/TODO.md "kvstore JWT
signing-key rotation" for what's needed to support rotation. Private key
persisted to `/data/jwk_private.pem`.

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
- ALLOWED_KVSTORE_URLS — comma-separated kvstore instances a `/users/<u>/did.html`
                profile page's Follow link is allowed to forward the visitor's
                token to via the `mykvstore` query param (default:
                https://kvstore.mooc.ca,https://kvstore.downes.ca). `mykvstore`
                is attacker-controllable input — `get_did_profile()` in routes.py
                zeroes it out if it's not in this list, since an unchecked value
                would let a crafted profile link exfiltrate a visitor's JWT to
                an arbitrary domain. See SECURITY.md's "Client-side token
                handling rules" section.
- ADMIN_USERNAMES — comma-separated usernames allowed to read/write `/admin/settings`
                (checked via `clist_server_admin.sqlite.is_admin`, same as pastebin/survey).
- CLIST_STATIC_DIR — filesystem path (inside the container) to the paired CList static
                install's directory, where `defaults.js` lives. Default: unset/empty,
                meaning this instance has no paired CList install and `_write_defaults_js()`
                in app.py is a no-op (e.g. kvstore2 — see "Two instances share this code").
                kvstore's value is `/clist_static`, backed by the bind mount in Volumes above.
- DEFAULT_LOCALRSS, DEFAULT_PASTEBIN, DEFAULT_SURVEY, DEFAULT_ANNOTATIONS, DEFAULT_COLLAB,
                DEFAULT_DISCUSSIONS — `.env`-sourced fallback values for the matching
                `DEFAULT_*` settings, used as the effective value before any admin override
                is saved (defaults match CList's own stock `defaults.js` values, e.g.
                https://localrss.downes.ca, https://pastebin.mooc.ca, etc.).

## Admin settings
Adopted the shared `clist-server-admin` pattern (pinned by commit SHA in
requirements.txt — see /srv/shared/clist-server-admin), same as pastebin/survey.
Settings live in their own small sqlite file, `/data/_settings.db` — kvstore's only
app-wide table; every other table here is per-user (see Database section above).

- `GET/PUT /admin/settings` — admin-only (Bearer token, username in `ADMIN_USERNAMES`).
  Fields: `ENABLED` (boolean — **display-only, not wired to a kill-switch**: unlike
  pastebin/survey, disabling kvstore would break login for every CList user, so this
  flag is kept only for App Settings panel consistency), plus one `url` field per remote
  service CList depends on: `DEFAULT_LOCALRSS`, `DEFAULT_PASTEBIN`, `DEFAULT_SURVEY`,
  `DEFAULT_ANNOTATIONS`, `DEFAULT_COLLAB`, `DEFAULT_DISCUSSIONS`.
- No `GET /public/settings` route — removed. Instead, every successful `PUT
  /admin/settings` triggers `_write_defaults_js()` (an `after_request` hook in app.py,
  since `register_admin_settings_routes` has no save-hook parameter), which regenerates
  `defaults.js` directly on disk in the paired CList install (via `CLIST_STATIC_DIR`,
  see Environment variables above and Volumes above). `_write_defaults_js()` also runs
  once on every container start, so the file stays in sync with the DB across restarts.
  CList reads `window.CList.defaults.*` from that file directly — no API call, no CORS
  concern, works even for `file://` local installs.
- Consumed by CList's `js/kvstore.js` (`ADMIN_SETTINGS_APPS`), which the "KVStore" entry
  (and five others, one per service) edits via the App Settings panel.
- See /srv/www/clist.mooc.ca/defaults.js and its CLAUDE.md for the CList side of this.

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
