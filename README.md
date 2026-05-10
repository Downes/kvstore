# kvstore — Your Keys. Your Data. Your Server.

kvstore is a lightweight, self-hosted identity and storage layer for web applications. It gives your users a single secure account they control — credentials, settings, tokens — without trusting any platform with their data.

**Zero-knowledge by design.** Your password never leaves your device. kvstore derives your encryption key locally using PBKDF2, so everything stored on the server is ciphertext the server can never read. Not us, not an attacker with a database dump.

**Federated authentication.** Log in once. kvstore issues a signed JWT that any participating app can verify independently — no callback required, no shared session infrastructure. Build a constellation of small apps that all trust the same identity without coupling them together.

**Decentralized identity built in.** Every kvstore account has a `did:web` document out of the box, so your identity is portable, verifiable, and yours — not locked to a platform.

**Runs anywhere Docker runs.** One container, one SQLite file per user, one environment variable for your secret key. No Postgres, no Redis, no managed cloud dependency. Back it up with `cp`.

---

*Self-host it. Fork it. Wire it into whatever you're building.*

---

## Overview

Encrypted credential store for [CList](https://github.com/Downes/CList) and similar client-side web applications.

kvstore lets a browser-based app store sensitive credentials (API keys, access tokens, passwords) on a server without the server ever seeing the encryption key or raw values. All cryptography happens in the browser.

## How it works

### Zero-knowledge design

When a user registers or logs in, the browser derives two keys from their password using PBKDF2 (100,000 iterations):

- **encKey** = PBKDF2(password, username + `"_enc"`) — stays in the browser, never sent to the server. Used to AES-GCM encrypt credential values before they leave the browser.
- **authHash** = PBKDF2(password, username + `"_auth"`) — sent to the server on login/register. The server stores `bcrypt(authHash)` and never sees the raw password.

Stored values are opaque ciphertext blobs. The server cannot decrypt them. Even if the database is compromised, credentials are safe as long as passwords are strong.

On successful login the server issues a signed **ES256 JWT** (30-day expiry). Legacy opaque tokens (`username:hex32`) are still accepted for backwards compatibility but are no longer issued.

### API endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/register` | — | Create account |
| POST | `/auth/login` | — | Authenticate, receive token |
| POST | `/auth/logout` | Bearer | Invalidate token |
| GET  | `/auth/verify` | Bearer | Validate token (used by proxyp) |
| PUT  | `/auth/did` | Bearer | Register a DID document |
| DELETE | `/auth/did` | Bearer | Remove a DID document |
| GET  | `/.well-known/jwks.json` | — | Public key for JWT verification |
| GET  | `/users/{username}/did.json` | — | Serve public DID document |
| GET  | `/get_kvs/` | Bearer | Retrieve all key-value pairs |
| POST | `/add_kv/` | Bearer | Add a new key-value pair |
| POST | `/update_kv/` | Bearer | Update an existing pair |
| POST | `/delete_kv/` | Bearer | Delete a pair |

Rate limiting is applied to `/auth/login` (10/min) and `/auth/register` (5/hour).

## Stack

- **Python 3.11** / **Flask** — API server
- **Gunicorn** — WSGI server (1 worker)
- **SQLite** — per-user database files in `/data/`
- **bcrypt** — password hashing
- **flask-limiter** — rate limiting
- **Docker** — containerised deployment

## Setup

### Prerequisites

- Docker and Docker Compose
- A reverse proxy (Caddy recommended) for HTTPS and CORS

### 1. Clone and configure

```bash
git clone https://github.com/Downes/kvstore.git
cd kvstore
cp .env.example .env
```

Edit `.env`:

```env
SECRET_KEY=your-random-secret-key-here
CORS_ORIGIN=https://your-clist-domain.com
DATA_DIR=/data
```

Generate a strong `SECRET_KEY`:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 2. Run the container

```bash
docker compose up -d
```

The app listens on port 5000 (internal only).

### 3. Configure Caddy

kvstore needs HTTPS and CORS headers. **Do not use `flask-cors`** — it fails to inject headers into Flask's automatic OPTIONS responses for blueprint routes, causing browser preflight requests to fail silently. Handle CORS entirely in Caddy:

```caddyfile
kvstore.yourdomain.com {
  handle /.well-known/acme-challenge/* {
    root * /srv/www/kvstore.yourdomain.com
    file_server
  }

  @options method OPTIONS
  handle @options {
    header Access-Control-Allow-Origin "https://your-clist-domain.com"
    header Access-Control-Allow-Credentials "true"
    header Access-Control-Allow-Methods "GET, POST, DELETE, OPTIONS"
    header Access-Control-Allow-Headers "Content-Type, Authorization"
    respond 204
  }

  handle {
    header Access-Control-Allow-Origin "https://your-clist-domain.com"
    header Access-Control-Allow-Credentials "true"
    reverse_proxy kvstore:5000
  }
}
```

Create the ACME challenge directory:
```bash
mkdir -p /srv/www/kvstore.yourdomain.com
```

### 4. Configure CList

In CList, users select their account server from a dropdown in the login screen. To add your kvstore instance as an option, add it to the `serverSelect` dropdown in `index.html`:

```html
<option value="https://kvstore.yourdomain.com">kvstore.yourdomain.com</option>
```

## Security notes

The server operator cannot decrypt stored credentials — they never possess the encryption key. However, since the client-side JavaScript is served by a web server, a malicious operator could in principle modify the JS to intercept credentials. Mitigations: open source code, Subresource Integrity (SRI), or self-hosting.

See [SECURITY.md](SECURITY.md) for the full threat model.

## Integrating kvstore authentication into your app

kvstore acts as a lightweight identity provider. Users log in to kvstore once; your app accepts their token without ever calling kvstore again.

### How it works

1. The user's browser derives an `authHash = PBKDF2(password, username+"_auth", 100k)` and POSTs it to `/auth/login`. kvstore returns a signed **ES256 JWT**.
2. The browser sends that JWT as a `Bearer` token with requests to your app.
3. Your app verifies the JWT locally using kvstore's public JWKS endpoint — no callback needed.

The JWT `iss` claim carries the kvstore URL, so your app doesn't need to know it in advance. Users running their own kvstore instance work automatically.

### Verifying a token — Node.js

```js
import { createRemoteJWKSet, jwtVerify } from 'jose';

// issuerUrl comes from the JWT's `iss` claim, or from the user's stored kvstore URL
const jwks = createRemoteJWKSet(new URL(`${issuerUrl}/.well-known/jwks.json`));
const { payload } = await jwtVerify(token, jwks, { issuer: issuerUrl });
const username = payload.sub; // authenticated username
```

### Verifying a token — Python

```python
import requests
from jwt import PyJWT
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Fetch the public key once and cache it
jwks = requests.get(f"{issuer_url}/.well-known/jwks.json").json()
# Convert JWKS to PEM and verify using PyJWT + cryptography
# See jwt_utils.py in this repo for a full implementation
```

See [jwt_utils.py](jwt_utils.py) for the complete Python verification used by kvstore itself.

### JWKS endpoint

```
GET /.well-known/jwks.json   (public, no auth required)
```

Returns an EC P-256 public key in standard JWKS format. Cache it — it only changes if the server is rebuilt from scratch.

### JWT claims

| Claim | Value |
|-------|-------|
| `sub` | Username — use this as the authenticated identity |
| `iss` | kvstore URL — use this to find the JWKS endpoint |
| `exp` | 30 days from login |

### Letting users bring their own kvstore

Don't hardcode a kvstore URL. Add a "Identity server" field to your login form and store the URL in `localStorage` alongside the token. Any user running a self-hosted kvstore instance will work without any changes on your end — the `iss` claim in their JWT points to their server automatically.

### `/auth/verify` — legacy callback verification

If your backend can't do local JWT verification, you can fall back to a server-side call:

```http
GET /auth/verify
Authorization: Bearer <token>
```

Returns `200 {"username": "alice", "valid": true}` or `401`. Use local verification (above) in preference — it's faster and doesn't create a dependency on kvstore being reachable at request time.

For the full authentication design including the zero-knowledge key derivation model, see [AUTH.md](AUTH.md).

## Licence

Copyright Stephen Downes
Licensed under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/)
