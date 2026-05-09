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

On successful login the server issues a long-lived opaque Bearer token (`username:hex32`), stored as a SHA-256 hash in a per-user SQLite database.

### API endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/register` | — | Create account |
| POST | `/auth/login` | — | Authenticate, receive token |
| POST | `/auth/logout` | Bearer | Invalidate token |
| GET  | `/auth/verify` | Bearer | Validate token (used by proxyp) |
| GET  | `/get_kvs/` | Bearer | Retrieve all key-value pairs |
| POST | `/add_kv/` | Bearer | Add a new key-value pair |
| POST | `/update_kv/` | Bearer | Update an existing pair |
| POST | `/delete_kv/` | Bearer | Delete a pair |

Rate limiting is applied to `/auth/login` (10/min) and `/auth/register` (5/hour).

## Stack

- **Python 3.11** / **Flask** — API server
- **Gunicorn** — WSGI server (2 workers)
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

In CList's `index.html`, set:

```javascript
let flaskSiteUrl = 'https://kvstore.yourdomain.com';
```

## Security notes

The server operator cannot decrypt stored credentials — they never possess the encryption key. However, since the client-side JavaScript is served by a web server, a malicious operator could in principle modify the JS to intercept credentials. Mitigations: open source code, Subresource Integrity (SRI), or self-hosting.

See [SECURITY.md](SECURITY.md) for the full threat model.

## Licence

Copyright National Research Council of Canada 2025
Licensed under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/)
