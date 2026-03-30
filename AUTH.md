# kvstore Authentication — How Remote Services Integrate

This document describes how remote web applications authenticate users via kvstore
and how kvstore tokens are verified. It covers the full flow from login to API access.

---

## Overview

kvstore acts as an identity provider. Users log in with a password-derived hash;
kvstore issues a signed JWT that the user's browser stores and sends to any app that
needs to verify their identity. Apps verify the JWT **locally** — they never need to
call kvstore again after the initial login.

---

## 1. Login flow (browser → kvstore)

The browser (running CList, CARE, or any other client) never sends the raw password
to kvstore. Instead it derives a one-way hash client-side:

```
authHash = PBKDF2(password, username + "_auth", 100 000 iterations, SHA-256)
           → 64-character lowercase hex string (256 bits)
```

The browser POSTs this to kvstore:

```http
POST /auth/login
Content-Type: application/json

{ "username": "alice", "auth_hash": "<64-char hex>" }
```

kvstore checks `bcrypt(authHash)` against its stored value. On success it returns:

```json
{
  "token":   "<signed JWT>",
  "username": "alice",
  "expires":  "2026-04-29T21:00:00+00:00"
}
```

The browser stores the token in `localStorage` alongside the kvstore URL it used to
log in. Both are needed: the token for auth, the URL to know which JWKS endpoint to
verify against.

---

## 2. The JWT

The token is a standard **ES256 JWT** (ECDSA over P-256, SHA-256).

### Claims

| Claim | Value | Purpose |
|-------|-------|---------|
| `sub` | `"alice"` | Username — used as identity by relying apps |
| `iss` | `"https://kvstore.mooc.ca"` | Issuer URL — tells verifiers where to fetch the public key |
| `iat` | Unix timestamp | Issued-at |
| `exp` | Unix timestamp (+30 days) | Expiry |

### Why EC P-256?

Smaller and faster than RSA at equivalent security. Keys are ~32 bytes vs ~256 bytes.

---

## 3. The public key (JWKS endpoint)

kvstore generates an EC P-256 keypair on first start and persists it to
`/data/jwk_private.pem`. The corresponding public key is served at:

```
GET /.well-known/jwks.json
```

No authentication required. Response example:

```json
{
  "keys": [{
    "kty": "EC",
    "crv": "P-256",
    "use": "sig",
    "alg": "ES256",
    "x": "<base64url>",
    "y": "<base64url>"
  }]
}
```

This is the standard **JWKS** (JSON Web Key Set) format. Any library that understands
JWKS can use it — no kvstore-specific code required on the relying app side.

---

## 4. How a remote app verifies a token

When the user sends a request to a remote app with `Authorization: Bearer <JWT>`,
the app does **not** call kvstore. It verifies locally:

1. **Decode** the JWT header and payload (no signature check yet) to extract `iss`.
2. **Fetch** `<iss>/.well-known/jwks.json` — e.g. `https://kvstore.mooc.ca/.well-known/jwks.json`.
   Cache this response; it rarely changes.
3. **Verify** the JWT signature against the fetched public key and check expiry.
4. **Trust** the `sub` claim as the authenticated username.

This works with **any kvstore instance** — a user running their own kvstore at
`https://mykvstore.example.com` will have `iss` pointing to their instance, and
remote apps will fetch the public key from there automatically.

### Node.js example (using `jose`)

```js
import { createRemoteJWKSet, jwtVerify } from 'jose';

const jwks = createRemoteJWKSet(new URL(`${issuerUrl}/.well-known/jwks.json`));
const { payload } = await jwtVerify(token, jwks, { issuer: issuerUrl });
const username = payload.sub;
```

### Python example (using `PyJWT` + `cryptography`)

See `jwt_utils.py` → `verify_jwt()` for the server-side implementation used by
kvstore itself when verifying tokens on its own `/auth/verify` and KV routes.

---

## 5. kvstore's own token verification

kvstore verifies tokens on two code paths:

- **`/auth/verify`** (`auth.py`) — called by legacy services (proxyp) that do not
  verify JWTs locally and still use the callback style.
- **`token_required` decorator** (`routes.py`) — protects all KV endpoints
  (`/get_kvs/`, `/add_kv/`, `/update_kv/`, `/delete_kv/`).

Both paths handle two token formats:

```
if token has two dots  →  JWT path: verify signature via jwt_utils.verify_jwt()
else                   →  Opaque path: parse "username:hex", check SHA-256 hash in DB
```

The opaque path exists only for backwards compatibility with existing CList/proxyp
sessions that predate the JWT migration. New logins always receive JWTs.

---

## 6. Opaque tokens (legacy, backwards-compatible)

Format: `username:hex32` (64 hex chars after the colon).

Stored as `SHA-256(token)` in the per-user SQLite DB. Valid for 365 days from issue.
kvstore no longer **issues** opaque tokens (login always returns a JWT), but it
continues to **accept** them until existing sessions expire.

---

## 7. Bring-your-own-kvstore

Because the JWT `iss` claim carries the kvstore URL and the JWKS endpoint is public,
users can run their own kvstore instance and use it with any app that supports this
flow. The app does not need to know the kvstore URL in advance — it reads it from
the JWT itself.

The app's frontend needs to let users enter their kvstore URL at login time (rather
than hardcoding a default). CARE does this via the "Identity server" field on its
login form; the URL is stored in `localStorage` alongside the token.

---

## 8. What kvstore does NOT know

- The user's raw password (never sent; derived hash only)
- The user's encryption key (`encKey = PBKDF2(password, username+"_enc", 100k)` —
  stays in the browser, never transmitted)
- The plaintext of any stored KV values (all AES-GCM encrypted client-side)
