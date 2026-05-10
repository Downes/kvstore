# kvstore Security Model

## Design goals

- The server never sees your password or encryption key.
- Stored values are opaque ciphertext; the server cannot read them.
- A passive attacker who reads the database cannot decrypt your data.

## How it works

Two keys are derived client-side from your password using PBKDF2-SHA256 (100k iterations):

- **encKey** = PBKDF2(password, username+"_enc") — stays in the browser, never transmitted.
  Used to AES-GCM encrypt/decrypt KV values before they are sent to or received from the server.
- **authHash** = PBKDF2(password, username+"_auth") — sent to the server on login/register.
  The server stores bcrypt(authHash). The server never sees the raw password.

The two salts are different by design: knowing authHash does not let you derive encKey.

On login the server issues a signed **ES256 JWT** (30-day expiry). Legacy opaque tokens
(`username:hex32`, SHA-256 hashed in DB) are still accepted for backwards compatibility but
are no longer issued.

## What the server (and its operator) can and cannot do

### Cannot (without knowing your password)
- Read your plaintext credential values — they are AES-GCM encrypted with encKey, which never
  leaves your browser.
- Derive encKey from the stored bcrypt(authHash) — different salt, different key.
- Use a stored token hash to impersonate you — opaque tokens are stored as SHA-256 hashes
  (not reversible); JWTs are verified cryptographically with no server-side state at all.

### Can (with access to server code or database)
- **Log the incoming authHash** on login. This does not directly give encKey, but it enables
  faster offline brute-force of your password (100k PBKDF2 iterations per guess, no bcrypt
  overhead). If your password is weak, this is a real threat.
- Disrupt or delete your data (availability attack).
- Return garbage from /get_kvs/ — you will see decryption errors, not silent data theft.
- **Retain access after you log out.** JWTs cannot be revoked server-side — kvstore holds no
  server-side session state for JWT users. Logging out clears your local token, but a stolen
  JWT remains valid until it expires (30 days). If you suspect a token has been compromised,
  change your password (which changes authHash and invalidates old opaque tokens, but does
  not invalidate outstanding JWTs until they expire naturally).

### The unavoidable trust requirement: who serves the JavaScript?

If the server operator also serves the frontend JavaScript (e.g., clist.mooc.ca on the same VPS),
they can inject code to steal encKey from sessionStorage or intercept the password before
PBKDF2 runs. **This completely bypasses the zero-knowledge design.**

This is a fundamental limitation of browser-based cryptography: the browser trusts whatever
JavaScript it is served.

## Mitigations and their limits

| Mitigation | What it prevents | What it does not prevent |
|---|---|---|
| Separate frontend host (GitHub Pages, CDN) | VPS operator modifying JS without GitHub access | Operator who also controls the frontend host |
| Open source code | Users can audit what the code is supposed to do | Operator serving different code than what is published |
| Published SRI hashes | Makes JS substitution detectable after the fact | Operator who also controls the HTML (can update the hash) |
| Self-hosting | User trusts no operator at all | Requires user to run their own copy |
| Browser extension (app store distributed) | JS served by a third-party gatekeeper | Extension author themselves |
| Strong password | Makes offline brute-force of captured authHash infeasible | Everything else |

## The honest bottom line

For a web app, you cannot fully eliminate trust in the operator. The best achievable goal is to
make that trust *auditable* and *optional*:

- Publish the source so users can read what the code does.
- Serve the frontend from a host independent of the API server when possible.
- Support self-hosting so users who do not trust the operator can run their own copy.
- Be transparent: using a hosted instance means trusting the host.

The same trust model applies to Bitwarden's web vault, ProtonMail's web client, and most other
browser-based encrypted services. Users who need stronger guarantees should use native apps
(distributed through app stores with independent signing) or self-host.

## Current deployment

- API: kvstore.mooc.ca (VPS 158.69.209.43, /srv/apps/kvstore/)
- Frontend: clist.mooc.ca (same VPS, /srv/www/clist.mooc.ca/)

Both are controlled by the same operator. Users of the hosted instance trust that operator.

Both components are open source:
- kvstore API: https://github.com/Downes/kvstore
- CList frontend: https://github.com/Downes/CList
