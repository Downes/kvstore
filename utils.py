# utils.py — token generation and hashing helpers
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

TOKEN_LIFETIME_DAYS = 365


def generate_opaque_token(username):
    """Return a token in 'username:hex32' format.
    The username prefix lets the server locate the right per-user DB
    without a separate token-lookup table."""
    return f"{username}:{secrets.token_hex(32)}"


def hash_token(token):
    """SHA-256 hash of a token for safe DB storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def token_expiry():
    """Return expiry datetime for a freshly issued token."""
    return datetime.now(timezone.utc) + timedelta(days=TOKEN_LIFETIME_DAYS)


def parse_token(raw_token):
    """Split 'username:hex' into (username, raw_token). Returns (None, None) if malformed."""
    parts = raw_token.split(':', 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None, None
    return parts[0], raw_token
