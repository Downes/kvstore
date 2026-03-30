# jwt_utils.py — EC P-256 keypair management, JWT issuance, and JWKS export
import base64
import os
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, load_pem_private_key
)

JWT_LIFETIME_DAYS = 30


def _key_path():
    from config import Config
    return os.path.join(Config.DATA_DIR, 'jwk_private.pem')


def _load_or_create_key():
    """Load existing EC P-256 private key from disk, or generate and persist a new one."""
    path = _key_path()
    if os.path.exists(path):
        with open(path, 'rb') as f:
            return load_pem_private_key(f.read(), password=None)
    key = generate_private_key(SECP256R1())
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(pem)
    return key


# Load/create key once at import time
_private_key = _load_or_create_key()
_public_key = _private_key.public_key()


def _b64url(data: bytes) -> str:
    """URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def get_jwks() -> dict:
    """Return the public key as a JWKS document."""
    nums = _public_key.public_numbers()
    return {
        'keys': [{
            'kty': 'EC',
            'crv': 'P-256',
            'use': 'sig',
            'alg': 'ES256',
            'x': _b64url(nums.x.to_bytes(32, 'big')),
            'y': _b64url(nums.y.to_bytes(32, 'big')),
        }]
    }


def issue_jwt(username: str, issuer_url: str) -> tuple:
    """Issue a signed JWT. Returns (token_string, expires_datetime)."""
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=JWT_LIFETIME_DAYS)
    token = jwt.encode(
        {'sub': username, 'iss': issuer_url, 'iat': now, 'exp': expires},
        _private_key,
        algorithm='ES256',
    )
    return token, expires


def is_jwt(token: str) -> bool:
    """Return True if this looks like a JWT (three dot-separated base64url segments)."""
    return token.count('.') == 2


def verify_jwt(token: str) -> str | None:
    """Verify a JWT issued by this server. Returns username (sub claim) or None if invalid."""
    try:
        payload = jwt.decode(token, _public_key, algorithms=['ES256'])
        return payload.get('sub')
    except jwt.PyJWTError:
        return None
