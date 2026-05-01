# auth.py — registration, login, logout routes (JSON API)
import base64
import json
import re
import bcrypt
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify
from db_utils import get_user_session
from models_user_kv import User
from utils import generate_opaque_token, hash_token, parse_token, token_expiry
from jwt_utils import is_jwt, issue_jwt, verify_jwt
from config import Config
from extensions import limiter

auth_bp = Blueprint('auth', __name__)
log = logging.getLogger(__name__)


def _valid_auth_hash(h):
    """auth_hash must be a 64-character lowercase hex string (256-bit PBKDF2 output)."""
    return isinstance(h, str) and len(h) == 64 and all(c in '0123456789abcdef' for c in h)


@auth_bp.route("/verify", methods=["GET"])
def verify():
    """Validate a Bearer token. Returns 200 + username if valid, 401 if not.
    Used by proxyp (and any other internal service) to check kvstore auth."""
    auth_header = request.headers.get('Authorization', '')
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return jsonify({'error': 'Authorization header required'}), 401

    token_str = parts[1]

    # JWT path — verify cryptographically, no DB lookup needed
    if is_jwt(token_str):
        username = verify_jwt(token_str)
        if not username:
            return jsonify({'error': 'Invalid or expired token'}), 401
        return jsonify({'username': username}), 200

    # Opaque token path — kept for backwards compatibility with existing sessions
    username, raw_token = parse_token(token_str)
    if not username:
        return jsonify({'error': 'Malformed token'}), 401

    session = get_user_session(username)
    try:
        user = session.query(User).filter_by(username=username).first()
        if not user or user.api_token_hash != hash_token(raw_token):
            return jsonify({'error': 'Invalid token'}), 401
        if user.token_expires and user.token_expires < datetime.utcnow():
            return jsonify({'error': 'Token expired'}), 401
        return jsonify({'username': username}), 200
    finally:
        session.close()


@auth_bp.route("/register", methods=["POST"])
@limiter.limit("5 per hour")
def register():
    """
    Create a new user account.
    Expects JSON: { "username": str, "auth_hash": hex64 }
    auth_hash = PBKDF2(password, username+"_auth", 100k iterations) — derived client-side.
    Server stores bcrypt(auth_hash). Server never sees the raw password or encryption key.
    """
    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip().lower()
    auth_hash = data.get('auth_hash', '')

    if not username:
        return jsonify({'error': 'username is required'}), 400
    if not re.match(r'^[a-z0-9][a-z0-9._-]{2,31}$', username):
        return jsonify({'error': 'Username must be 3–32 characters, start with a letter or digit, and contain only letters, digits, dots, hyphens, and underscores'}), 400
    if not _valid_auth_hash(auth_hash):
        return jsonify({'error': 'auth_hash must be a 64-char lowercase hex string'}), 400

    session = get_user_session(username)
    try:
        if session.query(User).filter_by(username=username).first():
            return jsonify({'error': 'User already exists'}), 409

        stored = bcrypt.hashpw(bytes.fromhex(auth_hash), bcrypt.gensalt()).decode()
        session.add(User(username=username, auth_hash=stored))
        session.commit()
        log.info("Registered new user: %s", username)
        return jsonify({'message': 'Registration successful'}), 201
    finally:
        session.close()


@auth_bp.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    """
    Authenticate a user and return a long-lived opaque token.
    Expects JSON: { "username": str, "auth_hash": hex64 }
    Returns: { "token": str, "username": str, "expires": ISO8601 }
    """
    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip().lower()
    auth_hash = data.get('auth_hash', '')

    if not username or not _valid_auth_hash(auth_hash):
        return jsonify({'error': 'username and valid auth_hash required'}), 400

    session = get_user_session(username)
    try:
        user = session.query(User).filter_by(username=username).first()
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401

        if not bcrypt.checkpw(bytes.fromhex(auth_hash), user.auth_hash.encode()):
            return jsonify({'error': 'Invalid credentials'}), 401

        log.info("Login successful: %s", username)
        token, expires = issue_jwt(username, Config.ISSUER_URL)
        return jsonify({
            'token': token,
            'username': username,
            'expires': expires.isoformat(),
        }), 200
    finally:
        session.close()


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """
    Invalidate the current token.
    Expects: Authorization: Bearer <token>
    """
    auth_header = request.headers.get('Authorization', '')
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return jsonify({'error': 'No valid token'}), 401

    token_str = parts[1]
    if is_jwt(token_str):
        return jsonify({'message': 'Logged out'}), 200

    from utils import parse_token
    username, raw_token = parse_token(token_str)
    if not username:
        return jsonify({'error': 'Malformed token'}), 401

    session = get_user_session(username)
    try:
        user = session.query(User).filter_by(username=username).first()
        if user:
            user.api_token_hash = None
            user.token_expires = None
            session.commit()
        return jsonify({'message': 'Logged out'}), 200
    finally:
        session.close()


@auth_bp.route("/did", methods=["PUT"])
def register_did():
    """Register or update the user's Ed25519 public key and DID profile.
    Stores user-controlled parts; full DID document is assembled at serve time."""

    # Verify auth (same pattern as /verify)
    auth_header = request.headers.get('Authorization', '')
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return jsonify({'error': 'Authorization header required'}), 401
    token_str = parts[1]
    if is_jwt(token_str):
        username = verify_jwt(token_str)
        if not username:
            return jsonify({'error': 'Invalid or expired token'}), 401
    else:
        username, raw_token = parse_token(token_str)
        if not username:
            return jsonify({'error': 'Malformed token'}), 401
        session = get_user_session(username)
        try:
            user = session.query(User).filter_by(username=username).first()
            if not user or user.api_token_hash != hash_token(raw_token):
                return jsonify({'error': 'Invalid token'}), 401
        finally:
            session.close()

    data = request.get_json(silent=True) or {}
    jwk          = data.get('publicKeyJwk')
    did_key      = data.get('didKey', '')
    services     = data.get('service', [])
    also_known_as = data.get('alsoKnownAs', [])

    # Validate Ed25519 OKP JWK
    if not jwk or jwk.get('kty') != 'OKP' or jwk.get('crv') != 'Ed25519' or not jwk.get('x'):
        return jsonify({'error': 'publicKeyJwk must be an Ed25519 OKP JWK with x coordinate'}), 400
    try:
        x_bytes = base64.urlsafe_b64decode(jwk['x'] + '==')
        if len(x_bytes) != 32:
            raise ValueError
    except Exception:
        return jsonify({'error': 'publicKeyJwk.x must be base64url-encoded 32 bytes'}), 400

    # Validate client-computed did:key (Ed25519 did:key always starts did:key:z6Mk)
    if not re.match(r'^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$', did_key):
        return jsonify({'error': 'didKey must be a valid Ed25519 did:key (did:key:z6Mk...)'}), 400

    # Validate services array
    if not isinstance(services, list):
        return jsonify({'error': 'service must be an array'}), 400
    for svc in services:
        if not all(k in svc for k in ('id', 'type', 'serviceEndpoint')):
            return jsonify({'error': 'each service must have id, type, and serviceEndpoint'}), 400

    # Validate alsoKnownAs array
    if not isinstance(also_known_as, list) or not all(isinstance(a, str) for a in also_known_as):
        return jsonify({'error': 'alsoKnownAs must be an array of strings'}), 400

    profile = {'publicKeyJwk': jwk, 'didKey': did_key, 'service': services, 'alsoKnownAs': also_known_as}
    session = get_user_session(username)
    try:
        user = session.query(User).filter_by(username=username).first()
        user.did_document = json.dumps(profile)
        session.commit()
    finally:
        session.close()

    log.info("DID profile registered for %s: %s", username, did_key)
    return jsonify({'message': 'DID profile registered', 'didKey': did_key}), 200


@auth_bp.route("/did", methods=["DELETE"])
def delete_did():
    """Remove the user's DID profile. The public DID document will return 404 after this."""

    auth_header = request.headers.get('Authorization', '')
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return jsonify({'error': 'Authorization header required'}), 401
    token_str = parts[1]
    if is_jwt(token_str):
        username = verify_jwt(token_str)
        if not username:
            return jsonify({'error': 'Invalid or expired token'}), 401
    else:
        username, raw_token = parse_token(token_str)
        if not username:
            return jsonify({'error': 'Malformed token'}), 401
        session = get_user_session(username)
        try:
            user = session.query(User).filter_by(username=username).first()
            if not user or user.api_token_hash != hash_token(raw_token):
                return jsonify({'error': 'Invalid token'}), 401
        finally:
            session.close()

    session = get_user_session(username)
    try:
        user = session.query(User).filter_by(username=username).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        user.did_document = None
        session.commit()
    finally:
        session.close()

    log.info("DID profile removed for %s", username)
    return jsonify({'message': 'DID profile removed'}), 200
