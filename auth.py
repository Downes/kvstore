# auth.py — registration, login, logout routes (JSON API)
import bcrypt
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify
from db_utils import get_user_session
from models_user_kv import User
from utils import generate_opaque_token, hash_token, parse_token, token_expiry
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

    username, raw_token = parse_token(parts[1])
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

        token = generate_opaque_token(username)
        user.api_token_hash = hash_token(token)
        user.token_expires = token_expiry()
        session.commit()
        log.info("Login successful: %s", username)

        return jsonify({
            'token': token,
            'username': username,
            'expires': user.token_expires.isoformat(),
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

    from utils import parse_token
    username, raw_token = parse_token(parts[1])
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
