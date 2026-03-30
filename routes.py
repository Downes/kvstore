# routes.py — KV store API routes + discussions registry
import os
import json
import time
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify
from db_utils import get_user_session
from models_user_kv import KeyValue, User
from utils import hash_token, parse_token
from jwt_utils import is_jwt, verify_jwt
from functools import wraps

routes_bp = Blueprint('routes', __name__)
log = logging.getLogger(__name__)

DISCUSSIONS_FILE = os.path.join(os.path.dirname(__file__), 'discussions.json')
DISCUSSION_EXPIRY = 300  # seconds


# ------------------------------------------------------------------------------
# TOKEN AUTHENTICATION
# ------------------------------------------------------------------------------

def token_required(f):
    """Decorator: verify Bearer token (JWT or opaque), inject username into route."""
    @wraps(f)
    def decorated(*args, **kwargs):
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
            return f(username, *args, **kwargs)

        # Opaque token path — kept for backwards compatibility with existing sessions
        username, raw_token = parse_token(token_str)
        if not username:
            return jsonify({'error': 'Malformed token'}), 401

        token_hash = hash_token(raw_token)
        session = get_user_session(username)
        try:
            user = session.query(User).filter_by(username=username).first()
            if not user or user.api_token_hash != token_hash:
                return jsonify({'error': 'Invalid token'}), 401
            if user.token_expires and user.token_expires < datetime.utcnow():
                return jsonify({'error': 'Token expired'}), 401
        finally:
            session.close()

        return f(username, *args, **kwargs)
    return decorated


# ------------------------------------------------------------------------------
# KEY-VALUE ROUTES
# ------------------------------------------------------------------------------

@routes_bp.route('/get_kvs/', methods=['GET'])
@token_required
def get_kvs(username):
    """Return all KV pairs for the authenticated user."""
    session = get_user_session(username)
    try:
        kvs = session.query(KeyValue).all()
        return jsonify([{'key': kv.key, 'value': kv.value} for kv in kvs])
    finally:
        session.close()


@routes_bp.route('/add_kv/', methods=['POST'])
@token_required
def add_kv(username):
    """Add a new KV pair. Fails if key already exists."""
    data = request.get_json(silent=True) or {}
    key = data.get('key', '').strip()
    value = data.get('value', '')

    if not key or not value:
        return jsonify({'error': 'key and value are required'}), 400

    session = get_user_session(username)
    try:
        if session.query(KeyValue).filter_by(key=key).first():
            return jsonify({'error': 'Key already exists'}), 409
        session.add(KeyValue(key=key, value=value))
        session.commit()
        return jsonify({'message': 'Added'}), 201
    finally:
        session.close()


@routes_bp.route('/update_kv/', methods=['POST'])
@token_required
def update_kv(username):
    """Update an existing KV pair."""
    data = request.get_json(silent=True) or {}
    key = data.get('key', '').strip()
    new_value = data.get('value', '')

    if not key or not new_value:
        return jsonify({'error': 'key and value are required'}), 400

    session = get_user_session(username)
    try:
        kv = session.query(KeyValue).filter_by(key=key).first()
        if not kv:
            return jsonify({'error': 'Key not found'}), 404
        kv.value = new_value
        session.commit()
        return jsonify({'message': 'Updated'})
    finally:
        session.close()


@routes_bp.route('/delete_kv/', methods=['POST'])
@token_required
def delete_kv(username):
    """Delete a KV pair by key."""
    data = request.get_json(silent=True) or {}
    key = data.get('key', '').strip()

    if not key:
        return jsonify({'error': 'key is required'}), 400

    session = get_user_session(username)
    try:
        kv = session.query(KeyValue).filter_by(key=key).first()
        if not kv:
            return jsonify({'error': 'Key not found'}), 404
        session.delete(kv)
        session.commit()
        return jsonify({'message': 'Deleted'})
    finally:
        session.close()


# ------------------------------------------------------------------------------
# DISCUSSIONS REGISTRY  (to be extracted to its own app later)
# ------------------------------------------------------------------------------

@routes_bp.route('/api/discussions', methods=['POST', 'GET', 'DELETE'])
def manage_discussions():
    """Unauthenticated P2P discussion peer registry with 5-minute TTL."""
    if not os.path.exists(DISCUSSIONS_FILE):
        if request.method != 'POST':
            return jsonify({'error': 'No discussions file found'}), 404
        with open(DISCUSSIONS_FILE, 'w') as f:
            json.dump([], f)

    def load():
        try:
            with open(DISCUSSIONS_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    def save(d):
        with open(DISCUSSIONS_FILE, 'w') as f:
            json.dump(d, f)

    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        name = data.get('name')
        peer_id = data.get('peerId')
        if not name or not peer_id:
            return jsonify({'error': 'name and peerId required'}), 400
        discussions = load()
        for d in discussions:
            if d['name'] == name:
                d['timestamp'] = int(time.time())
                break
        else:
            discussions.append({'name': name, 'peerId': peer_id, 'timestamp': int(time.time())})
        save(discussions)
        return jsonify({'message': 'Discussion advertised'}), 201

    elif request.method == 'GET':
        now = int(time.time())
        discussions = [d for d in load() if now - d['timestamp'] <= DISCUSSION_EXPIRY]
        save(discussions)
        return jsonify(discussions), 200

    elif request.method == 'DELETE':
        data = request.get_json(silent=True) or {}
        name = data.get('name')
        if not name:
            return jsonify({'error': 'name required'}), 400
        discussions = load()
        updated = [d for d in discussions if d['name'] != name]
        if len(updated) == len(discussions):
            return jsonify({'error': 'Discussion not found'}), 404
        save(updated)
        return jsonify({'message': 'Removed'}), 200
