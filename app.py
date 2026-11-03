# app.py — Flask application factory for kvstore JSON API
import json
import logging
import os
import sqlite3
from datetime import datetime
from urllib.parse import urlparse
from flask import Flask, request, jsonify, g
from config import Config
from auth import auth_bp
from routes import routes_bp
from extensions import limiter
from clist_server_admin.sqlite import (
    SettingField, init_settings_table, get_setting, register_admin_settings_routes, is_admin,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Generic admin-editable runtime settings (clist-server-admin pip package,
# pinned by commit SHA in requirements.txt — see /srv/shared/clist-server-admin).
# kvstore has no shared/global DB otherwise (every other table is per-user,
# see db_utils.py) — this is its own small dedicated sqlite file, same
# convention pastebin/survey use for their app_settings table.
SETTINGS_DB_PATH = os.path.join(Config.DATA_DIR, "_settings.db")


def _validate_url(value):
    parsed = urlparse(value)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        return "must be a valid http(s) URL"
    return None


SETTINGS_SCHEMA = [
    SettingField(
        key="ENABLED", label="Enabled", type="boolean", sensitive=False, validate=None,
        help="Cosmetic status flag only — kvstore has no kill-switch wired to this "
             "field (disabling it would break login for every CList user, unlike "
             "the other apps in this list). Kept for display consistency with the "
             "App Settings panel.",
    ),
    SettingField(
        key="DEFAULT_LOCALRSS", label="Default LocalRSS", type="url", sensitive=False, validate=_validate_url,
        help="Remote LocalRSS instance CList falls back to for logged-out visitors "
             "and accounts with no LocalRSS service URL of their own. Written to "
             "the paired CList install's defaults.js (window.CList.defaults.LOCALRSS) "
             "— never put a sensitive value in this field.",
    ),
    SettingField(
        key="DEFAULT_PASTEBIN", label="Default Pastebin", type="url", sensitive=False, validate=_validate_url,
        help="Written to the paired CList install's defaults.js (window.CList.defaults.PASTEBIN).",
    ),
    SettingField(
        key="DEFAULT_SURVEY", label="Default Survey", type="url", sensitive=False, validate=_validate_url,
        help="Written to the paired CList install's defaults.js (window.CList.defaults.SURVEY).",
    ),
    SettingField(
        key="DEFAULT_ANNOTATIONS", label="Default Annotations", type="url", sensitive=False, validate=_validate_url,
        help="Written to the paired CList install's defaults.js (window.CList.defaults.ANNOTATIONS).",
    ),
    SettingField(
        key="DEFAULT_COLLAB", label="Default Collab", type="url", sensitive=False, validate=_validate_url,
        help="Written to the paired CList install's defaults.js (window.CList.defaults.COLLAB).",
    ),
    SettingField(
        key="DEFAULT_DISCUSSIONS", label="Default Discussions", type="url", sensitive=False, validate=_validate_url,
        help="Written to the paired CList install's defaults.js (window.CList.defaults.DISCUSSIONS).",
    ),
]

SETTINGS_DEFAULTS = {
    "ENABLED": "true",
    "DEFAULT_LOCALRSS": os.environ.get("DEFAULT_LOCALRSS", "https://localrss.downes.ca"),
    "DEFAULT_PASTEBIN": os.environ.get("DEFAULT_PASTEBIN", "https://pastebin.mooc.ca"),
    "DEFAULT_SURVEY": os.environ.get("DEFAULT_SURVEY", "https://survey.mooc.ca"),
    "DEFAULT_ANNOTATIONS": os.environ.get("DEFAULT_ANNOTATIONS", "https://annotations.mooc.ca"),
    "DEFAULT_COLLAB": os.environ.get("DEFAULT_COLLAB", "https://collab.mooc.ca"),
    "DEFAULT_DISCUSSIONS": os.environ.get("DEFAULT_DISCUSSIONS", "https://discussions.mooc.ca"),
}

# Maps each DEFAULT_* setting to its property name in the paired CList
# install's defaults.js (window.CList.defaults.<name> — see
# /srv/www/clist.mooc.ca/defaults.js).
DEFAULTS_JS_KEYS = {
    "DEFAULT_LOCALRSS": "LOCALRSS",
    "DEFAULT_PASTEBIN": "PASTEBIN",
    "DEFAULT_SURVEY": "SURVEY",
    "DEFAULT_ANNOTATIONS": "ANNOTATIONS",
    "DEFAULT_COLLAB": "COLLAB",
    "DEFAULT_DISCUSSIONS": "DISCUSSIONS",
}


def _write_defaults_js():
    """Regenerates the paired CList install's defaults.js from the current
    settings (DB override, falling back to the .env-sourced SETTINGS_DEFAULTS).
    No-op if this instance has no paired CList install (CLIST_STATIC_DIR unset)
    — e.g. kvstore2, which is an alternate backend for the same clist.mooc.ca
    install kvstore already writes to, not a second CList install of its own."""
    if not Config.CLIST_STATIC_DIR:
        return
    db = sqlite3.connect(SETTINGS_DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        values = {
            js_key: get_setting(db, setting_key, default=SETTINGS_DEFAULTS[setting_key])
            for setting_key, js_key in DEFAULTS_JS_KEYS.items()
        }
    finally:
        db.close()

    lines = ["window.CList = window.CList || {};", "window.CList.defaults = {"]
    lines += [f"    {js_key}: {json.dumps(value)}," for js_key, value in values.items()]
    lines.append("};\n")

    path = os.path.join(Config.CLIST_STATIC_DIR, "defaults.js")
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        f.write("\n".join(lines))
    os.replace(tmp_path, path)


def get_settings_db():
    if "settings_db" not in g:
        g.settings_db = sqlite3.connect(SETTINGS_DB_PATH)
        g.settings_db.row_factory = sqlite3.Row
    return g.settings_db


def _init_settings_db():
    os.makedirs(Config.DATA_DIR, exist_ok=True)
    db = sqlite3.connect(SETTINGS_DB_PATH)
    init_settings_table(db)
    db.close()


def _verify_admin_token():
    """Adapter for register_admin_settings_routes's (username, err) contract.
    kvstore is the token issuer itself, so no remote JWKS fetch is needed —
    this mirrors the existing Bearer-token verification in auth.py's
    verify()/register_did() directly, then gates on ADMIN_USERNAMES."""
    from jwt_utils import is_jwt, verify_jwt
    from utils import parse_token, hash_token
    from db_utils import get_user_session
    from models_user_kv import User

    auth_header = request.headers.get('Authorization', '')
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None, ({'error': 'Authorization header required'}, 401)
    token_str = parts[1]

    if is_jwt(token_str):
        username = verify_jwt(token_str)
        if not username:
            return None, ({'error': 'Invalid or expired token'}, 401)
    else:
        username, raw_token = parse_token(token_str)
        if not username:
            return None, ({'error': 'Malformed token'}, 401)
        session = get_user_session(username)
        try:
            user = session.query(User).filter_by(username=username).first()
            if not user or user.api_token_hash != hash_token(raw_token):
                return None, ({'error': 'Invalid token'}, 401)
            if user.token_expires and user.token_expires < datetime.utcnow():
                return None, ({'error': 'Token expired'}, 401)
        finally:
            session.close()

    if not is_admin(username):
        return None, ({'error': 'Forbidden'}, 403)
    return username, None


def create_app():
    Config.validate()

    app = Flask(__name__)
    app.config['SECRET_KEY'] = Config.SECRET_KEY

    limiter.init_app(app)

    # Explicit CORS — flask-cors doesn't reliably intercept Flask's automatic OPTIONS
    # responses for blueprint routes, so we handle it directly here.
    @app.after_request
    def cors_headers(response):
        origin = request.headers.get('Origin', '')
        if origin in Config.CORS_ORIGIN:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            if request.method == 'OPTIONS':
                response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, OPTIONS'
                response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return response

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(routes_bp)

    @app.route('/health')
    def health():
        return {'status': 'ok'}

    @app.route('/.well-known/jwks.json')
    def jwks():
        from jwt_utils import get_jwks
        return jsonify(get_jwks())

    _init_settings_db()
    _write_defaults_js()  # keep defaults.js in sync with the DB on every start/restart

    @app.teardown_appcontext
    def close_settings_db(e=None):
        db = g.pop("settings_db", None)
        if db:
            db.close()

    register_admin_settings_routes(app, SETTINGS_SCHEMA, get_settings_db, _verify_admin_token, SETTINGS_DEFAULTS)

    @app.after_request
    def _regenerate_defaults_js(response):
        # register_admin_settings_routes owns PUT /admin/settings's handler and
        # commit — this just reacts to a successful save by rewriting defaults.js.
        if request.path == '/admin/settings' and request.method == 'PUT' and response.status_code == 200:
            _write_defaults_js()
        return response

    return app


app = create_app()

if __name__ == '__main__':
    app.run(debug=False)
