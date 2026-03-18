# app.py — Flask application factory for kvstore JSON API
import logging
from flask import Flask, request
from config import Config
from auth import auth_bp
from routes import routes_bp
from extensions import limiter

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


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
        if origin == Config.CORS_ORIGIN:
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

    return app


app = create_app()

if __name__ == '__main__':
    app.run(debug=False)
