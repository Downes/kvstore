# config.py — app configuration from environment variables
import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', '')
    # Comma-separated list of allowed CORS origins, e.g. "https://clist.mooc.ca,http://localhost:8080"
    CORS_ORIGIN = [o.strip() for o in os.environ.get('CORS_ORIGIN', 'https://clist.mooc.ca').split(',')]
    DATA_DIR = os.environ.get('DATA_DIR', '/data')
    ISSUER_URL = os.environ.get('ISSUER_URL', 'https://kvstore.mooc.ca')
    # Known kvstore instances a did.html profile's Follow link may forward a
    # visitor's token to. mykvstore is a query-string param — never trust it
    # as a redirect/token-forwarding target without checking this allowlist.
    ALLOWED_KVSTORE_URLS = [
        u.strip() for u in os.environ.get(
            'ALLOWED_KVSTORE_URLS', 'https://kvstore.mooc.ca,https://kvstore.downes.ca'
        ).split(',')
    ]

    @classmethod
    def validate(cls):
        if not cls.SECRET_KEY:
            raise ValueError("SECRET_KEY environment variable must be set")
