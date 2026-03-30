# config.py — app configuration from environment variables
import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', '')
    # Comma-separated list of allowed CORS origins, e.g. "https://clist.mooc.ca,http://localhost:8080"
    CORS_ORIGIN = [o.strip() for o in os.environ.get('CORS_ORIGIN', 'https://clist.mooc.ca').split(',')]
    DATA_DIR = os.environ.get('DATA_DIR', '/data')
    ISSUER_URL = os.environ.get('ISSUER_URL', 'https://kvstore.mooc.ca')

    @classmethod
    def validate(cls):
        if not cls.SECRET_KEY:
            raise ValueError("SECRET_KEY environment variable must be set")
