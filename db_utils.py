# db_utils.py — per-user SQLite session factory
import os
import re
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models_user_kv import Base

DATA_DIR = os.environ.get('DATA_DIR', '/data')


def get_user_session(username):
    """Open (and auto-create) a per-user SQLite DB, return a Session."""
    # Restrict username characters to prevent path traversal
    safe = re.sub(r'[^a-zA-Z0-9._-]', '_', username)
    db_path = os.path.join(DATA_DIR, f"{safe}.db")
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()
