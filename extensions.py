# extensions.py — shared Flask extensions (avoids circular imports)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# In-memory storage; works correctly with a single Gunicorn worker.
limiter = Limiter(key_func=get_remote_address, default_limits=[])
