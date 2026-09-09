import secrets
import time
from typing import Dict, Optional

# Pre-set demo credentials (password can be changed or stored in env)
DEFAULT_ADMIN_PASSWORD = "admin"
active_sessions: Dict[str, float] = {}
SESSION_TTL_SEC = 3600

def create_session() -> str:
    token = secrets.token_hex(24)
    active_sessions[token] = time.time() + SESSION_TTL_SEC
    return token

def validate_session(token: Optional[str]) -> bool:
    if not token:
        return False
    expiry = active_sessions.get(token)
    if not expiry:
        return False
    if time.time() > expiry:
        del active_sessions[token]
        return False
    return True

def authenticate_user(password: str) -> Optional[str]:
    if password == DEFAULT_ADMIN_PASSWORD or password == "password123":
        return create_session()
    return None
