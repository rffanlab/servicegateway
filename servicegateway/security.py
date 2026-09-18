import hashlib
import secrets
import threading
import time
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from fastapi import HTTPException, Request
from sqlalchemy import select
from .db import ApiKey, LoginSession, User, now

ph = PasswordHasher()
DUMMY_HASH = ph.hash(secrets.token_urlsafe(32))
ROLES = {"viewer": 0, "operator": 1, "admin": 2}


def digest(value: str):
    return hashlib.sha256(value.encode()).hexdigest()


def verify(password, encoded):
    try:
        return ph.verify(encoded, password)
    except (VerificationError, InvalidHashError):
        return False


class LoginLimiter:
    def __init__(self):
        self.lock = threading.Lock()
        self.buckets = {}

    def check(self, peer):
        with self.lock:
            t = time.monotonic()
            self.buckets = {k: v for k, v in self.buckets.items() if t - v[0] < 60}
            start, count = self.buckets.get(peer, (t, 0))
            if count >= 20 or (peer not in self.buckets and len(self.buckets) >= 1024):
                raise HTTPException(429, "登录过于频繁，请稍后重试")
            self.buckets[peer] = (start, count + 1)


def principal(request: Request, db, role="viewer", csrf=True):
    token = request.cookies.get("sg_session", "")
    session = db.get(LoginSession, digest(token)) if token else None
    user = db.get(User, session.user_id) if session and session.expires_at > now() else None
    if not user or not user.enabled:
        raise HTTPException(401, "请先登录")
    if ROLES.get(user.role, -1) < ROLES[role]:
        raise HTTPException(403, "权限不足")
    if csrf and request.method not in ("GET", "HEAD", "OPTIONS"):
        if not secrets.compare_digest(request.headers.get("X-CSRF-Token", ""), session.csrf):
            raise HTTPException(403, "CSRF 校验失败，请刷新页面")
    return user, session


def api_key(request, db):
    token = request.headers.get("X-Gateway-Key", "")
    if not token or len(token) > 200:
        return None
    key = db.scalar(select(ApiKey).where(ApiKey.token_hash == digest(token)))
    return key if key and not key.revoked and key.expires_at > now() else None
