import hashlib
from datetime import timedelta
import secrets
import threading
import time
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from fastapi import HTTPException, Request
from sqlalchemy import select, update
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
    token = request.cookies.get(request.app.state.settings.cookie_name, "")
    session = db.get(LoginSession, digest(token)) if token else None
    user = db.get(User, session.user_id) if session and session.expires_at > now() else None
    settings = request.app.state.settings
    if (not user or not user.enabled or session.last_seen_at is None
            or session.last_seen_at < now() - timedelta(minutes=settings.session_idle_minutes)):
        raise HTTPException(401, "请先登录或会话已过期")
    if session.last_seen_at < now() - timedelta(seconds=60):
        # Separate short transaction: GET handlers intentionally do not commit their read session.
        # Never take gateway_state before/while refreshing a session.
        with request.app.state.sessions.begin() as refresh_db:
            refresh_db.execute(update(LoginSession).where(
                LoginSession.token_hash == session.token_hash,
                LoginSession.last_seen_at == session.last_seen_at,
            ).values(last_seen_at=now()))
    if ROLES.get(user.role, -1) < ROLES[role]:
        raise HTTPException(403, "权限不足")
    if csrf and request.method not in ("GET", "HEAD", "OPTIONS"):
        if not secrets.compare_digest(request.headers.get("X-CSRF-Token", ""), session.csrf):
            raise HTTPException(403, "CSRF 校验失败，请刷新页面")
    critical = (request.url.path.startswith(("/api/gateway/publish", "/api/gateway/rollback/", "/api/users", "/api/keys"))
                or (request.url.path.startswith("/api/services/") and request.url.path.endswith("/actions"))
                or (request.url.path.startswith("/api/registry/services/") and request.method == "DELETE"))
    if (critical and request.method not in ("GET", "HEAD", "OPTIONS")
            and (session.reauthenticated_at is None or session.reauthenticated_at < now() - timedelta(minutes=5))):
        raise HTTPException(428, "请重新验证密码后执行敏感操作")
    return user, session


def api_key(request, db):
    token = request.headers.get("X-Gateway-Key", "")
    if not token or len(token) > 200:
        return None
    key = db.scalar(select(ApiKey).where(ApiKey.token_hash == digest(token)))
    return key if key and not key.revoked and key.expires_at > now() else None
