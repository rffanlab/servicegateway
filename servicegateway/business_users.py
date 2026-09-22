"""Service-scoped end-user identities and WeChat Mini Program login.

These users are separate from ServiceGateway management users. Business tokens are
opaque, hashed at rest, service-scoped, and accepted only by routes explicitly
configured with auth=wechat.
"""
from datetime import timedelta
import ipaddress
import re
import secrets
import uuid

from fastapi import APIRouter, HTTPException, Request
from pydantic import Field, model_validator
from sqlalchemy import delete, select

from .db import Audit, BusinessAccessToken, BusinessUser, GatewayState, Release, Service, WechatIdentity, now
from .schemas import ID, Strict
from .security import digest, principal

TOKEN_PREFIX = "sgu_"
ROLE_RE = r"^[a-z][a-z0-9_-]{0,31}$"


class WechatLoginBody(Strict):
    code: str = Field(min_length=1, max_length=256)


class BusinessUserPatch(Strict):
    enabled: bool | None = None
    role: str | None = Field(default=None, pattern=ROLE_RE)
    display_name: str | None = Field(default=None, max_length=100)
    avatar_url: str | None = Field(default=None, max_length=500)
    remark: str | None = Field(default=None, max_length=300)

    @model_validator(mode="after")
    def not_empty(self):
        if all(getattr(self, name) is None for name in ("enabled", "role", "display_name", "avatar_url", "remark")):
            raise ValueError("At least one field is required")
        return self


def _bearer(request):
    value = request.headers.get("Authorization", "")
    if not value.startswith("Bearer "):
        return ""
    token = value[7:].strip()
    if not token.startswith(TOKEN_PREFIX) or not 20 <= len(token) <= 200:
        return ""
    return token


def _identity(db, user_id, service_id):
    return db.scalar(select(WechatIdentity).where(
        WechatIdentity.user_id == user_id,
        WechatIdentity.service_id == service_id,
    ).order_by(WechatIdentity.id).limit(1))


def _payload(db, user, token_row=None, admin=False):
    identity = _identity(db, user.id, user.service_id)
    data = {
        "user_id": user.id,
        "service_id": user.service_id,
        "role": user.role,
        "enabled": user.enabled,
        "display_name": user.display_name,
        "avatar_url": user.avatar_url,
        "openid": identity.openid if identity else None,
        "unionid": identity.unionid if identity else None,
        "appid": identity.appid if identity else None,
        "created_at": user.created_at.isoformat() + "Z",
        "last_login_at": user.last_login_at.isoformat() + "Z" if user.last_login_at else None,
        "token_expires_at": token_row.expires_at.isoformat() + "Z" if token_row else None,
    }
    if admin:
        data["remark"] = user.remark
    return data


def authenticate_token(db, request_or_token, service_id, roles=None):
    token = _bearer(request_or_token) if hasattr(request_or_token, "headers") else request_or_token
    if not token:
        raise HTTPException(401, "WeChat login required")
    row = db.get(BusinessAccessToken, digest(token))
    user = db.get(BusinessUser, row.user_id) if row and not row.revoked and row.expires_at > now() else None
    if not row or row.service_id != service_id or not user or user.service_id != service_id or not user.enabled:
        raise HTTPException(401, "Business user token is invalid or expired")
    roles = roles or []
    if roles and user.role not in roles:
        raise HTTPException(403, "Business user role is not permitted on this route")
    return user, row, _identity(db, user.id, service_id)


def _check_active_service(request, db, settings, service_id):
    if not secrets.compare_digest(request.headers.get("X-SG-Secret", ""), settings.auth_secret()):
        raise HTTPException(403, "Forbidden")
    state = db.get(GatewayState, 1)
    release = db.get(Release, state.active_release) if state and state.active_release else None
    if not release or request.headers.get("X-SG-Digest", "") != release.digest:
        raise HTTPException(403, "Stale gateway configuration")
    host = request.headers.get("X-SG-Business-Host", "")
    route = next((r for r in release.snapshot.get("routes", [])
                  if r.get("enabled") and r.get("service_id") == service_id
                  and r.get("host") == host and r.get("auth") == "wechat"), None)
    if not route:
        raise HTTPException(403, "WeChat login is not published for this service host")
    return release


def _route_for_introspection(db, route_id):
    state = db.get(GatewayState, 1)
    release = db.get(Release, state.active_release) if state and state.active_release else None
    if not release:
        raise HTTPException(403, "No active release")
    route = next((r for r in release.snapshot.get("routes", [])
                  if r.get("id") == route_id and r.get("enabled")), None)
    if not route or (route.get("upstream_auth") or {}).get("mode") != "route_secret":
        raise HTTPException(403, "Route is not authorized for user introspection")
    return route


def routes(sessions, agent, limiter, settings):
    router = APIRouter(tags=["business users"])

    @router.get("/api/business-users")
    def list_users(request: Request, service_id: str | None = None, limit: int = 100):
        if not 1 <= limit <= 500:
            raise HTTPException(422, "limit must be 1..500")
        with sessions() as db:
            principal(request, db, "admin")
            query = select(BusinessUser).order_by(BusinessUser.created_at.desc()).limit(limit)
            if service_id:
                if not re.fullmatch(ID, service_id):
                    raise HTTPException(422, "Invalid service id")
                query = query.where(BusinessUser.service_id == service_id)
            return [_payload(db, user, admin=True) for user in db.scalars(query)]

    @router.get("/api/business-users/wechat-status/{service_id}")
    def wechat_status(service_id: str, request: Request):
        with sessions() as db:
            principal(request, db, "admin")
            if not db.get(Service, service_id):
                raise HTTPException(404, "服务不存在")
        return agent.call("wechat-config-status", service_id=service_id)

    @router.patch("/api/business-users/{user_id}")
    def patch_user(user_id: str, body: BusinessUserPatch, request: Request):
        with sessions.begin() as db:
            actor = principal(request, db, "admin")[0].username
            user = db.get(BusinessUser, user_id)
            if not user:
                raise HTTPException(404, "业务用户不存在")
            for name, value in body.model_dump(exclude_none=True).items():
                setattr(user, name, value)
            if body.enabled is False:
                db.execute(delete(BusinessAccessToken).where(BusinessAccessToken.user_id == user.id))
            db.add(Audit(actor=actor, action="business_user.update", target=user.id,
                         outcome="success", detail=f"service={user.service_id}; tokens revoked={body.enabled is False}"))
            return _payload(db, user, admin=True)

    @router.post("/api/business-users/{user_id}/revoke-tokens")
    def revoke_tokens(user_id: str, request: Request):
        with sessions.begin() as db:
            actor = principal(request, db, "admin")[0].username
            user = db.get(BusinessUser, user_id)
            if not user:
                raise HTTPException(404, "业务用户不存在")
            result = db.execute(delete(BusinessAccessToken).where(BusinessAccessToken.user_id == user.id))
            db.add(Audit(actor=actor, action="business_user.revoke_tokens", target=user.id,
                         outcome="success", detail=f"service={user.service_id}; revoked={result.rowcount or 0}"))
            return {"ok": True, "revoked": result.rowcount or 0}

    @router.post("/internal/wechat/login/{service_id}")
    def wechat_login(service_id: str, body: WechatLoginBody, request: Request):
        client_ip = request.headers.get("X-SG-Client-IP", "")
        try:
            ipaddress.ip_address(client_ip)
        except ValueError:
            client_ip = "unknown"
        limiter.check("wechat:" + service_id + ":" + client_ip)
        with sessions() as db:
            _check_active_service(request, db, settings, service_id)
        identity_data = agent.call("wechat-code2session", service_id=service_id, code=body.code)
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        with sessions.begin() as db:
            _check_active_service(request, db, settings, service_id)
            identity = db.scalar(select(WechatIdentity).where(
                WechatIdentity.service_id == service_id,
                WechatIdentity.appid == identity_data["appid"],
                WechatIdentity.openid == identity_data["openid"],
            ).with_for_update())
            if identity:
                user = db.get(BusinessUser, identity.user_id)
                if identity.unionid and identity_data.get("unionid") and identity.unionid != identity_data["unionid"]:
                    raise HTTPException(409, "WeChat identity changed unexpectedly")
                if not identity.unionid and identity_data.get("unionid"):
                    identity.unionid = identity_data["unionid"]
            else:
                user = BusinessUser(id=uuid.uuid4().hex, service_id=service_id, role="user",
                                    enabled=True, display_name="", avatar_url="", remark="")
                db.add(user)
                db.flush()
                identity = WechatIdentity(service_id=service_id, user_id=user.id,
                                          appid=identity_data["appid"], openid=identity_data["openid"],
                                          unionid=identity_data.get("unionid"))
                db.add(identity)
            if not user or not user.enabled:
                raise HTTPException(403, "业务用户已停用")
            user.last_login_at = now()
            db.execute(delete(BusinessAccessToken).where(
                BusinessAccessToken.user_id == user.id,
                BusinessAccessToken.expires_at <= now(),
            ))
            expires = now() + timedelta(days=settings.business_token_days)
            db.add(BusinessAccessToken(token_hash=digest(token), service_id=service_id, user_id=user.id,
                                       created_at=now(), last_seen_at=now(), expires_at=expires, revoked=False))
            db.add(Audit(actor="wechat:" + user.id, action="business_user.login", target=user.id,
                         outcome="success", detail=f"service={service_id}"))
            data = _payload(db, user)
        return {"access_token": token, "token_type": "Bearer",
                "expires_in": settings.business_token_days * 86400, "user": data}

    @router.get("/internal/wechat/me/{service_id}")
    def wechat_me(service_id: str, request: Request):
        with sessions() as db:
            _check_active_service(request, db, settings, service_id)
            user, token_row, _ = authenticate_token(db, request, service_id)
            return _payload(db, user, token_row)

    @router.post("/internal/wechat/logout/{service_id}")
    def wechat_logout(service_id: str, request: Request):
        token = _bearer(request)
        with sessions.begin() as db:
            _check_active_service(request, db, settings, service_id)
            user, token_row, _ = authenticate_token(db, token, service_id)
            token_row.revoked = True
            db.add(Audit(actor="wechat:" + user.id, action="business_user.logout", target=user.id,
                         outcome="success", detail=f"service={service_id}"))
        return {"ok": True}

    @router.post("/internal/business-users/introspect")
    def introspect(request: Request):
        if (not request.client or (request.client.host not in ("127.0.0.1", "::1")
                                   and not (settings.testing and request.client.host == "testclient"))):
            raise HTTPException(403, "User introspection is loopback-only")
        route_id = request.headers.get("X-SG-Route", "")
        route_secret = request.headers.get("X-SG-Upstream-Token", "")
        if not route_id or not route_secret:
            raise HTTPException(401, "Route identity is required")
        proof = agent.call("route-secret-check", route_id=route_id, token=route_secret)
        with sessions() as db:
            route = _route_for_introspection(db, route_id)
            if proof.get("service_id") != route.get("service_id"):
                raise HTTPException(403, "Route identity does not match active service")
            user, token_row, _ = authenticate_token(db, request, route["service_id"])
            return _payload(db, user, token_row)

    return router
