"""Per-service business users, WeChat login and opaque user-token introspection."""
from datetime import timedelta
import re
import secrets
import uuid

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import Field
from sqlalchemy import delete, select

from .db import Audit, BusinessSession, BusinessUser, GatewayState, Release, Service, WechatIdentity, now
from .schemas import Strict
from .security import digest, principal

TOKEN_RE = re.compile(r'^sgu_[A-Za-z0-9_-]{40,120}$')
ROLE_RE = r'^[a-z][a-z0-9_-]{0,31}$'


class WechatLoginBody(Strict):
    code: str = Field(min_length=1, max_length=256, pattern=r'^[A-Za-z0-9_-]+$')


class UserPatch(Strict):
    display_name: str = Field(default='', max_length=100)
    role: str = Field(default='user', pattern=ROLE_RE)
    enabled: bool = True
    remark: str = Field(default='', max_length=300)


class IntrospectBody(Strict):
    service_id: str = Field(pattern=r'^[a-z][a-z0-9-]{0,62}$')
    token: str = Field(min_length=44, max_length=128, pattern=r'^sgu_[A-Za-z0-9_-]+$')


def _bearer(request: Request):
    values = request.headers.getlist('authorization')
    if len(values) != 1:
        raise HTTPException(401, '需要唯一的 Bearer 用户 Token')
    value = values[0]
    if not value.startswith('Bearer '):
        raise HTTPException(401, '需要 Bearer 用户 Token')
    token = value[7:]
    if not TOKEN_RE.fullmatch(token):
        raise HTTPException(401, '用户 Token 无效')
    return token


def _identity(db, user_id, service_id):
    return db.scalar(select(WechatIdentity).where(
        WechatIdentity.user_id == user_id,
        WechatIdentity.service_id == service_id,
    ).order_by(WechatIdentity.id.desc()).limit(1))


def _user_view(db, user, include_identity=True):
    result = {
        'id': user.id,
        'service_id': user.service_id,
        'role': user.role,
        'display_name': user.display_name,
        'remark': user.remark,
        'enabled': user.enabled,
        'created_at': user.created_at.isoformat() + 'Z',
        'last_login_at': user.last_login_at.isoformat() + 'Z' if user.last_login_at else None,
    }
    if include_identity:
        identity = _identity(db, user.id, user.service_id)
        result['wechat'] = ({
            'appid': identity.appid,
            'openid': identity.openid,
            'unionid': identity.unionid,
            'last_login_at': identity.last_login_at.isoformat() + 'Z',
        } if identity else None)
    return result


def _resolve_token(db, token, service_id=None, touch=True):
    row = db.get(BusinessSession, digest(token))
    if not row or row.expires_at <= now():
        raise HTTPException(401, '用户 Token 已过期或无效')
    if service_id and row.service_id != service_id:
        raise HTTPException(403, '用户 Token 不属于该服务')
    user = db.get(BusinessUser, row.user_id)
    if not user or not user.enabled or user.service_id != row.service_id:
        raise HTTPException(403, '业务用户已停用或服务不匹配')
    identity = _identity(db, user.id, user.service_id)
    if not identity:
        raise HTTPException(403, '业务用户缺少微信身份')
    if touch and row.last_seen_at < now() - timedelta(seconds=60):
        row.last_seen_at = now()
    return user, identity, row


def _published_service(request, db, settings):
    if not secrets.compare_digest(request.headers.get('X-SG-Secret', ''), settings.auth_secret()):
        raise HTTPException(403, 'Forbidden')
    service_id = request.headers.get('X-SG-Service', '')
    host = request.headers.get('X-SG-Business-Host', '')
    live_digest = request.headers.get('X-SG-Digest', '')
    state = db.get(GatewayState, 1)
    release = db.get(Release, state.active_release) if state and state.active_release else None
    if not release or live_digest != release.digest:
        raise HTTPException(403, 'Stale gateway configuration')
    route = next((r for r in release.snapshot.get('routes', [])
                  if r.get('enabled') and r.get('service_id') == service_id
                  and r.get('host') == host and r.get('auth') == 'wechat_user'), None)
    if not route:
        raise HTTPException(403, 'WeChat login is not published for this service host')
    return service_id


def gateway_identity(db, request: Request, service_id: str):
    user, identity, _ = _resolve_token(db, _bearer(request), service_id)
    return user, identity



def routes(sessions, agent, limiter, settings):
    router = APIRouter()

    @router.post('/internal/wechat/login')
    def wechat_login(body: WechatLoginBody, request: Request):
        with sessions.begin() as db:
            service_id = _published_service(request, db, settings)
            if not db.get(Service, service_id):
                raise HTTPException(409, '业务服务未登记')
        peer = request.headers.get('X-SG-Client-IP', 'unknown')[:64]
        limiter.check('wechat:' + service_id + ':' + peer)
        identity_data = agent.call('wechat-login', service_id=service_id, code=body.code)

        token = 'sgu_' + secrets.token_urlsafe(32)
        created = False
        with sessions.begin() as db:
            identity = db.scalar(select(WechatIdentity).where(
                WechatIdentity.service_id == service_id,
                WechatIdentity.appid == identity_data['appid'],
                WechatIdentity.openid == identity_data['openid'],
            ).with_for_update())
            if identity:
                user = db.get(BusinessUser, identity.user_id)
                if not user or not user.enabled:
                    raise HTTPException(403, '业务用户已停用')
                if identity.unionid and identity_data.get('unionid') and identity.unionid != identity_data['unionid']:
                    raise HTTPException(409, '微信身份发生冲突，请管理员核对')
                if not identity.unionid and identity_data.get('unionid'):
                    identity.unionid = identity_data['unionid']
            else:
                user = BusinessUser(id=uuid.uuid4().hex, service_id=service_id, role='user',
                                    display_name='', remark='', enabled=True,
                                    created_at=now(), last_login_at=now())
                db.add(user)
                identity = WechatIdentity(user_id=user.id, service_id=service_id,
                                          appid=identity_data['appid'], openid=identity_data['openid'],
                                          unionid=identity_data.get('unionid'),
                                          created_at=now(), last_login_at=now())
                db.add(identity)
                created = True
            user.last_login_at = now()
            identity.last_login_at = now()
            # Keep at most 20 live sessions per user; never log or return their hashes.
            old = list(db.scalars(select(BusinessSession).where(
                BusinessSession.user_id == user.id
            ).order_by(BusinessSession.created_at.desc())))
            for stale in old[19:]:
                db.delete(stale)
            db.add(BusinessSession(token_hash=digest(token), user_id=user.id, service_id=service_id,
                                   created_at=now(), last_seen_at=now(),
                                   expires_at=now() + timedelta(hours=settings.business_session_hours)))
            db.add(Audit(actor='business:' + user.id, action='wechat.login',
                         target=service_id, outcome='created' if created else 'success',
                         detail='openid/session_key/token not logged'))
            user_data = _user_view(db, user)
        return {
            'access_token': token,
            'token_type': 'Bearer',
            'expires_in': settings.business_session_hours * 3600,
            'user': user_data,
        }

    @router.get('/internal/wechat/userinfo')
    def wechat_userinfo(request: Request):
        with sessions.begin() as db:
            service_id = _published_service(request, db, settings)
            user, _, _ = _resolve_token(db, _bearer(request), service_id)
            return _user_view(db, user)

    @router.post('/internal/business-users/introspect')
    def introspect(body: IntrospectBody, request: Request):
        # This endpoint is never exposed by Nginx.  A local service that already
        # possesses the opaque bearer token can resolve it without learning the
        # gateway management secret.
        if not request.client or request.client.host not in ('127.0.0.1', '::1', 'testclient'):
            raise HTTPException(403, 'Token introspection is loopback-only')
        with sessions.begin() as db:
            user, _, session = _resolve_token(db, body.token, body.service_id)
            result = _user_view(db, user)
            result['token'] = {'active': True, 'expires_at': session.expires_at.isoformat() + 'Z'}
            return result

    @router.get('/api/business-users')
    def list_users(request: Request, service_id: str):
        with sessions() as db:
            principal(request, db, 'admin')
            if not db.get(Service, service_id):
                raise HTTPException(404, '服务不存在')
            rows = list(db.scalars(select(BusinessUser).where(
                BusinessUser.service_id == service_id
            ).order_by(BusinessUser.created_at.desc()).limit(1000)))
            return [_user_view(db, row) for row in rows]

    @router.patch('/api/business-users/{user_id}')
    def update_user(user_id: str, body: UserPatch, request: Request):
        with sessions.begin() as db:
            actor = principal(request, db, 'admin')[0].username
            user = db.get(BusinessUser, user_id)
            if not user:
                raise HTTPException(404, '业务用户不存在')
            user.display_name, user.role = body.display_name, body.role
            user.enabled, user.remark = body.enabled, body.remark
            if not body.enabled:
                db.execute(delete(BusinessSession).where(BusinessSession.user_id == user.id))
            db.add(Audit(actor=actor, action='business-user.update', target=user.id,
                         outcome='success', detail=f'service={user.service_id}; enabled={body.enabled}; role={body.role}'))
            return _user_view(db, user)

    @router.post('/api/business-users/{user_id}/revoke-sessions')
    def revoke_sessions(user_id: str, request: Request):
        with sessions.begin() as db:
            actor = principal(request, db, 'admin')[0].username
            user = db.get(BusinessUser, user_id)
            if not user:
                raise HTTPException(404, '业务用户不存在')
            db.execute(delete(BusinessSession).where(BusinessSession.user_id == user.id))
            db.add(Audit(actor=actor, action='business-user.revoke-sessions',
                         target=user.id, outcome='success', detail=''))
        return {'ok': True}

    @router.get('/api/business-auth/wechat/{service_id}')
    def wechat_status(service_id: str, request: Request):
        with sessions() as db:
            principal(request, db, 'admin')
            if not db.get(Service, service_id):
                raise HTTPException(404, '服务不存在')
        return agent.call('wechat-status', service_id=service_id)

    return router
