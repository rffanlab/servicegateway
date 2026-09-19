"""Authenticated account operations: no public client-key download link."""
import base64
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import Field
from sqlalchemy import delete, select
from .db import Audit, LoginSession, User
from .schemas import Strict
from .security import principal, verify, ph


class PasswordChange(Strict):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)
    confirm_password: str = Field(min_length=12, max_length=256)


class CertificateDownload(Strict):
    current_password: str = Field(min_length=1, max_length=256)


def routes(sessions, agent, limiter, settings):
    router = APIRouter(prefix='/api/account', tags=['account'])

    def verify_current(db, request, password, role='viewer'):
        user, _ = principal(request, db, role)
        limiter.check('account:' + str(user.id))
        # Serialize password writes with logins so a concurrent old-password login
        # cannot create a surviving session after revocation.
        user = db.scalar(select(User).where(User.id == user.id).with_for_update().execution_options(populate_existing=True))
        if not user or not user.enabled or not verify(password, user.password_hash):
            db.add(Audit(actor='account', action='password.verify', target='self', outcome='failed', detail=''))
            db.commit()
            raise HTTPException(403, '当前密码不正确')
        return user

    @router.post('/password')
    def change_password(body: PasswordChange, request: Request, response: Response):
        with sessions.begin() as db:
            user = verify_current(db, request, body.current_password)
            if body.new_password != body.confirm_password:
                raise HTTPException(422, '两次新密码不一致')
            if verify(body.new_password, user.password_hash):
                raise HTTPException(422, '新密码不能与旧密码相同')
            user.password_hash = ph.hash(body.new_password)
            db.execute(delete(LoginSession).where(LoginSession.user_id == user.id))
            db.add(Audit(actor=user.username, action='password.change', target=user.username,
                         outcome='success', detail='All account sessions revoked; API keys unchanged'))
        response.delete_cookie(settings.cookie_name, path='/', domain=settings.cookie_domain)
        return {'ok': True, 'login_required': True, 'notice': '密码已更新，全部会话已退出，请重新登录。API Key 和客户端证书未改变。'}

    @router.get('/security')
    def security_status(request: Request):
        with sessions() as db:
            user, _ = principal(request, db)
            result = {'username': user.username, 'role': user.role, 'client_bundle_role': 'admin'}
            if user.role == 'admin':
                result['pki'] = agent.call('pki-status')
            return result

    @router.post('/client-certificate')
    def download(body: CertificateDownload, request: Request):
        with sessions.begin() as db:
            user = verify_current(db, request, body.current_password, 'admin')
            actor = user.username
            # Audit intent even if transfer or Agent call later fails.
            db.add(Audit(actor=actor, action='client-certificate.download', target='admin-browser', outcome='started', detail='Encrypted P12 only'))
        try:
            payload = agent.call('client-bundle')
            encoded = payload['base64']
            if not isinstance(encoded, str) or len(encoded) > 350000:
                raise ValueError('Invalid bundle response')
            data = base64.b64decode(encoded, validate=True)
            if not 0 < len(data) <= 256 * 1024:
                raise ValueError('Invalid bundle size')
        except Exception:
            with sessions.begin() as db:
                db.add(Audit(actor=actor, action='client-certificate.download', target='admin-browser', outcome='failed', detail=''))
            raise HTTPException(503, '客户端证书包暂不可用，请检查本机证书初始化和 Agent 状态') from None
        with sessions.begin() as db:
            db.add(Audit(actor=actor, action='client-certificate.download', target='admin-browser', outcome='success', detail='Encrypted P12 response prepared'))
        return Response(data, media_type='application/x-pkcs12', headers={
            'Content-Disposition': 'attachment; filename="admin-browser.p12"',
            'Cache-Control': 'no-store, private', 'Pragma': 'no-cache', 'X-Content-Type-Options': 'nosniff'})

    return router
