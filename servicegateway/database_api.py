"""Admin-only business provisioning, never a general SQL endpoint."""
from fastapi import APIRouter, HTTPException, Request, Response
from sqlalchemy import select
from .db import Audit, Service, User
from .business_databases import DatabaseRequest, CredentialRequest, env_file
from .security import principal, verify


def routes(sessions, agent, limiter):
    router = APIRouter(prefix='/api/databases', tags=['business databases'])

    def event(actor, action, target, outcome):
        with sessions.begin() as db:
            db.add(Audit(actor=actor, action=action, target=target[:80], outcome=outcome,
                         detail='Local business database operation; no SQL or credentials logged'))

    @router.get('')
    def overview(request: Request):
        with sessions() as db:
            principal(request, db, 'admin')
        return agent.call('database-status')

    @router.post('')
    def create(body: DatabaseRequest, request: Request):
        with sessions() as db:
            user, _ = principal(request, db, 'admin')
            if not db.get(Service, body.service_id):
                raise HTTPException(409, '先登记本机业务服务，再创建其数据库')
            actor = user.username
            limiter.check('database:' + str(user.id))
        event(actor, 'database.create', body.service_id, 'started')
        try:
            result = agent.call('database-create', spec=body.model_dump())
        except Exception:
            event(actor, 'database.create', body.service_id, 'failed')
            raise
        event(actor, 'database.create', body.service_id, 'success')
        return result

    @router.post('/{service_id}/credentials')
    def download(service_id: str, body: CredentialRequest, request: Request):
        with sessions.begin() as db:
            user, _ = principal(request, db, 'admin')
            limiter.check('db-credentials:' + str(user.id))
            user = db.scalar(select(User).where(User.id == user.id).with_for_update().execution_options(populate_existing=True))
            if not user or not user.enabled or not verify(body.current_password, user.password_hash):
                raise HTTPException(403, '当前网站登录密码不正确')
            actor = user.username
            db.add(Audit(actor=actor, action='database.credentials', target=service_id[:80],
                         outcome='started', detail=body.account))
        try:
            result = agent.call('database-credentials', service_id=service_id, account=body.account)
            content = env_file(result)
        except Exception:
            event(actor, 'database.credentials', service_id, 'failed')
            raise
        event(actor, 'database.credentials', service_id, 'success')
        return Response(content, media_type='text/plain', headers={
            'Content-Disposition': f'attachment; filename="database-{body.account}.env"',
            'Cache-Control': 'no-store, private', 'Pragma': 'no-cache',
            'X-Content-Type-Options': 'nosniff'})

    return router
