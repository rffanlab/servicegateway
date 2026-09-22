"""Management-only HTTP boundary: bounded bodies, fixed origins and generic errors."""
import asyncio
from urllib.parse import urlsplit
from fastapi.exceptions import RequestValidationError
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy.exc import SQLAlchemyError

MAX_BODY = 2 * 1024 * 1024


class Boundary:
    def __init__(self, app, settings, sessions):
        self.app, self.settings, self.sessions = app, settings, sessions

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        headers = Headers(scope=scope)
        method, path = scope['method'], scope['path']
        status = 500

        async def record_send(message):
            nonlocal status
            if message['type'] == 'http.response.start':
                status = message['status']
            await send(message)

        async def reject(code, message):
            await JSONResponse({'detail': message}, status_code=code)(scope, receive, record_send)

        def audit_denial():
            from .db import Audit
            try:
                with self.sessions.begin() as db:
                    db.add(Audit(actor='boundary', action='api.denied', target='management',
                                 outcome=str(status), detail='No request headers, body or query logged'))
            except SQLAlchemyError:
                # The original denial remains a denial during a DB outage.
                pass

        try:
            for name in ('host', 'cookie', 'authorization', 'x-gateway-key', 'x-csrf-token', 'x-sg-secret', 'x-sg-digest', 'x-sg-route', 'x-sg-upstream-token', 'x-sg-service', 'x-sg-business-host', 'x-sg-client-ip', 'x-sg-client-verify'):
                if len(headers.getlist(name)) > 1:
                    return await reject(400, 'Ambiguous authentication or host headers')
            cookie_names = [v.strip().split('=', 1)[0] for v in headers.get('cookie', '').split(';')]
            if cookie_names.count(self.settings.cookie_name) > 1:
                return await reject(400, 'Ambiguous management session')
            if path.startswith('/api/') and method not in ('GET', 'HEAD', 'OPTIONS'):
                configured = self.settings.public_origin.rstrip('/')
                expected = configured if self.settings.deployment_mode == 'remote' else f"{scope['scheme']}://{headers.get('host', '')}"
                origin = headers.get('origin')
                fetch_site = headers.get('sec-fetch-site')
                if origin and origin != expected:
                    return await reject(403, 'Cross-origin management write rejected')
                if fetch_site in ('cross-site', 'same-site') or (fetch_site and not origin):
                    return await reject(403, 'A same-origin browser request is required')
            if method not in ('GET', 'HEAD', 'OPTIONS'):
                length = headers.get('content-length')
                if length is not None:
                    if not length.isdigit():
                        return await reject(400, 'Invalid Content-Length')
                    if int(length) > MAX_BODY:
                        return await reject(413, 'Management body exceeds 2 MiB')
                # Buffer only the small management request, never business traffic.
                chunks, total = [], 0
                while True:
                    message = await receive()
                    if message['type'] == 'http.disconnect':
                        return
                    part = message.get('body', b'')
                    total += len(part)
                    if total > MAX_BODY:
                        return await reject(413, 'Management body exceeds 2 MiB')
                    chunks.append(part)
                    if not message.get('more_body', False):
                        break
                if total and headers.get('content-type', '').split(';')[0].strip() != 'application/json':
                    return await reject(415, 'Management requests require application/json')
                delivered = False

                async def bounded_receive():
                    nonlocal delivered
                    if not delivered:
                        delivered = True
                        return {'type': 'http.request', 'body': b''.join(chunks), 'more_body': False}
                    return await receive()
                await self.app(scope, bounded_receive, record_send)
            else:
                await self.app(scope, receive, record_send)
        finally:
            if path.startswith('/api/') and status >= 400:
                await asyncio.to_thread(audit_denial)


def install_boundary(app, settings):
    app.add_middleware(Boundary, settings=settings, sessions=app.state.sessions)
    hosts = ['127.0.0.1', 'localhost', urlsplit(settings.public_origin).hostname]
    if settings.testing:
        hosts.append('testserver')
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts, www_redirect=False)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse({'detail': [{'loc': e['loc'], 'type': e['type'], 'msg': e['msg']}
                                        for e in exc.errors()]}, status_code=422)

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request, exc):
        return JSONResponse({'detail': 'Database unavailable; request not authorized or completed'}, status_code=503)
