import asyncio
import contextlib
from contextlib import asynccontextmanager
from datetime import timedelta
import logging
from pathlib import Path
import secrets
import threading
import time
import uuid
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import Field
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError
import httpx
from .config import Settings
from .db import ApiKey, Audit, GatewayState, Health, LoginSession, Release, Route, Service, User, database, now
from .ipc import AgentClient, AgentError
from .schemas import ActionRequest, KeyRequest, PublishRequest, RouteSpec, ServiceSpec, Snapshot, Strict
from .security import DUMMY_HASH, LoginLimiter, api_key, digest, ph, principal, verify

log = logging.getLogger("servicegateway")


class LoginBody(Strict):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=1, max_length=256)


class ReauthBody(Strict):
    password: str = Field(min_length=1, max_length=256)


class UserBody(LoginBody):
    role: str = Field(default="viewer", pattern=r"^(admin|operator|viewer)$")


class ImportBody(Strict):
    services: list[ServiceSpec] = Field(max_length=200)
    apply: bool = False
    revision: int | None = None


def audit(db, actor, action, target, outcome="success", detail=""):
    db.add(Audit(actor=actor, action=action, target=target, outcome=outcome, detail=detail[:500]))


def state_lock(db):
    state = db.scalar(select(GatewayState).where(GatewayState.id == 1).with_for_update())
    if not state:
        raise HTTPException(503, "数据库尚未迁移；请运行 alembic upgrade head")
    return state


def snapshot(db):
    return Snapshot(services=[ServiceSpec.model_validate(s.spec) for s in db.scalars(select(Service).order_by(Service.id))], routes=[RouteSpec.model_validate(r.spec) for r in db.scalars(select(Route).order_by(Route.id))])


def release_view(row):
    return {"id": row.id, "digest": row.digest, "revision": row.revision, "status": row.status, "note": row.note, "error": row.error, "created_at": row.created_at.isoformat() + "Z"}


def create_app(settings=None, agent=None):
    settings = settings or Settings()
    engine, sessions = database(settings)
    agent = agent or AgentClient(settings.agent_socket)
    limiter = LoginLimiter()
    publish_lock = threading.Lock()

    def check_health(spec):
        try:
            data = agent.call("service", spec=spec, operation="status")
        except AgentError as exc:
            data = {"state": "unknown", "startup": "unknown", "units": [], "detail": type(exc).__name__}
        try:
            # Validate every health target through the root broker first; no arbitrary DB URL fetch.
            if data["state"] == "unknown":
                raise AgentError("Target has not been approved")
            started = time.monotonic()
            with httpx.Client(timeout=3, follow_redirects=False, trust_env=False) as client:
                with client.stream("GET", spec["health_url"]) as resp:
                    healthy = resp.status_code == 200
            data.update(healthy=healthy, latency_ms=int((time.monotonic() - started) * 1000), detail="" if healthy else "健康接口未返回 200")
        except Exception as exc:
            data.update(healthy=False if data["state"] != "unknown" else None, latency_ms=None, detail=type(exc).__name__)
        with sessions.begin() as db:
            health = db.get(Health, spec["id"])
            if not health:
                health = Health(service_id=spec["id"])
                db.add(health)
            for key, value in data.items():
                setattr(health, key, value)
            health.checked_at = now()
        return data

    def reconcile():
        with sessions.begin() as db:
            state = state_lock(db)
            if not state.pending_release:
                return
            pending = db.get(Release, state.pending_release)
            identity = agent.call("status")
            live = identity["digest"]
            active = db.get(Release, state.active_release) if state.active_release else None
            baseline = active.digest if active else Snapshot().digest()
            if live == pending.digest and identity.get("generation") == pending.id:
                if active:
                    active.status = "superseded"
                state.active_release = pending.id
                pending.status = "active"
            elif live == baseline:
                pending.status = "failed"
                pending.error = "发布中断，已确认仍为上一版本；可重新发布"
            else:
                raise AgentError("Live configuration is unknown; local inspection is required")
            state.pending_release = None
            audit(db, "system", "release.reconcile", pending.id, pending.status)

    async def monitor():
        while True:
            try:
                with sessions() as db:
                    specs = [s.spec for s in db.scalars(select(Service))]
                semaphore = asyncio.Semaphore(4)
                async def one(spec):
                    async with semaphore:
                        await asyncio.to_thread(check_health, spec)
                await asyncio.gather(*(one(s) for s in specs))
                with sessions.begin() as db:
                    db.execute(delete(LoginSession).where(LoginSession.expires_at < now()))
            except Exception as exc:
                log.warning("Health sweep failed: %s", type(exc).__name__)
            await asyncio.sleep(settings.health_interval)

    @asynccontextmanager
    async def lifespan(app):
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        with sessions() as db:
            if db.get(GatewayState, 1) is None:
                raise RuntimeError("Run alembic upgrade head before starting")
        try:
            await asyncio.to_thread(reconcile)
        except AgentError:
            log.warning("Agent/release reconciliation pending; existing edge config is unchanged")
        task = asyncio.create_task(monitor()) if settings.monitor_enabled else None
        yield
        if task:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        engine.dispose()

    app = FastAPI(title="ServiceGateway", version="0.1.0", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.engine, app.state.sessions, app.state.agent = engine, sessions, agent
    app.state.settings = settings
    from .account import routes as account_routes
    app.include_router(account_routes(sessions, agent, limiter, settings))
    from .boundary import install_boundary
    install_boundary(app, settings)

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        if request.url.path.startswith(("/api", "/internal")):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(AgentError)
    async def agent_error(request, exc):
        return JSONResponse({"detail": str(exc)[:500]}, status_code=503)

    @app.exception_handler(IntegrityError)
    async def conflict(request, exc):
        return JSONResponse({"detail": "记录重复或仍被引用，请刷新后重试"}, status_code=409)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "version": "0.1.0"}

    @app.get("/readyz")
    def readyz():
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ready"}

    @app.post("/api/auth/login")
    def login(body: LoginBody, request: Request, response: Response):
        limiter.check(request.client.host if request.client else "unknown")
        with sessions.begin() as db:
            user = db.scalar(select(User).where(User.username == body.username.lower()).with_for_update())
            valid = verify(body.password, user.password_hash if user else DUMMY_HASH)
            if not valid or not user or not user.enabled:
                audit(db, "anonymous", "login", "account", "failed")
                # Commit failure audit before returning a uniform error.
                db.commit()
                raise HTTPException(401, "用户名或密码错误")
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            old = request.cookies.get(settings.cookie_name)
            if old:
                db.execute(delete(LoginSession).where(LoginSession.token_hash == digest(old)))
            db.add(LoginSession(token_hash=digest(token), user_id=user.id, csrf=csrf, expires_at=now() + timedelta(hours=settings.session_hours)))
            audit(db, user.username, "login", "session")
            response.set_cookie(settings.cookie_name, token, max_age=settings.session_hours * 3600, httponly=True, secure=settings.secure_cookie, samesite="strict", path="/", domain=settings.cookie_domain)
            return {"username": user.username, "role": user.role, "csrf": csrf}

    @app.post("/api/auth/reauth")
    def reauth(body: ReauthBody, request: Request):
        with sessions.begin() as db:
            user, session = principal(request, db)
            limiter.check("reauth:" + str(user.id))
            if not verify(body.password, user.password_hash):
                audit(db, user.username, "session.reauth", "session", "failed")
                db.commit()
                raise HTTPException(401, "密码校验失败")
            session.reauthenticated_at = now()
            audit(db, user.username, "session.reauth", "session")
            return {"ok": True}

    @app.get("/api/auth/me")
    def me(request: Request):
        with sessions() as db:
            user, session = principal(request, db)
            return {"username": user.username, "role": user.role, "csrf": session.csrf}

    @app.post("/api/auth/logout")
    def logout(request: Request, response: Response):
        with sessions.begin() as db:
            user, session = principal(request, db)
            db.delete(session)
            audit(db, user.username, "logout", "session")
        response.delete_cookie(settings.cookie_name, path="/", domain=settings.cookie_domain)
        return {"ok": True}

    @app.get("/api/schema")
    def schema(request: Request):
        with sessions() as db:
            principal(request, db)
        return app.openapi()

    @app.get("/api/overview")
    def overview(request: Request):
        with sessions() as db:
            principal(request, db)
            state = db.get(GatewayState, 1)
            assets = []
            for service in db.scalars(select(Service).order_by(Service.id)):
                h = db.get(Health, service.id)
                assets.append({**service.spec, "state": h.state if h else "unknown", "startup": h.startup if h else "unknown", "healthy": h.healthy if h else None, "latency_ms": h.latency_ms if h else None, "units": h.units if h else [], "checked_at": h.checked_at.isoformat() + "Z" if h else None, "detail": h.detail if h else "尚未检查"})
            routes = [x.spec for x in db.scalars(select(Route).order_by(Route.id))]
            active = db.get(Release, state.active_release) if state.active_release else None
            return {"assets": assets, "routes": routes, "revision": state.revision, "active_release": release_view(active) if active else None, "pending_release": state.pending_release, "draft_digest": snapshot(db).digest()}

    @app.get("/api/registry/services")
    def services_list(request: Request):
        with sessions() as db:
            principal(request, db)
            return [s.spec for s in db.scalars(select(Service).order_by(Service.id))]

    @app.post("/api/registry/services")
    def register(body: ServiceSpec, request: Request):
        with sessions.begin() as db:
            key = api_key(request, db)
            if key and body.id in key.service_ids:
                actor = "key:" + key.id
            else:
                actor = principal(request, db, "admin")[0].username
            from .registry import register as register_spec
            return register_spec(db, body, agent, actor)

    @app.post("/internal/registry/services")
    def local_register(body: ServiceSpec, request: Request):
        # The public ingress blocks /internal/. Trust actual TCP peer only; never XFF.
        if not request.client or request.client.host not in ("127.0.0.1", "::1"):
            raise HTTPException(403, "本机注册仅允许回环连接")
        with sessions.begin() as db:
            key = api_key(request, db)
            if not key or body.id not in key.service_ids:
                raise HTTPException(403, "需要包含该服务 ID 的有效注册 Key")
            from .registry import register as register_spec
            return register_spec(db, body, agent, "local-key:" + key.id)

    @app.delete("/api/registry/services/{service_id}")
    def unregister(service_id: str, request: Request):
        with sessions.begin() as db:
            actor = principal(request, db, "admin")[0].username
            state = state_lock(db)
            if state.pending_release:
                raise HTTPException(409, "请先核对未决发布，再注销服务")
            if db.scalar(select(Route).where(Route.service_id == service_id).limit(1)):
                raise HTTPException(409, "请先删除引用此服务的草稿路由，并发布变更")
            active = db.get(Release, state.active_release) if state.active_release else None
            if active and any(r["service_id"] == service_id and r["enabled"] for r in active.snapshot["routes"]):
                raise HTTPException(409, "已发布路由仍引用该服务；请先发布路由删除")
            service = db.get(Service, service_id)
            if not service:
                raise HTTPException(404, "服务不存在")
            db.delete(service)
            db.execute(delete(Health).where(Health.service_id == service_id))
            state.revision += 1
            audit(db, actor, "service.unregister", service_id, detail="仅删除登记；不停止服务，不删除文件或数据")
            return {"ok": True}

    @app.post("/api/services/{service_id}/actions")
    def action(service_id: str, body: ActionRequest, request: Request):
        with sessions.begin() as db:
            actor = principal(request, db, "operator")[0].username
            service = db.get(Service, service_id)
            if not service:
                raise HTTPException(404, "服务不存在")
            spec = service.spec
            if body.action in ("stop", "restart", "disable") and body.confirm != spec["name"]:
                raise HTTPException(409, "请确认服务名称及任务中断影响")
            op_id = uuid.uuid4().hex
            audit(db, actor, "service." + body.action, service_id, "started", op_id)
        try:
            result = agent.call("service", spec=spec, operation=body.action)
        except AgentError:
            with sessions.begin() as db:
                audit(db, actor, "service." + body.action, service_id, "failed", op_id)
            raise
        with sessions.begin() as db:
            audit(db, actor, "service." + body.action, service_id, "success", op_id)
        check_health(spec)
        return result

    @app.post("/api/services/{service_id}/health")
    def health_check(service_id: str, request: Request):
        with sessions() as db:
            principal(request, db, "operator")
            service = db.get(Service, service_id)
            if not service:
                raise HTTPException(404, "服务不存在")
            spec = service.spec
        return check_health(spec)

    @app.get("/api/inventory")
    def inventory(request: Request):
        with sessions() as db:
            principal(request, db, "admin")
        return agent.call("inventory")

    @app.post("/api/import/e5")
    def import_e5(body: ImportBody, request: Request):
        with sessions.begin() as db:
            actor = principal(request, db, "admin")[0].username
            state = state_lock(db)
            if len({s.id for s in body.services}) != len(body.services):
                raise HTTPException(422, "导入清单包含重复 ID")
            conflicts, additions, unchanged = [], [], []
            for spec in body.services:
                old = db.get(Service, spec.id)
                if old:
                    (unchanged if old.spec == spec.model_dump() else conflicts).append(spec.id)
                else:
                    additions.append(spec.id)
            result = {"additions": additions, "conflicts": conflicts, "unchanged": unchanged, "revision": state.revision}
            if not body.apply:
                return result
            if body.revision != state.revision or conflicts:
                raise HTTPException(409, "草稿已变化或导入有冲突；不会覆盖已有服务")
            for spec in body.services:
                if spec.id in additions:
                    agent.call("service", spec=spec.model_dump(), operation="status")
                    db.add(Service(id=spec.id, spec=spec.model_dump()))
            if additions:
                state.revision += 1
            audit(db, actor, "e5.import", "registry", detail=f"added={len(additions)}")
            return {**result, "applied": True, "revision": state.revision}

    @app.put("/api/routes/{route_id}")
    def save_route(route_id: str, body: RouteSpec, request: Request, revision: int):
        if route_id != body.id:
            raise HTTPException(422, "路由 ID 不一致")
        with sessions.begin() as db:
            actor = principal(request, db, "admin")[0].username
            state = state_lock(db)
            if state.revision != revision:
                raise HTTPException(409, "配置已被修改，请刷新页面")
            if not db.get(Service, body.service_id):
                raise HTTPException(422, "请先注册服务")
            row = db.get(Route, route_id)
            if row:
                row.spec, row.service_id = body.model_dump(), body.service_id
            else:
                db.add(Route(id=route_id, service_id=body.service_id, spec=body.model_dump()))
            db.flush()
            try:
                snap = snapshot(db)
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from exc
            agent.call("validate", snapshot=snap.model_dump())
            state.revision += 1
            audit(db, actor, "route.save", route_id)
            return {"revision": state.revision}

    @app.delete("/api/routes/{route_id}")
    def delete_route(route_id: str, request: Request, revision: int):
        with sessions.begin() as db:
            actor = principal(request, db, "admin")[0].username
            state = state_lock(db)
            if state.revision != revision:
                raise HTTPException(409, "配置已变化，请刷新")
            row = db.get(Route, route_id)
            if not row:
                raise HTTPException(404, "路由不存在")
            db.delete(row)
            state.revision += 1
            audit(db, actor, "route.delete-draft", route_id)
            return {"revision": state.revision}

    @app.post("/api/gateway/preview")
    def preview(request: Request):
        with sessions() as db:
            principal(request, db, "admin")
            state = db.get(GatewayState, 1)
            snap = snapshot(db)
            result = agent.call("validate", snapshot=snap.model_dump())
            return {**result, "revision": state.revision, "snapshot": snap.model_dump()}

    def do_publish(body, request, rollback_id=None):
        if not publish_lock.acquire(blocking=False):
            raise HTTPException(409, "已有发布任务正在执行")
        try:
            with sessions.begin() as db:
                actor = principal(request, db, "admin")[0].username
                state = state_lock(db)
                if state.pending_release:
                    raise HTTPException(409, "存在未核对的发布，请先执行发布状态核对")
                if body.revision != state.revision:
                    raise HTTPException(409, "草稿版本已变化，请重新预览")
                source = db.get(Release, rollback_id) if rollback_id else None
                if rollback_id and (not source or source.status not in ("active", "superseded")):
                    raise HTTPException(404, "没有可回滚的成功版本")
                snap = Snapshot.model_validate(source.snapshot) if source else snapshot(db)
                if body.digest != snap.digest():
                    raise HTTPException(409, "配置摘要不匹配，请重新预览")
                active = db.get(Release, state.active_release) if state.active_release else None
                expected = active.digest if active else Snapshot().digest()
                release_id = uuid.uuid4().hex
                db.add(Release(id=release_id, digest=snap.digest(), snapshot=snap.model_dump(), revision=state.revision, status="pending", note=body.note))
                state.pending_release = release_id
                audit(db, actor, "release.rollback" if source else "release.publish", release_id, "started")
            error = ""
            try:
                result = agent.call("apply", snapshot=snap.model_dump(), expected=expected, generation=release_id)
                if result["digest"] != snap.digest():
                    raise AgentError("Agent returned an unexpected digest")
            except AgentError as exc:
                error = str(exc)
            try:
                reconcile()
            except AgentError:
                # Keep pending instead of claiming success/rollback when state is ambiguous.
                raise HTTPException(503, "发布结果尚未确认；保留待核对记录，不会自动重复执行")
            with sessions.begin() as db:
                row = db.get(Release, release_id)
                if row.status == "failed":
                    row.error = error[:500] or row.error
                audit(db, actor, "release.result", release_id, row.status)
                result = release_view(row)
            if result["status"] != "active":
                raise HTTPException(502, result)
            return result
        finally:
            publish_lock.release()

    @app.post("/api/gateway/publish")
    def publish(body: PublishRequest, request: Request):
        return do_publish(body, request)

    @app.post("/api/gateway/rollback/{release_id}")
    def rollback(release_id: str, body: PublishRequest, request: Request):
        return do_publish(body, request, release_id)

    @app.post("/api/gateway/reconcile")
    def reconcile_endpoint(request: Request):
        with sessions() as db:
            principal(request, db, "admin")
        if not publish_lock.acquire(blocking=False):
            raise HTTPException(409, "发布仍在执行，不能提前核对")
        try:
            reconcile()
            return agent.call("status")
        finally:
            publish_lock.release()

    @app.get("/api/gateway/status")
    def gateway_status(request: Request):
        with sessions() as db:
            principal(request, db)
        return agent.call("status")

    @app.get("/api/releases")
    def releases(request: Request, limit: int = 50, before: str | None = None):
        if not 1 <= limit <= 200:
            raise HTTPException(422, "limit must be 1..200")
        with sessions() as db:
            principal(request, db)
            query = select(Release).order_by(Release.created_at.desc(), Release.id.desc())
            if before:
                row = db.get(Release, before)
                if not row:
                    raise HTTPException(404, "游标不存在")
                query = query.where((Release.created_at < row.created_at) | ((Release.created_at == row.created_at) & (Release.id < row.id)))
            return [release_view(r) for r in db.scalars(query.limit(limit))]

    @app.get("/api/audit")
    def audit_list(request: Request, before: int | None = None, limit: int = 100):
        if not 1 <= limit <= 200:
            raise HTTPException(422, "limit must be 1..200")
        with sessions() as db:
            principal(request, db, "operator")
            query = select(Audit).order_by(Audit.id.desc())
            if before:
                query = query.where(Audit.id < before)
            return [{"id": a.id, "actor": a.actor, "action": a.action, "target": a.target, "outcome": a.outcome, "detail": a.detail, "created_at": a.created_at.isoformat() + "Z"} for a in db.scalars(query.limit(limit))]

    @app.get("/api/traffic")
    def traffic(request: Request):
        with sessions() as db:
            principal(request, db, "operator")
        return agent.call("traffic")

    @app.get("/api/keys")
    def keys(request: Request):
        with sessions() as db:
            principal(request, db, "admin")
            return [{"id": k.id, "name": k.name, "route_ids": k.route_ids, "service_ids": k.service_ids, "expires_at": k.expires_at.isoformat() + "Z", "revoked": k.revoked} for k in db.scalars(select(ApiKey).order_by(ApiKey.id).limit(500))]

    @app.post("/api/keys")
    def create_key(body: KeyRequest, request: Request):
        token = "sg_" + secrets.token_urlsafe(32)
        key_id = uuid.uuid4().hex
        with sessions.begin() as db:
            actor = principal(request, db, "admin")[0].username
            if not body.route_ids and not body.service_ids:
                raise HTTPException(422, "至少指定一个路由或服务注册作用域")
            db.add(ApiKey(id=key_id, name=body.name, token_hash=digest(token), route_ids=body.route_ids, service_ids=body.service_ids, expires_at=now() + timedelta(days=body.expires_days)))
            audit(db, actor, "key.create", key_id)
        return {"id": key_id, "token": token, "notice": "密钥只显示本次；不会保存明文"}

    @app.delete("/api/keys/{key_id}")
    def revoke_key(key_id: str, request: Request):
        with sessions.begin() as db:
            actor = principal(request, db, "admin")[0].username
            row = db.get(ApiKey, key_id)
            if not row:
                raise HTTPException(404, "密钥不存在")
            row.revoked = True
            audit(db, actor, "key.revoke", key_id)
        return {"ok": True}

    @app.get("/api/users")
    def users(request: Request):
        with sessions() as db:
            principal(request, db, "admin")
            return [{"id": u.id, "username": u.username, "role": u.role, "enabled": u.enabled} for u in db.scalars(select(User).order_by(User.id).limit(500))]

    @app.post("/api/users")
    def create_user(body: UserBody, request: Request):
        if len(body.password) < 12:
            raise HTTPException(422, "密码至少 12 个字符")
        with sessions.begin() as db:
            actor = principal(request, db, "admin")[0].username
            db.add(User(username=body.username.lower(), password_hash=ph.hash(body.password), role=body.role))
            audit(db, actor, "user.create", body.username.lower())
        return {"ok": True}

    @app.delete("/api/users/{user_id}")
    def disable_user(user_id: int, request: Request):
        with sessions.begin() as db:
            actor = principal(request, db, "admin")[0]
            if actor.id == user_id:
                raise HTTPException(409, "不能停用当前管理员")
            user = db.get(User, user_id)
            if not user:
                raise HTTPException(404, "用户不存在")
            user.enabled = False
            db.execute(delete(LoginSession).where(LoginSession.user_id == user_id))
            audit(db, actor.username, "user.disable", user.username)
        return {"ok": True}

    @app.get("/internal/auth")
    def internal_auth(request: Request):
        if not secrets.compare_digest(request.headers.get("X-SG-Secret", ""), settings.auth_secret()):
            raise HTTPException(403, "Forbidden")
        rid = request.headers.get("X-SG-Route", "")
        with sessions() as db:
            state = db.get(GatewayState, 1)
            release = db.get(Release, state.active_release) if state.active_release else None
            if not release:
                raise HTTPException(401, "No active release")
            live_digest = request.headers.get("X-SG-Digest", "")
            if live_digest and live_digest != release.digest:
                # Never evaluate an old worker using a new (possibly weaker) route policy.
                # Short fail-closed window across publication is preferable to an auth downgrade.
                raise HTTPException(403, "Stale gateway configuration")
            if settings.deployment_mode == "remote" and not live_digest:
                raise HTTPException(403, "Missing configuration identity")
            route = next((r for r in release.snapshot["routes"] if r["id"] == rid and r["enabled"]), None)
            if not route:
                raise HTTPException(403, "Route is not published")
            if route["auth"] == "session":
                user, _ = principal(request, db, csrf=False)
                if user.role != "admin" and user.username not in route.get("session_users", []):
                    raise HTTPException(403, "User is not permitted on this service")
            elif route["auth"] == "api_key":
                key = api_key(request, db)
                if not key or rid not in key.route_ids:
                    raise HTTPException(401, "Invalid gateway key")
            elif route["auth"] in ("mtls_or_api_key", "mtls_api_key"):
                # OR semantics: a verified client certificate is sufficient; otherwise
                # a route-scoped API key may authenticate the request.
                if request.headers.get("X-SG-Client-Verify", "") != "SUCCESS":
                    key = api_key(request, db)
                    if not key or rid not in key.route_ids:
                        raise HTTPException(401, "Valid client certificate or gateway key required")
            else:
                raise HTTPException(403, "Invalid auth mode")
        return Response(status_code=204)

    static = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static), name="static")

    @app.get("/")
    @app.get("/login")
    def index():
        return FileResponse(static / "index.html")

    return app
