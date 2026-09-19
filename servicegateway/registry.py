"""One registry transaction shared by browser/API and local root CLI."""
from fastapi import HTTPException
from sqlalchemy import select, func
from .db import Audit, GatewayState, Service
from .schemas import ServiceSpec


def register(db, spec: ServiceSpec, agent, actor: str):
    state = db.scalar(select(GatewayState).where(GatewayState.id == 1).with_for_update())
    if not state:
        raise HTTPException(503, '数据库尚未迁移')
    # Enforce root grants even when a valid scoped registration key is presented.
    agent.call('service', spec=spec.model_dump(), operation='status')
    old = db.get(Service, spec.id)
    if old and old.spec == spec.model_dump():
        return {'id': spec.id, 'changed': False, 'revision': state.revision}
    if old:
        old.spec = spec.model_dump()
    else:
        if db.scalar(select(func.count()).select_from(Service)) >= 200:
            raise HTTPException(409, "登记服务已达 200 个上限")
        db.add(Service(id=spec.id, spec=spec.model_dump()))
    state.revision += 1
    db.add(Audit(actor=actor, action='service.register', target=spec.id, outcome='success', detail='No lifecycle action or route publication'))
    return {'id': spec.id, 'changed': True, 'revision': state.revision}
