"""Root CLI registration: approve explicitly, then register without creating a route."""
import fcntl
import json
import os
from pathlib import Path
from .agent import atomic_write, root_file, unit_info, validate_service, load_policy
from .config import Settings
from .db import database
from .ipc import AgentClient
from .registry import register
from .schemas import ServiceSpec, endpoint


def read_manifest(path):
    with Path(path).open('rb') as source:
        raw = source.read(65537)
    if len(raw) > 65536:
        raise ValueError('Manifest exceeds 64 KiB')
    return ServiceSpec.model_validate_json(raw)


def approve(spec, settings):
    if os.geteuid() != 0:
        raise PermissionError('Local approval requires root')
    for unit in spec.services:
        unit_info(unit)
    host, port = endpoint(spec.health_url)
    if host != '127.0.0.1' or port in (18090, 19091, 19092, 19093) or port < 1024:
        raise ValueError('Local approval requires a non-control-plane loopback HTTP port >=1024')
    path = root_file(settings.policy_file)
    fd = os.open(str(path) + '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        root_file(str(path) + '.lock')
        fcntl.flock(lock, fcntl.LOCK_EX)
        policy = json.loads(root_file(path).read_text())
        grant = {'units': spec.services, 'upstreams': [f'{host}:{port}'], 'health_url': spec.health_url}
        previous = policy.get('services', {}).get(spec.id)
        if previous and (previous['units'] != grant['units'] or previous['health_url'] != grant['health_url']
                         or grant['upstreams'][0] not in previous['upstreams']):
            raise ValueError('Conflicting existing grant; review locally rather than overwrite')
        if not previous:
            policy.setdefault('services', {})[spec.id] = grant
            atomic_write(path, json.dumps(policy, ensure_ascii=False, indent=2) + '\n', 0o640)


def register_local(path, approve_first=False):
    if os.geteuid() != 0:
        raise PermissionError('Root CLI required; unprivileged applications use register-local.py with a scoped key file')
    settings = Settings(_env_file=root_file('/etc/servicegateway/app.env'))
    spec = read_manifest(path)
    if approve_first:
        approve(spec, settings)
    engine, sessions = database(settings)
    try:
        with sessions.begin() as db:
            result = register(db, spec, AgentClient(settings.agent_socket), 'local-root')
    finally:
        engine.dispose()
    print(json.dumps(result, ensure_ascii=False))
    print('服务已登记；未启停业务、未创建路由、未开放端口。')
