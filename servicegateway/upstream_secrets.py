"""Root-only per-route upstream identity secrets.

The route snapshot stores only ``upstream_auth.mode=route_secret``. Secret bytes
live outside MySQL and are never returned by the management API or config preview.
A live Nginx config contains the current secret because the root master must send
it upstream; that file remains root-only.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import stat

STORE = Path('/etc/servicegateway/upstream-secrets')
TOKEN_RE = re.compile(r'^[A-Za-z0-9_-]{40,160}$')
HEADER = 'X-SG-Upstream-Token'


class SecretError(ValueError):
    pass


def _private_dir():
    for parent in STORE.parents:
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise SecretError('Unsafe upstream-secret parent directory')
    STORE.mkdir(mode=0o700, exist_ok=True)
    st = STORE.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        raise SecretError('Upstream-secret directory must be root-owned 0700')


def _path(route_id):
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', route_id or ''):
        raise SecretError('Invalid route id')
    return STORE / (route_id + '.json')


def _read(route_id):
    from .agent import root_file
    path = root_file(_path(route_id))
    if stat.S_IMODE(path.stat().st_mode) != 0o600 or path.stat().st_size > 8192:
        raise SecretError('Unsafe upstream-secret record')
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        raise SecretError('Invalid upstream-secret record') from None
    if (data.get('route_id') != route_id or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', data.get('service_id', ''))
            or not TOKEN_RE.fullmatch(data.get('secret', ''))):
        raise SecretError('Invalid upstream-secret record')
    return data


def _write(record):
    from .agent import atomic_write
    _private_dir()
    path = _path(record['route_id'])
    if path.exists() or path.is_symlink():
        _read(record['route_id'])
    atomic_write(path, json.dumps(record, indent=2) + '\n', 0o600)


def configured(route):
    if route.upstream_auth.mode != 'route_secret':
        return True
    try:
        record = _read(route.id)
    except (OSError, SecretError, ValueError):
        return False
    return record['service_id'] == route.service_id


def resolve(snapshot, strict=True, preview=False):
    result, missing = {}, []
    for route in snapshot.routes:
        if not route.enabled or route.upstream_auth.mode != 'route_secret':
            continue
        try:
            record = _read(route.id)
            if record['service_id'] != route.service_id:
                raise SecretError('Route secret is bound to a different service')
            result[route.id] = 'REDACTED' if preview else record['secret']
        except (OSError, SecretError, ValueError):
            missing.append(route.id)
    if strict and missing:
        raise SecretError('Missing or mismatched upstream secret for route(s): ' + ', '.join(sorted(missing)))
    return result, missing


def ensure(route, rotate=False):
    if os.geteuid() != 0:
        raise SecretError('Local root is required for upstream secret management')
    if route.upstream_auth.mode != 'route_secret':
        raise SecretError('Route upstream_auth is not route_secret')
    try:
        previous = _read(route.id)
    except (OSError, SecretError, ValueError):
        previous = None
    if previous and previous['service_id'] != route.service_id:
        raise SecretError('Existing route secret belongs to a different service; review locally')
    if previous and not rotate:
        return previous, False
    record = {
        'route_id': route.id,
        'service_id': route.service_id,
        'secret': secrets.token_urlsafe(48),
        'created_at': datetime.now(timezone.utc).isoformat(),
        'generation': (previous.get('generation', 0) + 1) if previous else 1,
    }
    _write(record)
    return record, True


def export_env(record, output):
    output = Path(output).absolute()
    for parent in output.parents:
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise SecretError('Secret export directory must be root-owned and not group/world writable')
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write('# ServiceGateway route-origin secret. Do not commit or log.\n')
        stream.write('SG_UPSTREAM_TOKEN=' + record['secret'] + '\n')
        stream.flush(); os.fsync(stream.fileno())
    return output
