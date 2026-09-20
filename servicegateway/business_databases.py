"""Restricted MySQL provisioning. Root journals, not Web DB rows, prove ownership.

DDL implicitly commits. Interrupted work is retained for local review, never
'rolled back' by dropping a database or taking over an existing account.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Literal
from pydantic import Field, StrictBool, ValidationError
from .schemas import Strict, ID

CONFIG = Path('/etc/servicegateway/database-admin.json')
STORE = Path('/etc/servicegateway/business-databases')
SOCKET = '/run/mysqld/mysqld.sock'
LOCK_NAME = 'servicegateway:business-databases'
RUNTIME = ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
MIGRATION = RUNTIME + ('CREATE', 'ALTER', 'DROP', 'INDEX', 'REFERENCES', 'CREATE VIEW', 'SHOW VIEW')
PRIVILEGES = {'runtime': RUNTIME, 'migration': MIGRATION}


class ProvisionError(ValueError):
    """Safe to display: never contains a password or submitted SQL."""


class DatabaseRequest(Strict):
    service_id: str = Field(pattern=ID)
    database_name: str = Field(pattern=r'^sgb_[a-z][a-z0-9_]{0,58}$')


class CredentialRequest(Strict):
    current_password: str = Field(min_length=1, max_length=256, repr=False)
    account: Literal['runtime', 'migration'] = 'runtime'


class AdminConfig(Strict):
    enabled: StrictBool = True
    username: str = Field(default='root', pattern=r'^[a-zA-Z0-9_]{1,32}$')
    password: str = Field(default='', max_length=1024, repr=False)


def service_id(value):
    if not isinstance(value, str) or not re.fullmatch(ID, value):
        raise ProvisionError('无效服务 ID')
    return value


def private_file(path):
    from .agent import root_file
    path = root_file(path)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise ProvisionError('建库配置和凭据必须为 root-only 0600')
    return path


def private_directory(path):
    # Check the parent first: never create root files through writable ancestors.
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ProvisionError('拒绝不安全的建库记录父目录')
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ProvisionError('建库记录目录必须为 root 所有的 0700 普通目录')


def save(path, value):
    from .agent import atomic_write
    if path.exists() or path.is_symlink():
        private_file(path)
    atomic_write(path, json.dumps(value, ensure_ascii=False, indent=2) + '\n', 0o600)


def read(path):
    path = private_file(path)
    if path.stat().st_size > 65536:
        raise ProvisionError('建库记录超过大小限制')
    return json.loads(path.read_text())


def configuration():
    if not CONFIG.exists() and not CONFIG.is_symlink():
        raise ProvisionError('尚未启用业务建库，请在本机执行 sgctl database-enable')
    try:
        config = AdminConfig.model_validate(read(CONFIG))
    except (ValidationError, ValueError, OSError):
        raise ProvisionError('无法读取安全的本机建库配置，请本机检查，不输出凭据') from None
    if not config.enabled:
        raise ProvisionError('业务建库已由本机管理员停用')
    return config


def connect_admin(config):
    import pymysql
    # No TCP fallback, selectable server, defaults-file lookup, or LOCAL INFILE.
    return pymysql.connect(unix_socket=SOCKET, user=config.username, password=config.password,
                           charset='utf8mb4', autocommit=True, local_infile=False,
                           connect_timeout=5, read_timeout=10, write_timeout=10)


def environment_checks(cursor):
    cursor.execute('SELECT VERSION(), @@global.partial_revokes, @@global.mandatory_roles, @@port')
    version, partial_revokes, roles, port = cursor.fetchone()
    if 'mariadb' in version.lower() or not version.startswith(('8.0.', '8.4.')):
        raise ProvisionError('业务建库仅支持 MySQL 8.0/8.4')
    if roles:
        raise ProvisionError('MySQL 配置了 mandatory_roles，需先审核其对业务账号的权限影响')
    if port != 3306:
        raise ProvisionError('本机 MySQL 应使用已部署的 3306；不会改变数据库监听')
    return bool(partial_revokes)


def grant_target(database_name, partial_revokes):
    DatabaseRequest(service_id='validation', database_name=database_name)
    # Backticks alone do NOT stop '_' being a wildcard in schema-level GRANT.
    escaped = database_name if partial_revokes else database_name.replace('_', r'\_')
    return '`' + escaped + '`.*'


def names(sid):
    stem = 'sgb' + hashlib.sha256(service_id(sid).encode()).hexdigest()[:20]
    return {'runtime': stem + '_r', 'migration': stem + '_m'}


def public(record):
    return {key: record[key] for key in ('service_id', 'database_name', 'status', 'stage', 'created_at', 'accounts')}


@contextmanager
def store_lock():
    private_directory(STORE)
    fd = os.open(STORE / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+') as lock:
        private_file(STORE / '.lock')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ProvisionError('已有建库操作正在执行，请稍后重试') from None
        yield


def record_path(sid):
    return STORE / (service_id(sid) + '.json')


def records():
    if not STORE.exists() and not STORE.is_symlink():
        return []
    private_directory(STORE)
    paths = sorted(STORE.glob('*.json'))
    if len(paths) > 200:
        raise ProvisionError('业务建库记录超过 200 项上限')
    return [read(p) for p in paths]


def status():
    enabled = False
    if CONFIG.exists() or CONFIG.is_symlink():
        try:
            enabled = AdminConfig.model_validate(read(CONFIG)).enabled
        except (ValidationError, ValueError, OSError):
            raise ProvisionError('无法读取安全的本机建库配置') from None
    return {'enabled': enabled, 'host': '127.0.0.1', 'port': 3306, 'prefix': 'sgb_',
            'items': [public(r) for r in records()],
            'notice': '只列出本平台建库记录，不查询业务数据、不返回密码；不是实时数据库健康检查。'}


def approve_target(request, policy):
    from .agent import unit_info
    grant = policy.get('services', {}).get(request.service_id)
    if not grant or not grant.get('units'):
        raise ProvisionError('服务尚未获得本机批准，不能申请数据库')
    for unit in grant['units']:
        unit_info(unit)  # loaded non-root unit is enough; it need not be running.
    return hashlib.sha256(json.dumps(grant, sort_keys=True).encode()).hexdigest()


def check_grants(cur, record, partial_revokes):
    target = grant_target(record['database_name'], partial_revokes)
    for account, user in record['accounts'].items():
        cur.execute('SHOW GRANTS FOR %s@%s', (user, '127.0.0.1'))
        actual = set()
        for (line,) in cur.fetchall():
            match = re.fullmatch(r'GRANT (.+) ON (.+) TO .+', line)
            if not match or ' WITH GRANT OPTION' in line:
                raise ProvisionError('业务账号存在非预期角色或授权，需要本机审核')
            privileges, scope = match.groups()
            if scope == '*.*' and privileges == 'USAGE':
                continue
            if scope != target:
                raise ProvisionError('业务账号授权范围不匹配，不自动覆盖授权')
            actual.update(privileges.split(', '))
        if actual != set(PRIVILEGES[account]):
            raise ProvisionError('业务账号权限已变化，需要本机审核')


def create(request, policy):
    request = DatabaseRequest.model_validate(request)
    config = configuration()
    grant_digest = approve_target(request, policy)
    record = None
    with store_lock():
        path = record_path(request.service_id)
        previous = read(path) if path.exists() or path.is_symlink() else None
        if previous:
            if previous['database_name'] != request.database_name or previous['grant_digest'] != grant_digest:
                raise ProvisionError('该服务已有不同建库记录或本机授权改变；不会覆盖旧库或密码')
            if previous['status'] != 'ready':
                raise ProvisionError('上次建库未完整确认；请本机检查私有记录，不自动删库或重放 DDL')
        else:
            existing = records()
            if len(existing) >= 200 or any(r['database_name'] == request.database_name for r in existing):
                raise ProvisionError('库名已被其他服务保留，或已达 200 项上限')
        connection = None
        locked = False
        try:
            connection = connect_admin(config)
            with connection.cursor() as cur:
                cur.execute('SELECT GET_LOCK(%s, 3)', (LOCK_NAME,))
                locked = cur.fetchone()[0] == 1
                if not locked:
                    raise ProvisionError('MySQL 建库锁被占用，请稍后重试')
                partial_revokes = environment_checks(cur)
                cur.execute('SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE LOWER(SCHEMA_NAME)=%s',
                            (request.database_name,))
                schema_exists = cur.fetchone() is not None
                users = names(request.service_id)
                cur.execute('SELECT User, Host FROM mysql.user WHERE User IN (%s, %s)', tuple(users.values()))
                found_users = set(cur.fetchall())
                if previous:
                    if not schema_exists or found_users != {(u, '127.0.0.1') for u in users.values()}:
                        raise ProvisionError('数据库或账号发生外部变更，不自动重建或重置密码')
                    check_grants(cur, previous, partial_revokes)
                    return {**public(previous), 'changed': False}
                if schema_exists or found_users:
                    raise ProvisionError('同名数据库或账号已存在，拒绝接管；未修改已有库和密码')
                cur.execute('SELECT User FROM mysql.db WHERE User IN (%s, %s)', tuple(users.values()))
                if cur.fetchone():
                    raise ProvisionError('发现遗留账号授权记录，拒绝接管')
                record = {**request.model_dump(), 'grant_digest': grant_digest, 'status': 'pending',
                          'stage': 'prepared', 'created_at': datetime.now(timezone.utc).isoformat(),
                          'accounts': users, 'passwords': {k: secrets.token_urlsafe(32) + 'aA7!' for k in users},
                          'created_accounts': [], 'database_created': False}
                save(path, record)  # Durable intent and recoverable passwords BEFORE DDL.
                record['stage'] = 'create-database'; save(path, record)
                cur.execute(f'CREATE DATABASE `{request.database_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci')
                record['database_created'] = True; save(path, record)
                for account in users:
                    record['stage'] = 'create-' + account; save(path, record)
                    cur.execute('CREATE USER %s@%s IDENTIFIED BY %s WITH MAX_USER_CONNECTIONS 32 ACCOUNT LOCK',
                                (users[account], '127.0.0.1', record['passwords'][account]))
                    record['created_accounts'].append(account); save(path, record)
                    record['stage'] = 'grant-' + account; save(path, record)
                    cur.execute('GRANT ' + ', '.join(PRIVILEGES[account]) + ' ON ' +
                                grant_target(request.database_name, partial_revokes) + ' TO %s@%s',
                                (users[account], '127.0.0.1'))
                # Both accounts stay locked until all scope checks have succeeded.
                record['stage'] = 'verify-grants'; save(path, record)
                check_grants(cur, record, partial_revokes)
                record['stage'] = 'unlock'; save(path, record)
                for user in users.values():
                    cur.execute('ALTER USER %s@%s ACCOUNT UNLOCK', (user, '127.0.0.1'))
                record['stage'] = 'complete'; record['status'] = 'ready'; save(path, record)
                return {**public(record), 'changed': True}
        except Exception as exc:
            if record:
                record['status'] = 'needs_review'
                if connection:
                    # Only lock accounts known to have been created by this operation.
                    for account in record['created_accounts']:
                        try:
                            with connection.cursor() as cur:
                                cur.execute('ALTER USER %s@%s ACCOUNT LOCK',
                                            (record['accounts'][account], '127.0.0.1'))
                        except Exception:
                            pass
                try:
                    save(path, record)
                except OSError:
                    pass  # Prior durable incomplete phase also blocks unsafe retries.
            if isinstance(exc, ProvisionError):
                raise
            code = exc.args[0] if exc.args and isinstance(exc.args[0], int) else type(exc).__name__
            raise ProvisionError(f'本机建库未完成（{code}）；保留私有记录供核对，不输出 SQL 或密码，不自动清库') from None
        finally:
            if connection:
                if locked:
                    try:
                        with connection.cursor() as cur:
                            cur.execute('SELECT RELEASE_LOCK(%s)', (LOCK_NAME,))
                    except Exception:
                        pass
                connection.close()


def credentials(sid, account):
    configuration()
    if account not in PRIVILEGES:
        raise ProvisionError('无效账号类型')
    with store_lock():
        path = record_path(sid)
        if not path.exists():
            raise ProvisionError('该服务没有受管数据库')
        record = read(path)
        if record['status'] != 'ready':
            raise ProvisionError('未完成建库不提供凭据，请本机核对')
        return {'service_id': sid, 'database': record['database_name'], 'host': '127.0.0.1', 'port': 3306,
                'charset': 'utf8mb4', 'account': account, 'username': record['accounts'][account],
                'password': record['passwords'][account], 'privileges': list(PRIVILEGES[account])}


def env_file(data):
    from urllib.parse import quote
    return ('# Private business credentials. Do not commit or source as a shell script.\n' +
            '# Migration account can change/drop objects and its OWN database; do not use for routine runtime.\n' +
            f'DB_HOST=127.0.0.1\nDB_PORT=3306\nDB_NAME={data["database"]}\nDB_USER={data["username"]}\n' +
            f'DB_PASSWORD={data["password"]}\nDB_CHARSET=utf8mb4\n' +
            f'DATABASE_URL=mysql+pymysql://{data["username"]}:{quote(data["password"], safe="")}@127.0.0.1:3306/{data["database"]}?charset=utf8mb4\n')


def enable(username='root', ask_password=False):
    if os.geteuid() != 0:
        raise ProvisionError('只有本机 root 可启用建库执行器')
    if CONFIG.exists() or CONFIG.is_symlink():
        configuration()
        print('建库执行器已配置；未覆盖 MySQL 管理凭据。'); return
    config = AdminConfig(username=username, password=getpass.getpass('本机 MySQL 管理口令（不输出）: ') if ask_password else '')
    try:
        conn = connect_admin(config)
        try:
            with conn.cursor() as cur:
                environment_checks(cur)
                cur.execute('SHOW GRANTS FOR CURRENT_USER')
                required = {'CREATE USER', *MIGRATION}
                scope = set()
                for (line,) in cur.fetchall():
                    match = re.fullmatch(r'GRANT (.+) ON \*\.\* TO .+ WITH GRANT OPTION', line)
                    if match:
                        if match[1] == 'ALL PRIVILEGES':
                            scope = required; break
                        scope.update(match[1].split(', '))
                if not required.issubset(scope):
                    raise ProvisionError('本机 MySQL 管理账号缺少建库/建用户/授权能力；未自动提权')
        finally:
            conn.close()
    except ProvisionError:
        raise
    except Exception:
        raise ProvisionError('无法验证本机 MySQL 管理连接；密码认证使用 --ask-password，不会重置 root 密码') from None
    from .agent import root_file
    root_file(CONFIG.parent / 'policy.json')
    private_directory(STORE)
    with store_lock():
        if CONFIG.exists() or CONFIG.is_symlink():
            raise ProvisionError('已有并发配置，请检查；未覆盖')
        save(CONFIG, config.model_dump())
    print('已启用受限本机建库；Web 运行账号没有获得全局 MySQL 权限。')
