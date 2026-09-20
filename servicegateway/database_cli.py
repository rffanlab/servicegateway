"""Explicit local-root provisioning. No secrets in argv/stdout or arbitrary SQL."""
import json
import os
from pathlib import Path
import stat
from .agent import root_file
from .business_databases import DatabaseRequest, ProvisionError, enable, env_file
from .config import Settings
from .db import Audit, database
from .ipc import AgentClient


def add_commands(sub):
    p = sub.add_parser('database-enable', help='Authorize local business provisioning once (root only)')
    p.add_argument('--admin-user', default='root')
    p.add_argument('--ask-password', action='store_true', help='Hidden MySQL management password prompt; default uses Unix-socket authentication')
    p = sub.add_parser('database-create', help='Create one MySQL database and scoped runtime/migration users for an approved service')
    p.add_argument('--service', required=True)
    p.add_argument('--name', required=True, help='New lowercase sgb_ schema name; never an existing schema')
    p = sub.add_parser('database-credentials', help='Export one business account into a NEW private file')
    p.add_argument('--service', required=True)
    p.add_argument('--account', choices=['runtime', 'migration'], default='runtime')
    p.add_argument('--output', type=Path, required=True)
    sub.add_parser('database-list', help='List managed database metadata without passwords')


def write_new_private(path, content):
    path = path.absolute()
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ProvisionError('凭据导出目录必须由 root 所有且不可被其他用户写入')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(content); out.flush(); os.fsync(out.fileno())
    return path


def run(args):
    if os.geteuid() != 0:
        raise ProvisionError('本机建库命令需要 root；普通登记 Key 没有建库权限')
    if args.command == 'database-enable':
        return enable(args.admin_user, args.ask_password)
    settings = Settings(_env_file=root_file('/etc/servicegateway/app.env'))
    agent = AgentClient(settings.agent_socket)
    if args.command == 'database-list':
        print(json.dumps(agent.call('database-status'), ensure_ascii=False, indent=2)); return
    engine, sessions = database(settings)
    action = 'database.create' if args.command == 'database-create' else 'database.credentials'
    try:
        with sessions.begin() as db:
            db.add(Audit(actor='local-root', action=action, target=args.service[:80], outcome='started', detail='Root CLI; credentials not printed'))
        try:
            if args.command == 'database-create':
                spec = DatabaseRequest(service_id=args.service, database_name=args.name)
                result = agent.call('database-create', spec=spec.model_dump())
                print(json.dumps(result, ensure_ascii=False, indent=2))
                print('业务库和专用账号已创建/确认；密码未打印。使用 database-credentials 导出连接文件。')
            else:
                data = agent.call('database-credentials', service_id=args.service, account=args.account)
                path = write_new_private(args.output, env_file(data))
                print(f'凭据已写入 {path}（0600）；不要提交 Git 或发到聊天。')
        except Exception:
            with sessions.begin() as db:
                db.add(Audit(actor='local-root', action=action, target=args.service[:80], outcome='failed', detail=''))
            raise
        with sessions.begin() as db:
            db.add(Audit(actor='local-root', action=action, target=args.service[:80], outcome='success', detail=''))
    finally:
        engine.dispose()
