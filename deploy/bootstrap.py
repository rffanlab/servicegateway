#!/usr/bin/env python3
"""Ubuntu 24.04 host provisioning. --dry-run never writes or executes host commands.

Only this local installer installs packages; the Web API cannot invoke it.
Credentials are neither shell-evaluated nor passed on a command line.
"""
import argparse
import contextlib
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CFG = Path('/etc/servicegateway')
STATE = CFG / 'bootstrap.json'
BASE = Path('/srv/e5-apps/servicegateway/current')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/root',
       'DEBIAN_FRONTEND': 'noninteractive', 'NEEDRESTART_MODE': 'l'}
PACKAGES = ['nginx', 'mysql-server', 'mysql-client', 'certbot', 'openssl', 'python3',
            'python3-venv', 'python3-pip', 'ca-certificates', 'curl', 'git', 'logrotate']


class Stop(RuntimeError):
    pass


def run(args, *, data=None, check=True, timeout=1800, env=None, quiet=False):
    result = subprocess.run([str(a) for a in args], input=data, text=True,
                            capture_output=True, timeout=timeout, env=env or ENV)
    if result.returncode and check:
        # Never print SQL, env files, or potentially credential-bearing command stderr.
        raise Stop(f'{Path(str(args[0])).name} failed (exit {result.returncode}); '
                   '检查本机对应服务日志。未执行清库或关闭防火墙。')
    if not quiet and result.stdout and not str(args[0]).endswith(('mysql', 'mysqldump')):
        print(result.stdout[-3000:].rstrip(), flush=True)
    return result


def owned(path, private=False):
    path = Path(path)
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_nlink != 1 or s.st_mode & 0o022:
        raise Stop(f'拒绝不安全的文件: {path}')
    if private and s.st_mode & 0o077:
        raise Stop(f'文件必须为 root:root 0600: {path}')
    for parent in path.parents:
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise Stop(f'拒绝不安全的父目录: {parent}')
    return path


def mkdir(path, mode=0o700):
    path = Path(path)
    if path.is_symlink():
        raise Stop(f'目录不能是符号链接: {path}')
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    st = path.stat()
    if st.st_uid != 0 or st.st_mode & 0o022:
        raise Stop(f'目录必须由 root 所有且不可被其他用户写入: {path}')


def write(path, content, mode=0o600):
    path = Path(path)
    if path.exists() or path.is_symlink():
        owned(path)
    fd, name = tempfile.mkstemp(prefix='.sg-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as out:
            out.write(content); out.flush(); os.fsync(out.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
        d = os.open(path.parent, os.O_DIRECTORY)
        try: os.fsync(d)
        finally: os.close(d)
    finally:
        if os.path.exists(name): os.unlink(name)


def domain(value):
    value = value.lower().rstrip('.')
    if (len(value) > 253 or '.' not in value or value.endswith(('.invalid', '.test', '.localhost', '.local'))
            or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in value.split('.'))):
        raise argparse.ArgumentTypeError('请输入实际可公开解析的域名，不接受通配符、IP 或 URL')
    try: ipaddress.ip_address(value)
    except ValueError: return value
    raise argparse.ArgumentTypeError('需要域名，不能使用 IP 代替')


def cidr(value):
    try: network = ipaddress.IPv4Network(value, strict=True)
    except ValueError as exc: raise argparse.ArgumentTypeError('管理来源必须是明确的 IPv4/CIDR') from exc
    if network.prefixlen < 16 or network.is_multicast or network.is_unspecified:
        raise argparse.ArgumentTypeError('管理白名单不接受大于 /16 的宽泛网络')
    return str(network)


def parser():
    p = argparse.ArgumentParser(description='完整部署：Ubuntu 24.04 + Nginx + MySQL + Let\'s Encrypt + ServiceGateway')
    p.add_argument('action', choices=['install', 'certificate', 'renew-test', 'pki-refresh', 'status'], nargs='?', default='install')
    p.add_argument('--domain', type=domain, help='管理域名；certificate 操作为新增业务证书的域名')
    p.add_argument('--email', help='Let\'s Encrypt 账户邮箱')
    p.add_argument('--admin-cidr', action='append', type=cidr, default=[], help='可选：固定出口时额外限制 IPv4/CIDR，可重复；动态 IP 请省略')
    p.add_argument('--admin-user', default='rffanlab')
    p.add_argument('--certificate-id', default=None, help='新增业务证书 ID，如 harness')
    p.add_argument('--agree-tos', action='store_true', help='同意 Let\'s Encrypt 服务条款并允许向 CA 提交域名/邮箱')
    p.add_argument('--reuse-mysql', action='store_true', help='明确允许复用已有、仅本机监听的 MySQL；不改 root 密码')
    p.add_argument('--mysql-admin-file', type=Path, help='已有 MySQL 的 root-only mysql defaults 文件（凭据不放参数）')
    p.add_argument('--pki-pass-file', type=Path, help='无人值守时读取 root-only 0600 密码文件；默认隐藏交互输入')
    p.add_argument('--skip-acme-test', action='store_true', help='跳过首次 staging 验证；默认先 dry-run 再生产签发')
    p.add_argument('--dry-run', action='store_true', help='仅显示计划，不安装、不写文件、不访问数据库')
    return p


def validate_args(args, saved=None):
    saved = saved or {}
    if args.action == 'install':
        args.domain = args.domain or saved.get('domain')
        args.email = args.email or saved.get('email')
        args.admin_cidr = args.admin_cidr or saved.get('admin_cidrs', [])
        if not args.domain or not args.email:
            raise Stop('首次部署必须提供 --domain 和 --email；先把域名 A 记录指向服务器。动态出口无需 --admin-cidr。')
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', args.admin_user):
            raise Stop('无效管理员名称')
        if saved and (args.domain != saved['domain'] or sorted(args.admin_cidr) != sorted(saved['admin_cidrs'])
                      or args.admin_user != saved['admin_user'] or args.email != saved['email']):
            raise Stop('重跑不能静默更改管理域名、账号、邮箱或来源策略，请单独审核迁移。')
    if args.action in ('install', 'certificate') and not args.agree_tos:
        raise Stop('签发证书需显式添加 --agree-tos；没有该参数不会接受 CA 条款。')
    if args.pki_pass_file and args.action in ('install', 'pki-refresh'):
        owned(args.pki_pass_file, True)
    if args.email and not re.fullmatch(r'[A-Za-z0-9.!#$%&*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', args.email):
        raise Stop('邮箱格式无效')
    if args.action == 'certificate':
        if not args.domain or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', args.certificate_id or ''):
            raise Stop('新增业务证书必须提供 --domain 和 --certificate-id')
        if args.certificate_id in ('admin', 'admin-ca'):
            raise Stop('管理证书不能由业务证书命令覆盖')


def plan(args):
    print('计划（未执行）:\n'
          '1. 检查 Ubuntu 24.04、root 权限、DNS A/AAAA、端口和既有数据库。\n'
          '2. 安装官方 apt 包；阻止包安装时自动启动系统 Nginx。\n'
          '3. 创建专用 MySQL schema、迁移/运行账号和 root-only 随机凭据。\n'
          '4. 安装 ServiceGateway；80 先仅提供隔离的 ACME HTTP-01 验证。\n'
          '5. staging 验证 → Let\'s Encrypt 生产证书 → 初始化管理 mTLS。\n'
          '6. 启用唯一 80/443 入口；安装每日两次的自动续期定时器。\n'
          '7. 验收、输出文件位置；不修改 SSH/防火墙/云安全组，不删除旧数据。')
    print(f'操作: {args.action}; 域名: {args.domain or "已保存配置"}')
    print('新安装默认使用 mTLS 客户端证书 + 账号密码，不绑定出口 IP；--admin-cidr 仅为可选附加限制。')


def dns_check(host):
    try: records = socket.getaddrinfo(host, 80, type=socket.SOCK_STREAM)
    except socket.gaierror as exc: raise Stop('域名尚未正确解析，先设置公开 A 记录') from exc
    if any(r[0] == socket.AF_INET6 for r in records):
        raise Stop('当前网关只生成 IPv4 监听。检测到 AAAA 记录，请先正确处理 IPv6/DNS 后再签发，不能忽略验证。')
    if not any(ipaddress.ip_address(r[4][0]).is_global for r in records):
        raise Stop('HTTP-01 部署需要公开 A 记录；内网/通配域名请另配 DNS-01，不会自动绕过。')


def mysql(args, sql):
    command = ['/usr/bin/mysql']
    if args.mysql_admin_file:
        command.append('--defaults-extra-file=' + str(owned(args.mysql_admin_file, True)))
    else:
        command.append('--no-defaults')
    command += ['--protocol=socket', '--batch', '--skip-column-names', '--user=root']
    return run(command, data=sql, quiet=True).stdout.strip()


def inspect_mysql(args):
    version = mysql(args, 'SELECT VERSION();')
    if 'mariadb' in version.lower() or not version.startswith(('8.0.', '8.4.')):
        raise Stop('自动部署仅接受 MySQL 8.0/8.4，不替换 MariaDB 或未知版本')
    values = mysql(args, "SHOW VARIABLES WHERE Variable_name IN ('bind_address','mysqlx_bind_address');")
    for row in values.splitlines():
        key, _, value = row.partition('\t')
        if value not in ('127.0.0.1', '::1', 'localhost'):
            raise Stop(f'{key} 不是本机地址；拒绝继续，不擅自重启已有 MySQL')


@contextlib.contextmanager
def suppress_package_start():
    # Debian maintainer scripts honor policy-rc.d. Restore the original even on failure.
    policy = Path('/usr/sbin/policy-rc.d')
    backup = Path('/usr/sbin/policy-rc.d.servicegateway-backup')
    sentinel = b'#!/bin/sh\n# temporary ServiceGateway package bootstrap\nexit 101\n'
    if backup.exists() or (policy.exists() and b'ServiceGateway package bootstrap' in policy.read_bytes()):
        raise Stop('上次包安装被中断：先检查并恢复 /usr/sbin/policy-rc.d 的备份，不继续覆盖。')
    had = policy.exists() or policy.is_symlink()
    if had: os.rename(policy, backup)
    try:
        write(policy, sentinel.decode(), 0o755)
        yield
    finally:
        policy.unlink(missing_ok=True)
        if had: os.rename(backup, policy)


def check_host(saved, args):
    os_release = Path('/etc/os-release').read_text()
    if not re.search(r'^ID=ubuntu$', os_release, re.M) or not re.search(r'^VERSION_ID="24\.04"$', os_release, re.M):
        raise Stop('该完整安装器仅支持 Ubuntu Server 24.04；其他系统使用经审核的分步部署，不自动升级系统。')
    if Path('/proc/1/comm').read_text().strip() != 'systemd':
        raise Stop('需要真实 systemd 主机，不支持普通 Docker/WSL 容器直接安装')
    if shutil.which('dpkg-query'):
        packages = run(['/usr/bin/dpkg-query', '-W', '-f=${binary:Package} ${db:Status-Status}\n'], quiet=True).stdout
        if any(line.startswith('mariadb-server') and line.endswith(' installed') for line in packages.splitlines()):
            raise Stop('发现 MariaDB；拒绝用 MySQL 包替换现有数据库')
    if not saved:
        for path in (CFG / 'app.env', CFG / 'policy.json', BASE,
                     Path('/etc/systemd/system/servicegateway.service')):
            if path.exists() or path.is_symlink():
                raise Stop('发现非本安装器接管的 ServiceGateway。不会覆盖现有配置，请使用 deploy/install.sh 升级并单独迁移 ACME。')
        for port in (80, 443, 19092, 19093):
            if run(['/usr/bin/ss', '-H', '-ltn', f'sport = :{port}'], quiet=True).stdout.strip():
                raise Stop(f'端口 {port} 已有监听；请先迁移现有服务，脚本不会杀进程')
        if shutil.which('nginx'):
            if run(['/usr/bin/systemctl', 'is-enabled', 'nginx.service'], check=False, quiet=True).returncode == 0:
                raise Stop('已有系统 Nginx 设置为自启。请先审核其配置并自行取消自启，不能与新 edge 抢占 80/443。')
    if shutil.which('mysql'):
        if not saved and not args.reuse_mysql:
            raise Stop('检测到已有 MySQL；核实后显式使用 --reuse-mysql。不改 root 密码、不清库。')
        inspect_mysql(args)
    elif Path('/var/lib/mysql').exists() and any(Path('/var/lib/mysql').iterdir()):
        raise Stop('发现已有 MySQL 数据目录但无客户端；拒绝安装覆盖未知数据库')


def runtime(*args, capture=False):
    cmd = [str(BASE / '.venv/bin/python'), '-I', '-m', 'servicegateway.deploykit', *args]
    if capture:
        return run(cmd, quiet=True).stdout
    # Keep tty for hidden PKI-password entry. No secrets in stdout or argv.
    result = subprocess.run(cmd, env=ENV)
    if result.returncode: raise Stop('ServiceGateway 初始化步骤失败；已有凭据/数据保留，可修复后重跑。')


def setup_database(args, saved):
    mkdir(CFG)
    if not saved:
        if mysql(args, "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='servicegateway';"):
            raise Stop('同名数据库已存在，不自动接管或清空')
        if mysql(args, "SELECT User FROM mysql.user WHERE User IN ('sg_runtime','sg_migrate');"):
            raise Stop('预留的数据库账号名已存在，不覆盖密码/权限')
        saved = {'domain': args.domain, 'email': args.email, 'admin_cidrs': args.admin_cidr,
                 'admin_user': args.admin_user, 'database_created': False,
                 'runtime_password': 'Sg1!' + secrets.token_hex(32), 'migration_password': 'Sg1!' + secrets.token_hex(32)}
        write(STATE, json.dumps(saved, indent=2) + '\n')
    # Passwords exist in a root-only journal before MySQL CREATE USER, making interruption resumable.
    mysql(args, "CREATE DATABASE IF NOT EXISTS servicegateway CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n"
          f"CREATE USER IF NOT EXISTS 'sg_runtime'@'127.0.0.1' IDENTIFIED BY '{saved['runtime_password']}';\n"
          f"CREATE USER IF NOT EXISTS 'sg_migrate'@'127.0.0.1' IDENTIFIED BY '{saved['migration_password']}';\n"
          "GRANT SELECT, INSERT, UPDATE, DELETE ON servicegateway.* TO 'sg_runtime'@'127.0.0.1';\n"
          "GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES ON servicegateway.* TO 'sg_migrate'@'127.0.0.1';\n")
    # Never reset an existing account; credential mismatch will stop the migration.
    common = (f'SG_PUBLIC_ORIGIN=https://{saved["domain"]}\nSG_DEPLOYMENT_MODE=remote\n'
              'SG_SECURE_COOKIE=true\nSG_SESSION_IDLE_MINUTES=30\n')
    for filename, user, key in [('app.env', 'sg_runtime', 'runtime_password'), ('migrate.env', 'sg_migrate', 'migration_password')]:
        path = CFG / filename
        if not path.exists():
            write(path, f'SG_DATABASE_URL=mysql+pymysql://{user}:{saved[key]}@127.0.0.1:3306/servicegateway?charset=utf8mb4\n' + common)
    if not (CFG / 'policy.json').exists():
        policy = json.loads((ROOT / 'deploy/policy.example.json').read_text())
        policy.update(management_host=saved['domain'],
                      management_ip_filter=bool(saved['admin_cidrs']),
                      management_allow_cidrs=['127.0.0.1/32', *saved['admin_cidrs']] if saved['admin_cidrs'] else [],
                      listen_address='0.0.0.0', acme_enabled=True)
        write(CFG / 'policy.json', json.dumps(policy, indent=2) + '\n', 0o640)
    saved['database_created'] = True
    write(STATE, json.dumps(saved, indent=2) + '\n')
    return saved


def backup_database(args):
    directory = Path('/var/backups/servicegateway')
    mkdir(directory)
    path = directory / (time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + secrets.token_hex(3) + '.sql')
    command = ['/usr/bin/mysqldump']
    command.append('--defaults-extra-file=' + str(owned(args.mysql_admin_file, True)) if args.mysql_admin_file else '--no-defaults')
    command += ['--protocol=socket', '--user=root', '--single-transaction', '--no-tablespaces', '--set-gtid-purged=OFF', '--skip-add-drop-table', 'servicegateway']
    with path.open('x') as out:
        os.chmod(path, 0o600)
        result = subprocess.run(command, stdout=out, stderr=subprocess.DEVNULL, env=ENV)
    if result.returncode:
        path.rename(path.with_suffix('.failed'))
        raise Stop('升级前数据库备份失败，未继续迁移')
    shutil.copy2(CFG / 'app.env', directory / (path.stem + '.app.env'))
    shutil.copy2(CFG / 'policy.json', directory / (path.stem + '.policy.json'))
    print(f'升级前备份已保存到 {path}；包含敏感数据，权限仅限 root。')


def install_timers():
    for name in ('servicegateway-renew.service', 'servicegateway-renew.timer'):
        write(Path('/etc/systemd/system') / name, (ROOT / 'deploy' / name).read_text(), 0o644)
    write(Path('/usr/local/sbin/servicegateway-cert-deploy'),
          '#!/bin/sh\nexec /srv/e5-apps/servicegateway/current/.venv/bin/python -I -m servicegateway.deploykit sync-certificates\n', 0o755)
    run(['/usr/bin/systemctl', 'daemon-reload'])
    run(['/usr/bin/systemctl', 'enable', '--now', 'servicegateway-renew.timer'])


def main(argv=None):
    args = parser().parse_args(argv)
    if args.dry_run:
        # Deliberately do not read root state, resolve DNS, or require root for a plan.
        plan(args); return 0
    if os.geteuid() != 0: raise Stop('请使用 sudo bash deploy/full-deploy.sh ...')
    os.umask(0o077)
    # A signal must unwind package-start suppression. SIGKILL/power loss is detected next run.
    def interrupted(signum, frame): raise Stop('部署已中断；保留已有数据，检查当前阶段后重跑。')
    signal.signal(signal.SIGTERM, interrupted)
    lock_path = Path('/run/servicegateway-install.lock')
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise Stop('已有安装/维护任务运行')
        saved = json.loads(owned(STATE, True).read_text()) if STATE.exists() else {}
        validate_args(args, saved)
        if args.action != 'install':
            if not saved or not (BASE / '.venv/bin/python').exists(): raise Stop('请先完成 install')
            if args.action == 'certificate':
                dns_check(args.domain)
                runtime('certificate', '--domain', args.domain, '--certificate-id', args.certificate_id,
                        '--agree-tos', *(['--skip-acme-test'] if args.skip_acme_test else []))
            elif args.action == 'pki-refresh':
                runtime('pki-refresh', *(['--pki-pass-file', str(owned(args.pki_pass_file, True))] if args.pki_pass_file else []))
            else: runtime(args.action)
            return 0
        dns_check(args.domain)
        check_host(saved, args)
        print('检查通过；开始安装独立网关依赖，不更改 SSH、防火墙和云安全组。', flush=True)
        existing_nginx, existing_mysql = bool(shutil.which('nginx')), bool(shutil.which('mysql'))
        with suppress_package_start():
            run(['/usr/bin/apt-get', 'update', '-qq'])
            run(['/usr/bin/apt-get', 'install', '-y', '--no-upgrade', *PACKAGES])
        if not existing_nginx:
            run(['/usr/bin/systemctl', 'disable', 'nginx.service'])
        if not existing_mysql:
            write(Path('/etc/mysql/mysql.conf.d/servicegateway-local.cnf'),
                  '[mysqld]\nbind-address=127.0.0.1\nmysqlx-bind-address=127.0.0.1\nlocal-infile=0\n', 0o644)
            run(['/usr/bin/systemctl', 'enable', '--now', 'mysql.service'])
        inspect_mysql(args)
        if saved and saved.get('database_created'): backup_database(args)
        saved = setup_database(args, saved)
        # Public challenge directory contains only CA tokens, never credentials or app content.
        mkdir('/var/lib/servicegateway', 0o755)
        for path in ('/var/lib/servicegateway/acme-webroot', '/var/lib/servicegateway/acme-webroot/.well-known',
                     '/var/lib/servicegateway/acme-webroot/.well-known/acme-challenge'):
            mkdir(path, 0o755); os.chmod(path, 0o755)
        # The existing installer has code/unit rollback and never auto-rolls back database data.
        child_env = {**ENV, 'SG_BOOTSTRAP': '1'}
        result = subprocess.run(['/bin/bash', str(ROOT / 'deploy/install.sh')], env=child_env)
        if result.returncode: raise Stop('应用安装失败；未继续签发/激活，按安装器回退结果排查')
        runtime('init-admin')
        runtime('certificate', '--domain', saved['domain'], '--certificate-id', 'admin', '--agree-tos',
                *(['--skip-acme-test'] if args.skip_acme_test else []))
        runtime('init-pki', *(['--pki-pass-file', str(owned(args.pki_pass_file, True))] if args.pki_pass_file else []))
        runtime('activate')
        install_timers()
        runtime('status')
        print(f'部署完成： https://{saved["domain"]}/\n'
              '先将 /root/servicegateway-access/admin-browser.p12 安全传到管理电脑并导入，再登录。\n'
              '初始管理员密码仅存于 /root/servicegateway-access/admin-password；重跑不会重置。\n'
              'CA 恢复包是加密的，请异地备份并记住其口令；当前 SSH/防火墙规则未改动。\n'
              '完整说明：docs/FULL-DEPLOYMENT.md。还需从外部核实端口和真实业务。')
    return 0


if __name__ == '__main__':
    try: sys.exit(main())
    except (Stop, ValueError, OSError, KeyboardInterrupt, subprocess.TimeoutExpired) as exc:
        print(f'停止：{exc}', file=sys.stderr)
        sys.exit(1)
