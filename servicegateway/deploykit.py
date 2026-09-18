"""Local root deployment/renewal helpers. Not exposed by the management HTTP API."""
import argparse
import contextlib
from datetime import datetime, UTC, timedelta
import fcntl
import getpass
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import tarfile
import tempfile
import time
from cryptography import x509
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from sqlalchemy import select
from .agent import atomic_write, root_file
from .certificates import ACME, MAPPING, load_mapping
from .config import Settings
from .db import Audit, User, database
from .ingress import valid_host, LoopbackTLS
from .ipc import AgentClient
from .security import ph

CFG = Path('/etc/servicegateway')
ACCESS = Path('/root/servicegateway-access')
ARCHIVE = ACCESS / 'client-ca.sgpki'
CERTS = CFG / 'certs'
WEBROOT = Path('/var/lib/servicegateway/acme-webroot')
MAGIC = b'SGPKI1\0'
PKI_TEMP = Path('/run')


def command(args, *, data=None, check=True, timeout=1800, pass_fds=()):
    p = subprocess.run([str(x) for x in args], input=data, capture_output=True,
                       timeout=timeout, pass_fds=pass_fds,
                       env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','HOME':'/root'})
    if check and p.returncode:
        raise ValueError(f'{Path(str(args[0])).name} failed ({p.returncode}); '
                         '检查对应本机日志，不输出命令输入或私钥')
    return p


def settings():
    # No source/eval; this file is parsed as dotenv, then validated by Settings.
    return Settings(_env_file=root_file(CFG / 'app.env'))


def state():
    return json.loads(root_file(CFG / 'bootstrap.json').read_text())


def mkdir(path, mode=0o700):
    if path.is_symlink(): raise ValueError('Symlink directory rejected')
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    if path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
        raise ValueError('Directory must be owned and writable only by root')


def bytes_write(path, data):
    if path.exists(): root_file(path)
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data); out.flush(); os.fsync(out.fileno())
        os.chmod(name, 0o600); os.replace(name, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(name): os.unlink(name)


def init_admin():
    saved = state()
    engine, sessions = database(settings())
    mkdir(ACCESS)
    password_file = ACCESS / 'admin-password'
    with sessions.begin() as db:
        user = db.scalar(select(User).where(User.username == saved['admin_user']))
        if user:
            print('管理员已存在；未重置密码或权限。')
        else:
            password = root_file(password_file).read_text().strip() if password_file.exists() else secrets.token_urlsafe(32)
            if not password_file.exists(): atomic_write(password_file, password + '\n')
            db.add(User(username=saved['admin_user'], password_hash=ph.hash(password), role='admin'))
            db.add(Audit(actor='local-bootstrap', action='admin.create', target=saved['admin_user'], outcome='success', detail='Password not logged'))
            print(f'初始管理员已创建，密码只写入 {password_file}。')
    engine.dispose()


def certbot_args():
    for directory in (ACME, Path('/var/lib/servicegateway/certbot'), Path('/srv/e5-logs/servicegateway/certbot')):
        mkdir(directory)
    return ['/usr/bin/certbot', '--config', '/dev/null', '--config-dir', str(ACME), '--work-dir', '/var/lib/servicegateway/certbot',
            '--logs-dir', '/srv/e5-logs/servicegateway/certbot', '--non-interactive', '--no-directory-hooks']


def challenge_probe(host):
    token, value = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    path = WEBROOT / '.well-known/acme-challenge' / token
    atomic_write(path, value, 0o644)
    import http.client
    conn = http.client.HTTPConnection('127.0.0.1', 80, timeout=5)
    try:
        conn.request('GET', '/.well-known/acme-challenge/' + token, headers={'Host': host})
        response = conn.getresponse()
        if response.status != 200 or response.read(1024).decode() != value:
            raise ValueError('网关 HTTP-01 验证目录不可用。请检查 acme_enabled 和实际监听，不停止生产 HTTPS。')
    finally:
        conn.close(); path.unlink(missing_ok=True)


def issue_certificate(args):
    import re
    if (not args.agree_tos or not valid_host(args.domain) or
            not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', args.certificate_id or '')):
        raise ValueError('签发需要明确域名、证书 ID 和 --agree-tos')
    saved = state()
    mapping = load_mapping()
    row = {'domain': args.domain, 'lineage':'sg-' + args.certificate_id}
    if args.certificate_id in mapping and mapping[args.certificate_id] != row:
        raise ValueError('证书 ID 已绑定其他域名，拒绝覆盖')
    policy = json.loads(root_file(CFG / 'policy.json').read_text())
    if not policy.get('acme_enabled'): raise ValueError('先启用网关的独立 HTTP-01 webroot')
    challenge_probe(args.domain)
    base = certbot_args() + ['certonly', '--webroot', '-w', str(WEBROOT), '--preferred-challenges', 'http',
                              '--cert-name', row['lineage'], '-d', args.domain,
                              '--email', saved['email'], '--agree-tos', '--no-eff-email', '--key-type', 'ecdsa', '--keep-until-expiring']
    renewal = ACME / 'renewal' / (row['lineage'] + '.conf')
    if not renewal.exists() and not args.skip_acme_test:
        print('先执行 Let\'s Encrypt staging 验证，不把测试证书装进生产。', flush=True)
        command(base + ['--dry-run'])
    command(base)
    mapping[args.certificate_id] = row
    atomic_write(MAPPING, json.dumps(mapping, indent=2) + '\n')
    sync_certificates()
    print(f'证书已申请并验证：{args.domain}；控制台证书 ID：{args.certificate_id}')


def sync_certificates():
    result = AgentClient(settings().agent_socket).call('sync-certificates')
    print(json.dumps(result, ensure_ascii=False))


def password(args):
    if args.pki_pass_file:
        path = root_file(args.pki_pass_file)
        if path.stat().st_mode & 0o077: raise ValueError('PKI 密码文件必须为 0600')
        value = path.read_text().strip()
    else:
        if not os.isatty(0): raise ValueError('PKI 初始化需要终端或 root-only --pki-pass-file')
        value = getpass.getpass('客户端证书/离线 CA 恢复包口令（至少 16 位，请自行保存）: ')
        if not ARCHIVE.exists() and value != getpass.getpass('再次输入口令: '):
            raise ValueError('两次口令不一致')
    if not 16 <= len(value) <= 256 or '\n' in value or '\r' in value:
        raise ValueError('口令必须为 16..256 字符且不包含换行')
    return value.encode()


def seal(data, secret):
    salt, nonce = os.urandom(16), os.urandom(12)
    key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(secret)
    return MAGIC + salt + nonce + AESGCM(key).encrypt(nonce, data, MAGIC)


def unseal(data, secret):
    if not data.startswith(MAGIC) or len(data) > 16 * 1024 * 1024:
        raise ValueError('Invalid recovery archive')
    offset = len(MAGIC)
    salt, nonce = data[offset:offset+16], data[offset+16:offset+28]
    key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(secret)
    try: return AESGCM(key).decrypt(nonce, data[offset+28:], MAGIC)
    except Exception as exc: raise ValueError('恢复包口令错误或内容损坏；未改变现有证书') from exc


def ca_config(directory):
    config = directory / 'openssl.cnf'
    config.write_text(f'''[ ca ]
default_ca = local
[ local ]
database = {directory}/index
new_certs_dir = {directory}/newcerts
certificate = {directory}/ca.pem
private_key = {directory}/ca.key
serial = {directory}/serial
crlnumber = {directory}/crlnumber
default_md = sha256
default_days = 365
default_crl_days = 90
unique_subject = no
policy = policy_any
x509_extensions = client
[ policy_any ]
commonName = supplied
[ client ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
''')
    return config


def new_client(directory, name, config, days):
    command(['/usr/bin/openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=sg-' + name,
             '-keyout', directory / (name + '.key'), '-out', directory / (name + '.csr')])
    command(['/usr/bin/openssl', 'ca', '-batch', '-config', config, '-days', str(days),
             '-in', directory / (name + '.csr'), '-out', directory / (name + '.crt')])


def export_p12(directory, secret):
    r, w = os.pipe()
    try:
        os.write(w, secret + b'\n'); os.close(w); w = -1
        command(['/usr/bin/openssl', 'pkcs12', '-export', '-inkey', directory / 'browser.key',
                 '-in', directory / 'browser.crt', '-certfile', directory / 'ca.pem',
                 '-name', 'ServiceGateway administrator', '-out', directory / 'admin-browser.p12',
                 '-passout', 'fd:' + str(r)], pass_fds=(r,))
    finally:
        os.close(r)
        if w != -1: os.close(w)
    return (directory / 'admin-browser.p12').read_bytes()


def save_archive(directory, secret):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
        for item in sorted(directory.iterdir()):
            if item.name not in ('openssl.cnf', 'admin-browser.p12'):
                archive.add(item, arcname=item.name, recursive=True)
    bytes_write(ARCHIVE, seal(buffer.getvalue(), secret))


def init_pki(args, refresh=False):
    ca = CERTS / 'admin-ca'
    required = ('ca.pem', 'crl.pem', 'probe.crt', 'probe.key', 'browser.crt')
    if not refresh and ARCHIVE.exists() and (ACCESS / 'admin-browser.p12').exists() and all((ca / x).exists() for x in required):
        print('管理 mTLS 已初始化；未重置 CA、客户端证书或口令。'); return
    mkdir(ACCESS); mkdir(ca)
    secret = password(args)
    # Signer and browser private keys only exist in tmpfs during this operation.
    with tempfile.TemporaryDirectory(prefix='sg-pki-', dir=PKI_TEMP) as work:
        directory = Path(work)
        if ARCHIVE.exists():
            plain = unseal(root_file(ARCHIVE).read_bytes(), secret)
            with tarfile.open(fileobj=io.BytesIO(plain), mode='r:gz') as archive:
                if sum(m.size for m in archive.getmembers()) > 16 * 1024 * 1024:
                    raise ValueError('Recovery archive exceeds limit')
                if any(m.issym() or m.islnk() or not (m.isfile() or m.isdir()) for m in archive.getmembers()):
                    raise ValueError('Recovery archive contains non-regular files')
                archive.extractall(directory, filter='data')
        else:
            (directory / 'newcerts').mkdir()
            for name, value in [('index',''),('index.attr','unique_subject = no\n'),('serial','1000\n'),('crlnumber','1000\n')]:
                (directory / name).write_text(value)
            command(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '7300',
                     '-subj', '/CN=ServiceGateway private client CA', '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
                     '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', directory / 'ca.key', '-out', directory / 'ca.pem'])
        config = ca_config(directory)
        if not (directory / 'probe.crt').exists(): new_client(directory, 'probe', config, 3650)
        browser = directory / 'browser.crt'
        if not browser.exists():
            new_client(directory, 'browser', config, 365)
        elif refresh and x509.load_pem_x509_certificate(browser.read_bytes()).not_valid_after_utc < datetime.now(UTC) + timedelta(days=30):
            command(['/usr/bin/openssl', 'ca', '-config', config, '-revoke', browser])
            new_client(directory, 'browser', config, 365)
            print('浏览器证书接近到期，已生成替换证书；请重新导入 p12，旧证书在更新 CRL 后失效。')
        command(['/usr/bin/openssl', 'ca', '-gencrl', '-config', config, '-out', directory / 'crl.pem'])
        p12 = export_p12(directory, secret)
        # Persist encrypted recovery before installing public CA/CRL so a retry is reconstructible.
        save_archive(directory, secret)
        bytes_write(ACCESS / 'admin-browser.p12', p12)
        for name in required:
            bytes_write(ca / name, (directory / name).read_bytes())
    if refresh:
        AgentClient(settings().agent_socket).call('reload-tls')
    print(f'客户端证书：{ACCESS}/admin-browser.p12；加密 CA 恢复包：{ARCHIVE}。\n'
          '签名私钥已从临时目录移除，仅在口令加密恢复包中保留。CRL 90 天有效，建议每月运行 pki-refresh。')


def activate():
    path = CFG / 'policy.json'
    policy = json.loads(root_file(path).read_text())
    if policy.get('ingress_enabled'):
        print('统一入口已激活；保留现有路由和策略。'); return
    original = path.read_text()
    policy['ingress_enabled'] = True
    atomic_write(path, json.dumps(policy, indent=2) + '\n', 0o640)
    try:
        AgentClient(settings().agent_socket).call('bootstrap-ingress')
    except Exception:
        atomic_write(path, original, 0o640)
        raise
    print('已通过本机 Agent 激活 80/443。')


def renew_test():
    command(certbot_args() + ['renew', '--dry-run'])
    print('Let\'s Encrypt staging 续期演练通过；未替换生产证书、未运行部署钩子。')


def health_report():
    problems = []
    for cert_id, row in load_mapping().items():
        try:
            cert = x509.load_pem_x509_certificate(root_file(CERTS / cert_id / 'fullchain.pem').read_bytes())
            days = (cert.not_valid_after_utc - datetime.now(UTC)).days
            print(f'TLS {row["domain"]}: 剩余 {days} 天')
            if days < 14: problems.append('服务器证书临近到期: ' + cert_id)
        except (OSError, ValueError): problems.append('服务器证书无法读取: ' + cert_id)
    try:
        crl = x509.load_pem_x509_crl(root_file(CERTS / 'admin-ca/crl.pem').read_bytes())
        days = (crl.next_update_utc - datetime.now(UTC)).days
        print(f'管理客户端 CRL: 剩余 {days} 天；使用 pki-refresh 提前刷新')
        if days < 30: problems.append('管理客户端 CRL 请运行 pki-refresh')
    except (OSError, ValueError): problems.append('管理客户端 CRL 无法读取')
    for name in ('browser', 'probe'):
        try:
            cert = x509.load_pem_x509_certificate(root_file(CERTS / 'admin-ca' / (name + '.crt')).read_bytes())
            days = (cert.not_valid_after_utc - datetime.now(UTC)).days
            print(f'客户端 {name} 证书: 剩余 {days} 天')
            if days < 30: problems.append('客户端证书即将过期: ' + name)
        except (OSError, ValueError): problems.append('客户端证书无法读取: ' + name)
    if problems: raise ValueError('; '.join(problems))


def renew():
    error = None
    try:
        # Own Certbot config directory: do not take over unrelated system certificates.
        command(certbot_args() + ['renew', '--quiet', '--deploy-hook', '/usr/local/sbin/servicegateway-cert-deploy'])
    except ValueError as exc: error = exc
    # Retry synchronization even when issuance succeeded on a previous day but reload failed.
    sync_certificates()
    health_report()
    if error: raise error


def status():
    for unit in ('servicegateway', 'servicegateway-agent', 'servicegateway-edge', 'servicegateway-renew.timer'):
        name = unit if unit.endswith('.timer') else unit + '.service'
        result = command(['/usr/bin/systemctl', 'is-active', name], check=False)
        print(name + ': ' + result.stdout.decode().strip())
        if result.returncode: raise ValueError('服务/定时器未启动: ' + name)
    print(json.dumps(AgentClient(settings().agent_socket).call('status')))
    health_report()
    host = state()['domain']
    ctx = ssl.create_default_context()
    ctx.load_cert_chain(str(CERTS / 'admin-ca/probe.crt'), str(CERTS / 'admin-ca/probe.key'))
    conn = LoopbackTLS(host, 443, timeout=5, context=ctx)
    try:
        conn.request('GET', '/api/auth/me', headers={'Host': host})
        if conn.getresponse().status != 401:
            raise ValueError('管理 HTTPS/认证边界验证失败')
    finally:
        conn.close()
    print('本机状态正常；外部 80/443、DNS 和防火墙仍需从另一台机器核验。')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('action', choices=['init-admin','certificate','init-pki','pki-refresh','activate','renew','renew-test','sync-certificates','status'])
    p.add_argument('--domain'); p.add_argument('--certificate-id')
    p.add_argument('--agree-tos', action='store_true'); p.add_argument('--skip-acme-test', action='store_true')
    p.add_argument('--pki-pass-file', type=Path)
    args = p.parse_args()
    if os.geteuid() != 0: raise SystemExit('仅允许本机 root 执行')
    os.umask(0o077)
    # Certbot also locks its directories; this lock also covers root certificate-map and PKI changes.
    # A deploy hook runs inside certbot, so synchronization itself must not reacquire this lock.
    @contextlib.contextmanager
    def operation_lock():
        if args.action == 'sync-certificates': yield; return
        mkdir(Path('/var/lib/servicegateway'), 0o755)
        fd = os.open('/var/lib/servicegateway/certificate.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
    with operation_lock():
        if args.action == 'certificate': issue_certificate(args)
        elif args.action in ('init-pki','pki-refresh'): init_pki(args, args.action == 'pki-refresh')
        else: {'init-admin':init_admin,'activate':activate,'renew':renew,'renew-test':renew_test,
               'sync-certificates':sync_certificates,'status':status}[args.action]()


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f'操作未完成：{exc}')
        raise SystemExit(1)
