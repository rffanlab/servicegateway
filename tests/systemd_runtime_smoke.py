"""Disposable Actions VM: a real wheel, bootstrap umask 077 and non-root systemd.

Unique /srv files, temporary user, transient units and servicegateway_test only.
No production paths/ports are used. The probe performs no database mutations.
"""
import importlib.util
import os
from pathlib import Path
import pwd
import shutil
import socket
import stat
import subprocess
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]


def call(args, **kwargs):
    return subprocess.run(args, text=True, capture_output=True, timeout=90, **kwargs)


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.geteuid() != 0:
        raise SystemExit('Run only as root in the disposable GitHub Actions VM')
    if Path('/proc/1/comm').read_text().strip() != 'systemd':
        raise SystemExit('A real systemd host is required')
    database = os.environ.get('SG_DATABASE_URL', '')
    if not database.endswith('/servicegateway_test?charset=utf8mb4'):
        raise SystemExit('Only the disposable CI database is permitted')
    user = 'sg-runtime-ci'
    try:
        pwd.getpwnam(user)
    except KeyError:
        pass
    else:
        raise SystemExit('Refusing to reuse an existing test user')
    prefix = 'sg-runtime-' + uuid.uuid4().hex
    base = Path('/srv') / prefix
    base.mkdir(mode=0o755)
    os.umask(0o077)
    started = []
    created_user = False
    try:
        subprocess.run(['/usr/sbin/useradd', '--system', '--no-create-home', '--user-group',
                        '--shell', '/usr/sbin/nologin', user], check=True)
        created_user = True
        account = pwd.getpwnam(user)
        broken = base / 'broken'
        subprocess.run(['/usr/bin/python3', '-m', 'venv', '--without-pip', str(broken)], check=True)
        assert stat.S_IMODE((broken/'bin').stat().st_mode) == 0o700
        def transient(tag, command, *properties, wait=True):
            name = prefix + '-' + tag
            args = ['/usr/bin/systemd-run', '--quiet', '--collect', '--unit='+name,
                    '-p', 'User='+user, '-p', 'Group='+user,
                    '-p', 'ProtectSystem=strict', '-p', 'ProtectHome=true', '-p', 'PrivateTmp=true',
                    '-p', 'NoNewPrivileges=true', '-p', 'UMask=0077', '-p', 'TimeoutStartSec=60']
            for property in properties:
                args += ['-p', property]
            if wait:
                args += ['--wait', '--pipe']
            else:
                started.append(name)
            return call([*args, *command])
        old = transient('old', [str(broken/'bin/python'), '-I', '-c', 'print("not reached")'])
        assert old.returncode != 0
        print('PASS: inherited umask 077 prevents non-root execution of the old virtualenv')
        release = base / 'release'
        release.mkdir(mode=0o755)
        release.chmod(0o755)
        for name in ('pyproject.toml', 'servicegateway'):
            source = ROOT / name
            if source.is_dir():
                shutil.copytree(source, release / name, ignore=shutil.ignore_patterns('__pycache__'))
            else:
                shutil.copy2(source, release / name)
        script = (ROOT / 'deploy/install.sh').read_text()
        block = script.split('# BEGIN RUNTIME BUILD\n', 1)[1].split('# END RUNTIME BUILD', 1)[0]
        env = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'HOME':'/root', 'release':str(release),
               'PIP_CONFIG_FILE':'/dev/null', 'PIP_INDEX_URL':'https://pypi.org/simple'}
        subprocess.run(['/bin/bash', '-c', 'set -Eeuo pipefail\numask 077\n'+block],
                       env=env, check=True, timeout=240)
        assert stat.S_IMODE((release/'.venv/bin').stat().st_mode) == 0o755
        assert (release/'.venv/bin/uvicorn').stat().st_mode & 0o005 == 0o005
        cfg = base / 'config'; cfg.mkdir(mode=0o750); cfg.chmod(0o750)
        os.chown(cfg, 0, account.pw_gid)
        secret = cfg / 'auth-secret'; secret.write_text('a'*64)
        os.chown(secret, 0, account.pw_gid); secret.chmod(0o640)
        envfile = cfg / 'app.env'
        envfile.write_text(f'SG_DATABASE_URL={database}\nSG_TESTING=true\n'
                           'SG_MONITOR_ENABLED=false\nSG_PUBLIC_ORIGIN=https://admin.example.test\n'
                           f'SG_AUTH_SECRET_FILE={secret}\n')
        assert stat.S_IMODE(envfile.stat().st_mode) == 0o600
        props = [f'EnvironmentFile={envfile}', f'WorkingDirectory={release}']
        checked = transient('preflight', [str(release/'.venv/bin/python'), '-I', '-m',
                                         'servicegateway.runtimecheck'], *props)
        print(checked.stdout, checked.stderr)
        assert checked.returncode == 0, 'Non-root wheel/import/MySQL preflight failed'
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        launched = transient('api', [str(release/'.venv/bin/python'), '-I', '-m', 'uvicorn',
                                     'servicegateway.main:create_app', '--factory', '--host', '127.0.0.1',
                                     '--port', str(port), '--workers', '1', '--no-proxy-headers', '--no-access-log'],
                              *props, wait=False)
        assert launched.returncode == 0, launched.stderr
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(50):
            try:
                with client.open(f'http://127.0.0.1:{port}/readyz', timeout=1) as response:
                    assert response.status == 200
                    break
            except (OSError, urllib.error.URLError):
                time.sleep(.2)
        else:
            logs = call(['/usr/bin/journalctl', '-u', prefix+'-api', '-n', '40', '--no-pager'])
            raise AssertionError(logs.stdout.replace(database, '[CI database URL redacted]'))
        with client.open(f'http://127.0.0.1:{port}/static/app.js', timeout=2) as response:
            assert response.status == 200 and response.read(16)
        try:
            client.open(f'http://127.0.0.1:{port}/api/overview', timeout=2)
        except urllib.error.HTTPError as exc:
            assert exc.code == 401
        else:
            raise AssertionError('Unauthenticated management request was not denied')
        for args in (['test', '-r', str(envfile)], ['test', '-w', str(release/'.venv')]):
            assert call(['/usr/sbin/runuser', '-u', user, '--', *args]).returncode != 0
        info = call(['/usr/bin/systemctl', 'show', prefix+'-api', '--property=User', '--value'])
        assert info.stdout.strip() == user
        spec = importlib.util.spec_from_file_location('sg_diag_real', ROOT/'deploy/diagnose.py')
        diag = importlib.util.module_from_spec(spec); spec.loader.exec_module(diag)
        diag.REPORTS = cfg / 'deploy-reports'
        path = diag.save_report('Isolated CI diagnosis, no secrets\n')
        assert stat.S_IMODE(path.stat().st_mode) == 0o600 and path.stat().st_uid == 0
        assert stat.S_IMODE(diag.REPORTS.stat().st_mode) == 0o700
        assert call(['/usr/sbin/runuser', '-u', user, '--', 'test', '-r', str(path)]).returncode != 0
        print('PASS: real non-root API starts in strict systemd sandbox and serves readiness/static/401')
        print('PASS: app.env and diagnostic reports stay root-only; runtime cannot modify installed code')
    finally:
        for unit in started:
            call(['/usr/bin/systemctl', 'stop', unit])
        shutil.rmtree(base)
        if created_user:
            call(['/usr/sbin/userdel', user])


if __name__ == '__main__':
    main()
