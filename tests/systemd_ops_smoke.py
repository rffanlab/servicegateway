"""Ephemeral CI VM only: real socket permissions and encrypted service credentials.

No application data/ports. Uses disposable users, transient units and /run paths.
"""
import os
from pathlib import Path
import pwd
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid


def run(args, **kwargs):
    p = subprocess.run(args, capture_output=True, text=True, timeout=90, **kwargs)
    if p.returncode:
        raise RuntimeError(f'{args[0]} failed: {p.stdout[-1000:]} {p.stderr[-1500:]}')
    return p


def main():
    if os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true' or Path('/proc/1/comm').read_text().strip() != 'systemd':
        raise SystemExit('This destructive-isolated smoke check is for disposable GitHub Actions VMs only')
    tag = uuid.uuid4().hex[:10]
    user = 'sgops' + tag
    root = Path('/run/sg-ops-' + tag)
    root.mkdir(mode=0o755)
    units = []
    run(['/usr/sbin/useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', user])
    try:
        account = pwd.getpwnam(user)
        source = Path(__file__).resolve().parents[1]
        shutil.copytree(source / 'servicegateway', root / 'servicegateway', ignore=shutil.ignore_patterns('__pycache__'))
        log = root / 'traffic.log'
        log.write_text('{"route":"demo","status":200,"seconds":0.1,"bytes":5,"request_id":"test"}\n')
        log.chmod(0o600)
        server = root / 'server.py'
        server.write_text(f'''import os,sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,{str(root)!r})
from servicegateway import agent
agent.ACCESS_LOG=Path({str(log)!r})
path=Path(os.environ['RUNTIME_DIRECTORY'])/'agent.sock'
path.unlink(missing_ok=True)
with agent.Server(str(path),agent.Handler) as s:
    os.chown(path,0,{account.pw_gid});os.chmod(path,0o660)
    s.allowed_uid={account.pw_uid}
    s.broker=agent.Broker(SimpleNamespace(auth_secret=lambda:'a'*64))
    s.serve_forever()
''')
        server.chmod(0o644)
        client = root / 'client.py'
        client.write_text(f'''import sys
sys.path.insert(0,{str(root)!r})
from servicegateway.ipc import AgentClient,AgentError
c=AgentClient(sys.argv[1])
try:
    x=c.call('traffic')
except AgentError:
    raise SystemExit(13)
assert x['sample'][0]['status']==200
try:c.call('install-crl',pem='not-a-crl')
except AgentError as e:assert 'local-root-only' in str(e)
else:raise AssertionError('Web UID must not install CRLs')
print('Web UID can read bounded traffic via socket, but cannot perform root maintenance')
''')
        client.chmod(0o644)
        for old in (True, False):
            name = 'sg-ops-' + tag + ('-old' if old else '-fixed')
            unit = name + '.service'; units.append(unit)
            args = ['/usr/bin/systemd-run', '--quiet', '--collect', '--unit=' + name,
                    '-p', 'User=root', '-p', 'Group=' + ('root' if old else user),
                    '-p', 'RuntimeDirectory=' + name, '-p', 'RuntimeDirectoryMode=0750',
                    '-p', 'UMask=0077', '-p', 'ProtectSystem=strict', '-p', 'ProtectHome=true',
                    '-p', 'NoNewPrivileges=true']
            if old:
                args += ['-p', 'ExecStartPre=/usr/bin/chgrp ' + user + ' /run/' + name]
            args += [sys.executable, '-I', str(server)]
            run(args)
            path = Path('/run') / name / 'agent.sock'
            for _ in range(100):
                if path.exists():break
                time.sleep(.1)
            else:
                raise RuntimeError(run(['/usr/bin/journalctl','-u',unit,'--no-pager','-n','20']).stdout)
            peer = subprocess.run(['/usr/sbin/runuser', '-u', user, '--', sys.executable, '-I', str(client), str(path)], capture_output=True, text=True)
            if old:
                assert peer.returncode == 13, peer.stdout + peer.stderr
                print('Reproduced: Group=root resets RuntimeDirectory despite ExecStartPre chgrp')
            else:
                assert path.parent.stat().st_gid == account.pw_gid
                assert stat.S_IMODE(path.parent.stat().st_mode) == 0o750
                assert peer.returncode == 0, peer.stdout + peer.stderr
                outsider = subprocess.run(['/usr/sbin/runuser', '-u', 'nobody', '--', sys.executable, '-I', str(client), str(path)], capture_output=True)
                assert outsider.returncode == 13
                run(['/usr/bin/systemctl', 'restart', unit])
                for _ in range(100):
                    peer = subprocess.run(['/usr/sbin/runuser','-u',user,'--',sys.executable,'-I',str(client),str(path)],capture_output=True,text=True)
                    if peer.returncode==0:break
                    time.sleep(.1)
                assert peer.returncode==0,peer.stderr
                print('Fixed socket group survives restart; unrelated UID denied')
            run(['/usr/bin/systemctl','stop',unit])
        secret = 'DISPOSABLE-CI-ONLY-123456'
        credential = root / 'passphrase.cred'; credential.touch(mode=0o600)
        run(['/usr/bin/systemd-creds','encrypt','--with-key=host','--name=pki-passphrase','-',str(credential)],input=secret)
        assert secret.encode() not in credential.read_bytes()
        test = root / 'check-credential.py'
        test.write_text(f'''import os,stat
from pathlib import Path
p=Path(os.environ['CREDENTIALS_DIRECTORY'])/'pki-passphrase'
assert p.read_text()=={secret!r}
assert not p.stat().st_mode & 0o077
print('Encrypted systemd credential loaded privately; no credential printed')
''')
        name = 'sg-ops-' + tag + '-credential';units.append(name+'.service')
        run(['/usr/bin/systemd-run','--quiet','--wait','--pipe','--collect','--unit='+name,
             '-p','Type=oneshot','-p','User=root','-p','ProtectSystem=strict','-p','ProtectHome=read-only',
             '-p','LoadCredentialEncrypted=pki-passphrase:'+str(credential),sys.executable,'-I',str(test)])
        print('PASS: real systemd socket and credential regression checks')
    finally:
        for unit in units:
            subprocess.run(['/usr/bin/systemctl','stop',unit],capture_output=True)
        subprocess.run(['/usr/sbin/userdel',user],capture_output=True)
        shutil.rmtree(root)


if __name__ == '__main__':
    main()
