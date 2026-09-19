"""Mandatory CI check using a real systemd mount sandbox, not nginx -t alone.

Run on the disposable Ubuntu Actions VM, never a production server. Makes only
unique /run test files and transient units. Masks Nginx's compiled default temp
directory read-only *inside* those units; never changes the host's Nginx files.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from servicegateway.nginx import render
from servicegateway.schemas import Snapshot


def run(args, **kwargs):
    return subprocess.run(args, text=True, capture_output=True, timeout=60, **kwargs)


def main():
    if Path('/proc/1/comm').read_text().strip() != 'systemd':
        raise SystemExit('This smoke check requires a systemd VM (not a container)')
    nginx = '/usr/sbin/nginx'
    build = run([nginx, '-V'])
    if '--http-fastcgi-temp-path=/var/lib/nginx/' not in build.stderr:
        raise SystemExit('This fresh-host test targets Ubuntu/Debian packaged Nginx')
    root = '/run/sg-nginx-smoke-' + uuid.uuid4().hex
    subprocess.run(['sudo', '-n', 'install', '-d', '-m', '0755', root], check=True)
    try:
        snap = Snapshot()
        text = render(snap, {}, snap.digest(), 'a'*64)
        text = text.replace('/run/servicegateway-edge', root)
        text = text.replace('/srv/e5-logs/servicegateway', root)
        text = text.replace('/var/lib/servicegateway/edge', root)
        old = ''.join(line for line in text.splitlines(keepends=True)
                      if not any(name + '_temp_path ' in line for name in ('fastcgi', 'uwsgi', 'scgi')))
        for name, config in (('old', old), ('fixed', text)):
            with tempfile.NamedTemporaryFile(mode='w') as file:
                file.write(config); file.flush()
                subprocess.run(['sudo', '-n', 'install', '-m', '0600', file.name, root+'/'+name+'.conf'], check=True)
            args = ['sudo', '-n', 'systemd-run', '--quiet', '--wait', '--pipe', '--collect',
                    '--unit=sg-nginx-' + uuid.uuid4().hex,
                    '-p', 'ProtectSystem=strict', '-p', 'ProtectHome=true', '-p', 'PrivateTmp=true',
                    '-p', 'ReadWritePaths=' + root,
                    '-p', 'TemporaryFileSystem=/var/lib/nginx:ro',
                    nginx, '-e', 'stderr', '-t', '-p', root, '-c', root+'/'+name+'.conf']
            result = run(args)
            print(f'[{name}] exit={result.returncode}\n{result.stdout}{result.stderr}')
            output = result.stdout + result.stderr
            if name == 'old':
                assert result.returncode != 0 and '/var/lib/nginx/fastcgi' in output
                assert 'Read-only file system' in output
            else:
                assert result.returncode == 0, result.stderr
        print('PASS: missing compile-time temp paths reproduced; fixed config passes strict systemd sandbox')
    finally:
        subprocess.run(['sudo', '-n', 'rm', '-rf', '--', root], check=True)


if __name__ == '__main__':
    main()
