#!/usr/bin/env python3
"""Read only service diagnostics; --save writes one root-only, redacted report.

No database queries, nginx -T, env dumps, restarts, installs or credential export.
Works from a checkout even after the installer removed current/unit symlinks.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from urllib.parse import unquote

UNITS = ('servicegateway-edge.service', 'servicegateway-agent.service', 'servicegateway.service')
CFG = Path('/etc/servicegateway')
REPORTS = Path('/var/log/servicegateway-deploy')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'SYSTEMD_COLORS': '0'}


def safe_file(path: Path) -> Path:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
        raise ValueError('Unsafe diagnostic source')
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Unsafe source directory')
    return path


def local_secrets() -> set[str]:
    values = set()
    for name in ('app.env', 'migrate.env', 'auth-secret', 'bootstrap.json'):
        try:
            path = safe_file(CFG / name)
            if path.stat().st_size > 262144:
                continue
            content = path.read_text()
            if name == 'auth-secret':
                values.add(content.strip())
            elif name == 'bootstrap.json':
                def visit(obj):
                    if isinstance(obj, dict):
                        for key, value in obj.items():
                            if isinstance(value, str) and any(x in key.lower() for x in ('pass', 'secret', 'token')):
                                values.add(value)
                            else:
                                visit(value)
                    elif isinstance(obj, list):
                        for item in obj:
                            visit(item)
                visit(json.loads(content))
            else:
                for line in content.splitlines():
                    key, sep, value = line.partition('=')
                    if sep and any(x in key.lower() for x in ('database_url', 'pass', 'secret', 'token')):
                        value = value.strip().strip('"\'')
                        values.add(value)
                        for match in re.finditer(r'://[^\s/:@]+:([^\s/@]+)@', value):
                            values.add(match[1]); values.add(unquote(match[1]))
        except (OSError, ValueError):
            # Still use generic redaction when config was removed or malformed.
            continue
    return {v for v in values if len(v) >= 4}


def redact(text: str, secrets=()) -> str:
    for value in sorted(secrets, key=len, reverse=True):
        text = text.replace(value, '[redacted]')
    text = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----',
                  '[private key redacted]', text, flags=re.S)
    text = re.sub(r'(?i)([a-z][a-z0-9+.-]*://[^\s/:@]+:)[^\s/@]+@', r'\1[redacted]@', text)
    text = re.sub(r'(?im)^.*(?:authorization|cookie|x-gateway-key|x-sg-secret)\s*[:=].*$',
                  '[credential-bearing line redacted]', text)
    text = re.sub(r'(?i)\b(password|passwd|token|secret)\s*[:=]\s*[^\s,;]+', r'\1=[redacted]', text)
    return text


def capture(args) -> str:
    try:
        with tempfile.TemporaryFile() as out:
            result = subprocess.run(args, stdout=out, stderr=out, timeout=15, env=ENV)
            size = out.tell(); out.seek(max(0, size - 65536))
            return f'exit={result.returncode}\n' + out.read(65536).decode('utf-8', errors='replace')
    except (OSError, subprocess.TimeoutExpired) as exc:
        return type(exc).__name__


def report() -> str:
    parts = ['ServiceGateway startup diagnostics (no configuration/credential dump)',
             datetime.now(timezone.utc).isoformat()]
    for unit in UNITS:
        parts += [f'\n## {unit}', capture(['/usr/bin/systemctl', 'show', unit,
                   '--property=LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,FragmentPath']),
                  capture(['/usr/bin/journalctl', '-b', '-u', unit, '-n', '100', '--no-pager', '-o', 'cat'])]
    parts += ['\n## nginx build', capture(['/usr/sbin/nginx', '-V'])]
    path = Path('/srv/e5-logs/servicegateway/edge-error.log')
    try:
        with safe_file(path).open('rb') as stream:
            size = stream.seek(0, 2); stream.seek(max(0, size - 32768))
            parts += ['\n## edge-error.log (tail)', stream.read(32768).decode('utf-8', errors='replace')]
    except (OSError, ValueError) as exc:
        parts.append('edge error log unavailable: ' + type(exc).__name__)
    return redact('\n'.join(parts), local_secrets())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--save', action='store_true', help='save a private report and print its location only')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Use sudo python3 -I deploy/diagnose.py')
    output = report() + '\n'
    if not args.save:
        print(output, end=''); return
    REPORTS.mkdir(mode=0o700, exist_ok=True)
    for parent in (REPORTS, *REPORTS.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise SystemExit('Refusing unsafe diagnostic output directory')
    fd, name = tempfile.mkstemp(prefix=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-'),
                                suffix='.txt', dir=REPORTS)
    with os.fdopen(fd, 'w') as stream:
        stream.write(output); stream.flush(); os.fsync(stream.fileno())
    print(f'回滚前诊断已保存（root-only，已过滤常见凭据）：{name}')
    print('需要查看：sudo python3 -I deploy/diagnose.py（分享前仍请检查内容）')


if __name__ == '__main__':
    main()
