"""Narrow on-start migration for legacy generated configs with missing temp paths.

Run only as an edge ExecStartPre, after interrupted-publish recovery. Never
changes routing, authentication or listeners; never weakens the systemd sandbox.
"""
import os
import re
import subprocess
import tempfile
from pathlib import Path

from .agent import CONFIG, atomic_write, root_file

TEMPS = ('fastcgi', 'uwsgi', 'scgi')
ANCHOR = '  proxy_temp_path /var/lib/servicegateway/edge/proxy;\n'
BASE = '/var/lib/servicegateway/edge'


def patch_generated_config(text: str) -> str:
    """Idempotently add missing global directives; reject ambiguous/manual configs."""
    if not re.match(r'^# servicegateway-digest [0-9a-f]{64}\n', text):
        raise ValueError('Refusing to modify a non-ServiceGateway configuration')
    lines = text.splitlines(keepends=True)
    if (lines.count('http {\n') != 1 or lines.count(ANCHOR) != 1
            or lines.count('  client_body_temp_path /var/lib/servicegateway/edge/client;\n') != 1):
        raise ValueError('Unexpected configuration structure; local review required')
    missing = []
    for name in TEMPS:
        wanted = f'  {name}_temp_path {BASE}/{name};\n'
        matches = re.findall(rf'^\s*{name}_temp_path\s+[^;]*;', text, re.M)
        if matches:
            if len(matches) != 1 or lines.count(wanted) != 1:
                raise ValueError(f'Unexpected {name}_temp_path; refusing to overwrite')
        else:
            missing.append(wanted)
    return text.replace(ANCHOR, ANCHOR + ''.join(missing), 1)


def prepare() -> bool:
    if os.geteuid() != 0:
        raise PermissionError('Root-only edge startup step')
    # Recovery runs first; do not modify a config involved in an unfinished operation.
    from . import recovery, certificates
    if recovery.JOURNAL.exists() or certificates.JOURNAL.exists():
        raise ValueError('Recovery must finish before repairing temporary paths')
    path = root_file(CONFIG)
    old = path.read_text()
    new = patch_generated_config(old)
    if old == new:
        return False
    # Refuse a command invoked manually against an already running master. During
    # ExecStartPre the unit reports activating, not active.
    state = subprocess.run(['/usr/bin/systemctl', 'show', 'servicegateway-edge.service',
                            '-p', 'ActiveState', '--value'], capture_output=True, text=True,
                           timeout=10, check=True).stdout.strip()
    if state not in ('inactive', 'failed', 'activating'):
        raise ValueError('Edge must be stopped before changing an existing configuration')
    fd, name = tempfile.mkstemp(prefix='.temp-paths-', suffix='.conf', dir=path.parent)
    os.close(fd)
    candidate = Path(name)
    try:
        atomic_write(candidate, new)
        # stderr goes to the edge journal, not a response containing the full config.
        subprocess.run(['/usr/sbin/nginx', '-t', '-c', str(candidate)], check=True, timeout=20)
        backup = path.with_name('nginx.conf.before-temp-paths-' + candidate.stem.removeprefix('.temp-paths-'))
        atomic_write(backup, old)
        atomic_write(path, new)
    finally:
        candidate.unlink(missing_ok=True)
    print(f'Repaired isolated Nginx temporary paths; original config retained at {backup}')
    return True


if __name__ == '__main__':
    prepare()
