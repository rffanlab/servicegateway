"""Root-owned write-ahead rollback journal for interrupted Nginx configuration changes."""
import json
import os
from pathlib import Path
import subprocess

JOURNAL = Path('/etc/servicegateway/publish-pending.json')
BACKUP = Path('/etc/servicegateway/rollback.conf')


def begin(old_config, digest, generation):
    from .agent import atomic_write
    if JOURNAL.exists():
        raise ValueError('An interrupted publish must be recovered before another publish')
    atomic_write(BACKUP, old_config)
    atomic_write(JOURNAL, json.dumps({'digest': digest, 'generation': generation}))


def pending():
    from .agent import root_file
    return json.loads(root_file(JOURNAL).read_text()) if JOURNAL.exists() else None


def restore_disk():
    from .agent import CONFIG, atomic_write, root_file
    record = pending()
    if record:
        atomic_write(CONFIG, root_file(BACKUP).read_text())
    return record


def finish():
    JOURNAL.unlink(missing_ok=True)
    fd = os.open(JOURNAL.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    # Invoked before starting the isolated edge. An interrupted candidate must never
    # become live merely because the machine/service restarts.
    if os.geteuid() != 0:
        raise SystemExit('Root required')
    from . import certificates
    if not JOURNAL.exists() and not certificates.JOURNAL.exists():
        return
    running = subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', 'servicegateway-edge.service'])
    if running.returncode == 0:
        raise SystemExit('Edge is active; recovery must run through the serialized broker')
    if certificates.restore_files():
        certificates.finish()
    if JOURNAL.exists():
        restore_disk()
        finish()
    print('Interrupted configuration restored before edge startup; database reconciliation remains required')


if __name__ == '__main__':
    main()
