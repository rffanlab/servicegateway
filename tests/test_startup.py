"""Regression coverage for fresh-host Nginx defaults and rollback diagnostics."""
import importlib.util
from pathlib import Path
import subprocess
from types import SimpleNamespace
import pytest
from servicegateway import startup, recovery, certificates
from servicegateway.nginx import render
from servicegateway.schemas import Snapshot

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sg_diagnostics', ROOT / 'deploy/diagnose.py')
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)


def generated():
    snap = Snapshot()
    return render(snap, {}, snap.digest(), 'a' * 64)


def legacy():
    return ''.join(line for line in generated().splitlines(keepends=True)
                   if not any(f'{name}_temp_path ' in line for name in startup.TEMPS))


def test_all_temp_paths_inside_sandbox():
    text = generated()
    for name, directory in (('client_body', 'client'), ('proxy', 'proxy'),
                            ('fastcgi', 'fastcgi'), ('uwsgi', 'uwsgi'), ('scgi', 'scgi')):
        assert f'{name}_temp_path /var/lib/servicegateway/edge/{directory};' in text
        assert f'/var/lib/servicegateway/edge/{directory}' in (ROOT / 'deploy/install.sh').read_text()


def test_legacy_migration_changes_only_missing_directives():
    result = startup.patch_generated_config(legacy())
    assert result == generated()
    assert startup.patch_generated_config(result) == result


@pytest.mark.parametrize('text', [
    'http {\n}',
    legacy().replace('  proxy_temp_path', '    proxy_temp_path'),
    legacy().replace('http {', 'http {\nhttp {'),
    legacy() + '  fastcgi_temp_path /tmp/not-managed;\n',
    generated() + '  fastcgi_temp_path /var/lib/servicegateway/edge/fastcgi;\n',
])
def test_manual_or_ambiguous_config_rejected(text):
    with pytest.raises(ValueError):
        startup.patch_generated_config(text)


@pytest.fixture
def repair_files(tmp_path, monkeypatch):
    path = tmp_path / 'nginx.conf'; path.write_text(legacy())
    monkeypatch.setattr(startup, 'CONFIG', path)
    monkeypatch.setattr(startup, 'root_file', lambda p: p)
    monkeypatch.setattr(startup.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(recovery, 'JOURNAL', tmp_path / 'publish-pending.json')
    monkeypatch.setattr(certificates, 'JOURNAL', tmp_path / 'cert-pending.json')
    return path


def test_backup_and_atomic_repair(repair_files, monkeypatch):
    def run(args, **kwargs):
        return SimpleNamespace(stdout='activating\n', returncode=0)
    monkeypatch.setattr(startup.subprocess, 'run', run)
    assert startup.prepare()
    assert repair_files.read_text() == generated()
    backups = list(repair_files.parent.glob('nginx.conf.before-temp-paths-*'))
    assert len(backups) == 1 and backups[0].read_text() == legacy()
    assert backups[0].stat().st_mode & 0o777 == 0o600
    assert not startup.prepare()


def test_nginx_check_failure_leaves_original(repair_files, monkeypatch):
    def run(args, **kwargs):
        if args[0].endswith('nginx'):
            raise subprocess.CalledProcessError(1, args)
        return SimpleNamespace(stdout='activating\n', returncode=0)
    monkeypatch.setattr(startup.subprocess, 'run', run)
    with pytest.raises(subprocess.CalledProcessError):
        startup.prepare()
    assert repair_files.read_text() == legacy()
    assert not list(repair_files.parent.glob('.temp-paths-*'))


def test_never_patch_an_active_master(repair_files, monkeypatch):
    monkeypatch.setattr(startup.subprocess, 'run', lambda *a, **k: SimpleNamespace(stdout='active\n'))
    with pytest.raises(ValueError): startup.prepare()
    assert repair_files.read_text() == legacy()


def test_pending_recovery_blocks_migration(repair_files, monkeypatch):
    recovery.JOURNAL.write_text('{}')
    monkeypatch.setattr(startup.subprocess, 'run', lambda *a, **k: pytest.fail('no command expected'))
    with pytest.raises(ValueError): startup.prepare()
    assert repair_files.read_text() == legacy()


def test_no_sandbox_weakening_and_diagnostics_before_rollback():
    unit = (ROOT / 'deploy/servicegateway-edge.service').read_text()
    assert 'ProtectSystem=strict' in unit
    assert 'ReadWritePaths=/etc/servicegateway /run/servicegateway-edge /var/lib/servicegateway/edge /srv/e5-logs/servicegateway' in unit
    assert unit.index('servicegateway.recovery') < unit.index('servicegateway.startup') < unit.index('ExecStartPre=/usr/sbin/nginx')
    text = (ROOT / 'deploy/install.sh').read_text()
    body = text.split('rollback() {', 1)[1]
    assert body.index('deploy/diagnose.py') < body.index('systemctl stop') < body.index('rm -f')
    assert 'systemctl enable --now servicegateway-edge.service' not in text


def test_diagnostics_redact_secrets_but_keep_cause():
    message = ('database mysql+pymysql://user:unknown-pass@localhost/db\n'
               'Authorization: Bearer secret\nCookie: sg_session=abc\n'
               'known-secret\npassword=plain\n'
               'nginx: mkdir() /var/lib/nginx/fastcgi failed (30: Read-only file system)')
    redacted = diag.redact(message, {'known-secret'})
    for item in ('unknown-pass', 'Bearer secret', 'sg_session=abc', 'known-secret', 'password=plain'):
        assert item not in redacted
    assert 'Read-only file system' in redacted
