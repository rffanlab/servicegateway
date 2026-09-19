"""Installation permission regression checks (real host checks run separately)."""
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('runtime_diagnostics', ROOT / 'deploy/diagnose.py')
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)


def build_block():
    script = (ROOT / 'deploy/install.sh').read_text()
    return script.split('# BEGIN RUNTIME BUILD\n', 1)[1].split('# END RUNTIME BUILD', 1)[0]


def test_actual_build_block_is_scoped_to_non_secret_creation(tmp_path):
    # Execute the installer block with a local command fixture; no pip/network.
    shim = tmp_path / 'python3'
    shim.write_text('#!/bin/bash\nset -eu\n'
                    'mkdir -p "$3/bin"\n'
                    'printf "#!/bin/bash\\numask > \\\"$3/pip-mask\\\"\\ntouch \\\"$3/library.py\\\"\\n" > "$3/bin/python"\n'
                    'chmod u+x "$3/bin/python"\n')
    shim.chmod(0o755)
    release = tmp_path / 'release'; release.mkdir()
    env = {**os.environ, 'PATH': f'{tmp_path}:/usr/bin:/bin', 'release': str(release)}
    result = subprocess.run(['/bin/bash', '-c', 'set -Eeuo pipefail\numask 077\n' + build_block() + '\numask\ntouch "$release/private-backup"'],
                            env=env, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == '0077'
    assert (release / '.venv/pip-mask').read_text().strip() == '0022'
    assert stat.S_IMODE((release / '.venv/bin/python').stat().st_mode) == 0o744
    assert stat.S_IMODE((release / '.venv/library.py').stat().st_mode) == 0o644
    assert stat.S_IMODE((release / 'private-backup').stat().st_mode) == 0o600
    assert stat.S_IMODE((release / '.venv').stat().st_mode) == 0o755


def test_nonroot_preflight_before_cutover_with_sandbox_intact():
    text = (ROOT / 'deploy/install.sh').read_text()
    preflight = text.index('systemd-run --quiet --wait --pipe --collect --unit="sg-runtime-check-')
    assert text.index('trap rollback ERR') < preflight < text.index('changed=1')
    line = text[preflight:].splitlines()[0]
    for required in ('User=servicegateway', 'Group=servicegateway', 'ProtectSystem=strict',
                     'ProtectHome=true', 'PrivateTmp=true', 'NoNewPrivileges=true',
                     'EnvironmentFile=$CFG/app.env', 'servicegateway.runtimecheck'):
        assert required in line
    assert 'chmod -R 777' not in text and 'chmod -R a+r' not in text
    unit = (ROOT / 'deploy/servicegateway.service').read_text()
    assert 'User=servicegateway' in unit and 'ProtectSystem=strict' in unit
    assert '/.venv/bin/python -I -m uvicorn ' in unit
    assert 'UMask=0077' in unit


def test_diagnostics_no_longer_depend_on_shared_var_log():
    assert diag.REPORTS == Path('/etc/servicegateway/deploy-reports')
    text = (ROOT / 'deploy/diagnose.py').read_text()
    assert 'short-iso-precise' in text and "'/usr/bin/namei'" in text


@pytest.fixture
def reports(tmp_path, monkeypatch):
    cfg = tmp_path / 'cfg'; cfg.mkdir(mode=0o750)
    reports = cfg / 'deploy-reports'
    monkeypatch.setattr(diag, 'REPORTS', reports)
    original = Path.lstat
    # pytest may run as non-root under /tmp. Only emulate trusted ancestors;
    # report directory permissions and regular file writes below remain real.
    ancestors = {cfg, *cfg.parents}
    def trusted_parents(path):
        result = original(path)
        if path in ancestors:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o750, st_uid=0)
        if path == reports and not stat.S_ISLNK(result.st_mode):
            return SimpleNamespace(st_mode=result.st_mode, st_uid=0)
        return result
    monkeypatch.setattr(Path, 'lstat', trusted_parents)
    return reports


def test_private_report_created_without_global_permission_changes(reports):
    file = diag.save_report('redacted report\n')
    assert file.read_text() == 'redacted report\n'
    assert stat.S_IMODE(file.stat().st_mode) == 0o600
    assert stat.S_IMODE(reports.stat().st_mode) == 0o700


@pytest.mark.parametrize('mode', [0o755, 0o770, 0o777])
def test_preexisting_broad_report_dir_is_not_silently_accepted(reports, mode):
    reports.mkdir(mode=mode); reports.chmod(mode)
    with pytest.raises(ValueError):
        diag.save_report('report')
    assert not list(reports.iterdir())


def test_report_symlink_is_rejected(reports):
    target = reports.parent / 'target'; target.mkdir()
    reports.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError):
        diag.save_report('report')
    assert not list(target.iterdir())


def test_save_failure_still_prints_redacted_evidence(monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['diagnose.py', '--save'])
    monkeypatch.setattr(diag.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(diag, 'report', lambda: 'status=203/EXEC [redacted]')
    def denied(_):
        raise PermissionError('diagnostic storage failure')
    monkeypatch.setattr(diag, 'save_report', denied)
    with pytest.raises(SystemExit):
        diag.main()
    assert 'status=203/EXEC [redacted]' in capsys.readouterr().out


def test_runtime_probe_refuses_root(monkeypatch):
    from servicegateway import runtimecheck
    monkeypatch.setattr(runtimecheck.os, 'geteuid', lambda: 0)
    with pytest.raises(RuntimeError, match='non-root'):
        runtimecheck.check()
