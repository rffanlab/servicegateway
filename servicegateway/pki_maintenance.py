"""Local-root CRL maintenance. Never expose signing credentials to the Web process.

The existing encrypted CA archive stays authoritative. A systemd host-encrypted
credential unlocks it only in the scheduled root unit. Automatic CRL refresh does
NOT rotate/revoke browser certificates (which would lock existing clients out).
"""
import base64
from datetime import UTC, datetime, timedelta
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tarfile
import tempfile
import time
from cryptography import x509
from cryptography.hazmat.primitives import serialization

CREDENTIAL = Path('/etc/servicegateway/pki-auto/passphrase.cred')
DOWNLOAD = Path('/etc/servicegateway/client-download/admin-browser.p12')
JOURNAL = Path('/etc/servicegateway/crl-pending.json')
STATUS = Path('/etc/servicegateway/pki-auto/status.json')
MAX_BUNDLE = 256 * 1024


def private_file(path):
    from .agent import root_file
    path = root_file(path)
    if path.stat().st_mode & 0o077:
        raise ValueError('PKI private file must be root-only')
    return path


def mirror_bundle():
    """Copy only the encrypted browser bundle, not its password/CA/probe keys."""
    from . import deploykit as kit
    kit.mkdir(DOWNLOAD.parent)
    data = private_file(kit.ACCESS / 'admin-browser.p12').read_bytes()
    if not 0 < len(data) <= MAX_BUNDLE:
        raise ValueError('Invalid client bundle size')
    kit.bytes_write(DOWNLOAD, data)


def bundle_payload():
    data = private_file(DOWNLOAD).read_bytes()
    if not 0 < len(data) <= MAX_BUNDLE:
        raise ValueError('Invalid client bundle size')
    return {'base64': base64.b64encode(data).decode('ascii'), 'filename': 'admin-browser.p12'}


def public_status():
    from .agent import CERTS, root_file
    result = {'credential_configured': CREDENTIAL.exists(), 'bundle_available': DOWNLOAD.exists(),
              'crl_days_remaining': None, 'last_run': None, 'timer_active': False}
    try:
        crl = x509.load_pem_x509_crl(root_file(CERTS / 'admin-ca/crl.pem').read_bytes())
        result['crl_days_remaining'] = (crl.next_update_utc - datetime.now(UTC)).days
    except (ValueError, OSError):
        pass
    import subprocess
    try:
        result['timer_active'] = subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', 'servicegateway-pki-refresh.timer'], capture_output=True, timeout=3).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        pass
    if STATUS.exists():
        # Only bounded, explicitly public fields; never return credential/archive data.
        saved = json.loads(root_file(STATUS).read_text())
        result['last_run'] = {k: saved.get(k) for k in ('at', 'outcome', 'error_type')}
    return result


def unpack(directory, secret):
    from . import deploykit as kit
    plain = kit.unseal(private_file(kit.ARCHIVE).read_bytes(), secret)
    with tarfile.open(fileobj=io.BytesIO(plain), mode='r:gz') as archive:
        members = archive.getmembers()
        if len(members) > 10000 or sum(m.size for m in members) > 16 * 1024 * 1024:
            raise ValueError('CA archive exceeds limit')
        if any(m.issym() or m.islnk() or not (m.isfile() or m.isdir()) for m in members):
            raise ValueError('Invalid CA archive member')
        archive.extractall(directory, filter='data')


def check_crl(pem, ca_pem, previous_pem=None, probe_pem=None):
    ca = x509.load_pem_x509_certificate(ca_pem)
    crl = x509.load_pem_x509_crl(pem)
    current = datetime.now(UTC)
    if crl.issuer != ca.subject or not crl.is_signature_valid(ca.public_key()):
        raise ValueError('CRL signature/issuer does not match the installed CA')
    if crl.last_update_utc > current + timedelta(minutes=5) or crl.next_update_utc < current + timedelta(days=30):
        raise ValueError('CRL validity is unsuitable for automatic deployment')
    serials = {entry.serial_number for entry in crl}
    if previous_pem:
        previous = x509.load_pem_x509_crl(previous_pem)
        if not previous.is_signature_valid(ca.public_key()):
            raise ValueError('Current CRL does not match the installed CA')
        if not {entry.serial_number for entry in previous}.issubset(serials):
            raise ValueError('Refusing a CRL that loses existing revocations; archive may be stale')
        if crl.last_update_utc < previous.last_update_utc:
            raise ValueError('Refusing older CRL')
    if probe_pem and x509.load_pem_x509_certificate(probe_pem).serial_number in serials:
        raise ValueError('Refusing to revoke the management readiness probe')
    return crl


def enable(args, secret=None):
    """One-time local consent: turn an offline-only archive into host-unlockable maintenance."""
    from . import deploykit as kit
    secret = secret or kit.password(args)
    with tempfile.TemporaryDirectory(prefix='sg-pki-check-', dir=kit.PKI_TEMP) as work:
        directory = Path(work)
        unpack(directory, secret)
        ca = x509.load_pem_x509_certificate((directory / 'ca.pem').read_bytes())
        from .agent import CERTS, root_file
        installed = x509.load_pem_x509_certificate(root_file(CERTS / 'admin-ca/ca.pem').read_bytes())
        if ca.public_bytes(serialization.Encoding.DER) != installed.public_bytes(serialization.Encoding.DER):
            raise ValueError('Archive is not for the installed CA')
    kit.mkdir(CREDENTIAL.parent)
    fd, name = tempfile.mkstemp(prefix='.credential-', dir=CREDENTIAL.parent)
    os.close(fd)
    candidate = Path(name)
    try:
        # No secret in argv or an environment variable, no cleartext password file.
        kit.command(['/usr/bin/systemd-creds', 'encrypt', '--with-key=host', '--name=pki-passphrase', '-', candidate], data=secret)
        os.chmod(candidate, 0o600)
        if kit.command(['/usr/bin/systemd-creds', 'decrypt', '--name=pki-passphrase', candidate, '-']).stdout != secret:
            raise ValueError('Credential round-trip failed')
        kit.bytes_write(CREDENTIAL, candidate.read_bytes())
    finally:
        candidate.unlink(missing_ok=True)
    mirror_bundle()
    kit.command(['/usr/bin/systemctl', 'enable', '--now', 'servicegateway-pki-refresh.timer'])
    print('已启用每日 CRL 检查；不足 30 天自动刷新至 90 天。不自动轮换浏览器证书。')


def credential_secret():
    directory = os.environ.get('CREDENTIALS_DIRECTORY')
    if not directory:
        raise ValueError('Run pki-auto-refresh through its systemd unit with LoadCredentialEncrypted')
    # Credential directories are created/read-protected by PID1. Do not accept symlinks.
    path = Path(directory) / 'pki-passphrase'
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('Unsafe systemd credential')
    secret = path.read_bytes()
    if not 16 <= len(secret) <= 1024:
        raise ValueError('Invalid PKI credential length')
    return secret


def auto_refresh():
    from . import deploykit as kit
    from .agent import CERTS, root_file, atomic_write
    from .ipc import AgentClient
    outcome = 'failed'
    error_type = None
    try:
        secret = credential_secret()
        path = CERTS / 'admin-ca/crl.pem'
        previous = root_file(path).read_bytes()
        current = x509.load_pem_x509_crl(previous)
        if current.next_update_utc > datetime.now(UTC) + timedelta(days=30):
            # Still verify that the encrypted archive can be unlocked; report broken setup early.
            kit.unseal(private_file(kit.ARCHIVE).read_bytes(), secret)
            outcome = 'not-due'
            return
        with tempfile.TemporaryDirectory(prefix='sg-crl-', dir=kit.PKI_TEMP) as work:
            directory = Path(work)
            unpack(directory, secret)
            installed_ca = root_file(CERTS / 'admin-ca/ca.pem').read_bytes()
            ca = x509.load_pem_x509_certificate(installed_ca)
            archived_ca = x509.load_pem_x509_certificate((directory / 'ca.pem').read_bytes())
            if ca.public_bytes(serialization.Encoding.DER) != archived_ca.public_bytes(serialization.Encoding.DER):
                raise ValueError('CA archive mismatch')
            config = kit.ca_config(directory)
            kit.command(['/usr/bin/openssl', 'ca', '-gencrl', '-config', config, '-out', directory / 'crl.pem'])
            pem = (directory / 'crl.pem').read_bytes()
            check_crl(pem, installed_ca, previous, root_file(CERTS / 'admin-ca/probe.crt').read_bytes())
            # Persist the updated CA index/crlnumber first. Retrying cannot lose revocations.
            kit.save_archive(directory, secret)
            AgentClient(kit.settings().agent_socket).call('install-crl', pem=pem.decode('ascii'))
        outcome = 'refreshed'
    except Exception as exc:
        error_type = type(exc).__name__
        raise
    finally:
        kit.mkdir(STATUS.parent)
        atomic_write(STATUS, json.dumps({'at': datetime.now(UTC).isoformat(), 'outcome': outcome, 'error_type': error_type}))
        print('管理 CRL 自动检查：' + outcome)


def restore_pending():
    from .agent import CONFIG, CERTS, root_file, atomic_write
    if not JOURNAL.exists():
        return False
    saved = json.loads(root_file(JOURNAL).read_text())
    if set(saved) != {'config', 'crl'}:
        raise ValueError('Invalid CRL recovery record')
    atomic_write(CERTS / 'admin-ca/crl.pem', saved['crl'])
    atomic_write(CONFIG, saved['config'])
    return True


def finish():
    JOURNAL.unlink(missing_ok=True)
    fd = os.open(JOURNAL.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def live_marker():
    conn = http.client.HTTPConnection('127.0.0.1', 19093, timeout=2)
    try:
        conn.request('GET', '/_sg/ready')
        result = conn.getresponse()
        result.read(100)
        return result.getheader('X-SG-CRL-Generation') if result.status == 200 else None
    finally:
        conn.close()


def install_crl(broker, pem):
    """Called only by UID 0 over the serialized broker; no Web signing capability."""
    from . import certificates, recovery
    from .agent import CONFIG, CERTS, root_file, atomic_write, command, load_policy
    from .ingress import check_frontdoor
    if not isinstance(pem, str) or len(pem) > 256 * 1024:
        raise ValueError('Invalid CRL size')
    with broker.lock:
        if JOURNAL.exists() or certificates.JOURNAL.exists() or recovery.pending():
            raise ValueError('Recover pending changes before CRL maintenance')
        identity = broker.live_identity()
        if not identity:
            raise ValueError('Edge is unavailable; CRL deployment postponed')
        old_config = root_file(CONFIG).read_text()
        old_crl = root_file(CERTS / 'admin-ca/crl.pem').read_text()
        check_crl(pem.encode(), root_file(CERTS / 'admin-ca/ca.pem').read_bytes(), old_crl.encode(),
                  root_file(CERTS / 'admin-ca/probe.crt').read_bytes())
        marker = secrets.token_hex(16)
        clean = re.sub(r'\s*add_header X-SG-CRL-Generation [0-9a-f]+;', '', old_config)
        candidate, count = re.subn(r'(add_header X-SG-Generation [0-9a-f]+;)',
                                  r'\1 add_header X-SG-CRL-Generation ' + marker + ';', clean)
        if not count:
            raise ValueError('Missing generated readiness markers')
        policy = load_policy(broker.settings)
        old_marker = live_marker()
        atomic_write(JOURNAL, json.dumps({'config': old_config, 'crl': old_crl}))
        try:
            atomic_write(CERTS / 'admin-ca/crl.pem', pem)
            atomic_write(CONFIG, candidate)
            command(['/usr/sbin/nginx', '-t', '-c', str(CONFIG)])
            command(['/usr/bin/systemctl', 'reload', 'servicegateway-edge.service'])
            for _ in range(20):
                if live_marker() == marker and check_frontdoor(policy, identity['digest'], identity.get('generation')):
                    finish()
                    return {'changed': True}
                time.sleep(.25)
            raise ValueError('New CRL reload not observed')
        except Exception as exc:
            restore_pending()
            command(['/usr/sbin/nginx', '-t', '-c', str(CONFIG)])
            command(['/usr/bin/systemctl', 'reload', 'servicegateway-edge.service'])
            for _ in range(20):
                if live_marker() == old_marker and broker.live_identity() == identity:
                    finish()
                    raise ValueError('CRL deployment failed; previous files restored') from exc
                time.sleep(.25)
            raise ValueError('CRL rollback unverified; recovery journal retained') from exc
