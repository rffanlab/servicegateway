"""Root-only certificate deployment, serialized by the Agent with route publication.

Certbot owns ACME files. Nginx uses validated regular-file copies, not symlinks into
Certbot's account/private directories. A persisted journal protects interrupted copies.
"""
import hashlib
import json
from pathlib import Path
import re
import ssl
import subprocess
import time
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from .ingress import LoopbackTLS, valid_host

ACME = Path('/etc/servicegateway/acme')
MAPPING = Path('/etc/servicegateway/certificate-map.json')
JOURNAL = Path('/etc/servicegateway/tls-pending.json')


def load_mapping():
    from .agent import root_file
    if not MAPPING.exists():
        return {}
    data = json.loads(root_file(MAPPING).read_text())
    if not isinstance(data, dict) or len(data) > 100:
        raise ValueError('Invalid certificate map')
    for cert_id, row in data.items():
        if (not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', cert_id)
                or not isinstance(row, dict) or set(row) != {'domain', 'lineage'}
                or not valid_host(row['domain']) or row['lineage'] != 'sg-' + cert_id):
            raise ValueError('Invalid root certificate mapping')
    return data


def certificate_pair(cert_pem, key_pem, host):
    cert = x509.load_pem_x509_certificate(cert_pem)
    key = serialization.load_pem_private_key(key_pem, password=None)
    public_format = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if cert.public_key().public_bytes(*public_format) != key.public_key().public_bytes(*public_format):
        raise ValueError('Certificate and private key do not match')
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    if host not in names:  # This deployer only issues exact single-domain certificates.
        raise ValueError('Certificate does not cover the approved exact domain')
    from datetime import datetime, UTC, timedelta
    if cert.not_valid_after_utc <= datetime.now(UTC) + timedelta(hours=12) or cert.not_valid_before_utc > datetime.now(UTC):
        raise ValueError('Certificate is expired, not yet valid, or too close to expiry')
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def source_file(lineage, name):
    from .agent import root_file
    # Certbot intentionally uses symlinks. Resolve, then constrain to this lineage's archive.
    path = (ACME / 'live' / lineage / name).resolve(strict=True)
    expected = ACME / 'archive' / lineage
    if path.parent != expected or not re.fullmatch(r'(fullchain|privkey)[0-9]+\.pem', path.name):
        raise ValueError('Unexpected Certbot archive target')
    return root_file(path)


def restore_files():
    from .agent import CERTS, root_file, atomic_write
    if not JOURNAL.exists():
        return False
    saved = json.loads(root_file(JOURNAL).read_text())
    for relative, content in saved.items():
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,62}/(fullchain|privkey)\.pem', relative):
            raise ValueError('Invalid certificate recovery journal')
        path = CERTS / relative
        if content is None:
            if path.exists(): root_file(path).unlink()
        else:
            atomic_write(path, content, 0o600)
    return True


def finish():
    import os
    JOURNAL.unlink(missing_ok=True)
    fd = os.open(JOURNAL.parent, os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def live_fingerprint(host, ca=None):
    from .agent import CERTS
    ctx = ssl._create_unverified_context()  # Exact DER fingerprint is verified against the trusted issued cert.
    if ca:
        ctx.load_cert_chain(str(CERTS / ca / 'probe.crt'), str(CERTS / ca / 'probe.key'))
    conn = LoopbackTLS(host, 443, timeout=3, context=ctx)
    try:
        conn.connect()
        return hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
    finally:
        conn.close()


def active_client_ca(config, host):
    # Generated config has exact validated host names. No user-supplied regex/templates.
    marker = 'server_name ' + host + ';'
    segments = config.split('  server {')
    blocks = [b for b in segments if marker in b and ':443 ssl' in b]
    if not blocks:
        return False, None
    match = re.search(r'ssl_client_certificate /etc/servicegateway/certs/([a-z0-9-]+)/ca.pem;', blocks[0])
    return True, match.group(1) if match else None


def sync(broker, force=False):
    from . import recovery
    from .agent import CERTS, CONFIG, root_file, atomic_write, command
    with broker.lock:
        if recovery.pending() or JOURNAL.exists():
            raise ValueError('Unrecovered publication/certificate transaction; restart Agent to restore before retrying')
        identity = broker.live_identity()
        if not identity:
            raise ValueError('Edge is unavailable; certificate deployment deferred, not reported successful')
        config = root_file(CONFIG).read_text()
        replacements, fingerprints, saved = {}, {}, {}
        for cert_id, row in load_mapping().items():
            # An interrupted issuance may have a registered intent but no certificate yet.
            live = ACME / 'live' / row['lineage']
            if not live.exists():
                continue
            cert = source_file(row['lineage'], 'fullchain.pem')
            key = source_file(row['lineage'], 'privkey.pem')
            cert_pem, key_pem = cert.read_bytes(), key.read_bytes()
            fingerprint = certificate_pair(cert_pem, key_pem, row['domain'])
            # Validate public trust/chain; a Let's Encrypt staging cert cannot reach production.
            verified = subprocess.run(['/usr/bin/openssl', 'verify', '-purpose', 'sslserver',
                                       '-verify_hostname', row['domain'], '-untrusted', str(cert), str(cert)],
                                      capture_output=True, timeout=10)
            if verified.returncode:
                raise ValueError('Certificate public trust validation failed; staging/self-signed certificates are not deployed')
            directory = CERTS / cert_id
            if directory.is_symlink(): raise ValueError('Certificate directory cannot be a symlink')
            directory.mkdir(mode=0o700, exist_ok=True)
            for name, data in [('fullchain.pem', cert_pem), ('privkey.pem', key_pem)]:
                target = directory / name
                previous = root_file(target).read_text() if target.exists() else None
                text = data.decode('ascii')
                if previous != text:
                    relative = cert_id + '/' + name
                    saved[relative], replacements[relative] = previous, text
            active, ca = active_client_ca(config, row['domain'])
            if active: fingerprints[row['domain']] = (fingerprint, ca)
        if not replacements and not force:
            # Recheck actual live certificate even on a retry where files already match.
            for host, (expected, ca) in fingerprints.items():
                if live_fingerprint(host, ca) != expected:
                    command(['/usr/bin/systemctl', 'reload', 'servicegateway-edge.service'])
                    break
            else: return {'changed': False}
        atomic_write(JOURNAL, json.dumps(saved))
        try:
            for relative, content in replacements.items():
                atomic_write(CERTS / relative, content, 0o600)
            command(['/usr/sbin/nginx', '-t', '-c', str(CONFIG)])
            command(['/usr/bin/systemctl', 'reload', 'servicegateway-edge.service'])
            for _ in range(20):
                if (broker.live_identity() == identity and all(live_fingerprint(host, ca) == expected
                    for host, (expected, ca) in fingerprints.items())):
                    finish()
                    return {'changed': True, 'verified_hosts': sorted(fingerprints)}
                time.sleep(.25)
            raise ValueError('Certificate reload fingerprint was not observed')
        except Exception as exc:
            restore_files()
            try:
                command(['/usr/sbin/nginx', '-t', '-c', str(CONFIG)])
                command(['/usr/bin/systemctl', 'reload', 'servicegateway-edge.service'])
            except Exception:
                raise ValueError('Certificate deploy/restore requires local inspection; recovery journal retained') from exc
            finish()
            raise ValueError('Certificate deployment failed; previous files restored, check live service before retrying') from exc
