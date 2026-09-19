from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
import json
import stat
import threading
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from servicegateway import pki_maintenance as pki, deploykit as kit, agent, certificates, recovery
from servicegateway.ipc import AgentClient, AgentError


@pytest.fixture
def ca():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME,'Test client CA')])
    c=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
       .not_valid_before(datetime.now(UTC)-timedelta(days=1)).not_valid_after(datetime.now(UTC)+timedelta(days=365))
       .add_extension(x509.BasicConstraints(ca=True,path_length=0),True).sign(key,hashes.SHA256()))
    return key,c.public_bytes(serialization.Encoding.PEM),name


def crl(ca,revoked=(),days=90):
    key,_,name=ca
    b=x509.CertificateRevocationListBuilder().issuer_name(name).last_update(datetime.now(UTC)-timedelta(seconds=1)).next_update(datetime.now(UTC)+timedelta(days=days))
    for serial in revoked:
        b=b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(datetime.now(UTC)-timedelta(hours=1)).build())
    return b.sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def test_crl_preserves_revocations_and_checks_signature(ca):
    old=crl(ca,[9],days=10);new=crl(ca,[9,10])
    assert pki.check_crl(new,ca[1],old)
    with pytest.raises(ValueError):pki.check_crl(crl(ca,[]),ca[1],old)
    with pytest.raises(ValueError):pki.check_crl(crl(ca,[9],days=5),ca[1],old)
    otherkey=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    with pytest.raises(ValueError):pki.check_crl(crl((otherkey,ca[1],ca[2]),[9]),ca[1],old)


@pytest.fixture
def real_archive(tmp_path,monkeypatch):
    certs=tmp_path/'certs';certs.mkdir()
    access=tmp_path/'access'
    monkeypatch.setattr(kit,'PKI_TEMP',tmp_path)
    monkeypatch.setattr(kit,'CERTS',certs);monkeypatch.setattr(agent,'CERTS',certs)
    monkeypatch.setattr(kit,'ACCESS',access);monkeypatch.setattr(kit,'ARCHIVE',access/'client-ca.sgpki')
    monkeypatch.setattr(kit,'root_file',lambda p:Path(p));monkeypatch.setattr(agent,'root_file',lambda p:Path(p))
    monkeypatch.setattr(kit,'mkdir',lambda p,mode=0o700:Path(p).mkdir(mode=mode,parents=True,exist_ok=True))
    monkeypatch.setattr(pki,'CREDENTIAL',tmp_path/'passphrase.cred')
    monkeypatch.setattr(pki,'STATUS',tmp_path/'state/status.json')
    monkeypatch.setattr(pki,'DOWNLOAD',tmp_path/'download/admin-browser.p12')
    secret=b'unit-test-pki-password-abc123'
    monkeypatch.setattr(kit,'password',lambda _:secret)
    monkeypatch.setattr(pki,'credential_secret',lambda:secret)
    kit.init_pki(SimpleNamespace(pki_pass_file=None))
    calls=[]
    monkeypatch.setattr(kit,'settings',lambda:SimpleNamespace(agent_socket='test'))
    monkeypatch.setattr(AgentClient,'call',lambda self,action,**body:calls.append((action,body)) or {'changed':True})
    return tmp_path,certs/'admin-ca',secret,calls


def test_automatic_crl_refresh_does_not_rotate_client_or_clear_revocations(real_archive):
    tmp,certs,secret,calls=real_archive
    before_browser=(certs/'browser.crt').read_bytes()
    before_bundle=(kit.ACCESS/'admin-browser.p12').read_bytes()
    before_probe=(certs/'probe.crt').read_bytes()
    work=tmp/'edit';work.mkdir()
    pki.unpack(work,secret)
    conf=kit.ca_config(work)
    # Add a revoked independent old device to the issuer database, then create a near-expiry CRL.
    kit.new_client(work,'old-device',conf,365)
    kit.command(['/usr/bin/openssl','ca','-config',conf,'-revoke',work/'old-device.crt'])
    kit.command(['/usr/bin/openssl','ca','-gencrl','-crldays','10','-config',conf,'-out',work/'crl.pem'])
    previous=(work/'crl.pem').read_bytes()
    (certs/'crl.pem').write_bytes(previous)
    kit.save_archive(work,secret)
    pki.auto_refresh()
    assert calls[0][0]=='install-crl'
    new= x509.load_pem_x509_crl(calls[0][1]['pem'].encode())
    assert new.next_update_utc > datetime.now(UTC)+timedelta(days=89)
    assert {x.serial_number for x in new}=={x.serial_number for x in x509.load_pem_x509_crl(previous)}
    assert (certs/'browser.crt').read_bytes()==before_browser
    assert (kit.ACCESS/'admin-browser.p12').read_bytes()==before_bundle
    assert (certs/'probe.crt').read_bytes()==before_probe
    assert json.loads(pki.STATUS.read_text())['outcome']=='refreshed'


def test_valid_crl_skips_reload_and_bundle_mirror_remains_encrypted(real_archive):
    _,_,secret,calls=real_archive
    pki.auto_refresh()
    assert not calls and json.loads(pki.STATUS.read_text())['outcome']=='not-due'
    pki.mirror_bundle()
    assert stat.S_IMODE(pki.DOWNLOAD.stat().st_mode)==0o600
    assert stat.S_IMODE(pki.DOWNLOAD.parent.stat().st_mode)==0o700
    from cryptography.hazmat.primitives.serialization import pkcs12
    data=pki.DOWNLOAD.read_bytes()
    with pytest.raises(ValueError):pkcs12.load_key_and_certificates(data,None)
    key,cert,extras=pkcs12.load_key_and_certificates(data,secret)
    assert key is not None and cert.subject.rfc4514_string()=='CN=sg-browser'
    assert secret not in data and b'PRIVATE KEY' not in data


def test_wrong_credential_leaves_files_unchanged(real_archive,monkeypatch):
    _,certs,_,calls=real_archive
    before=(certs/'crl.pem').read_bytes()
    monkeypatch.setattr(pki,'credential_secret',lambda:b'a-wrong-password-12345')
    with pytest.raises(ValueError):pki.auto_refresh()
    assert not calls and (certs/'crl.pem').read_bytes()==before
    assert json.loads(pki.STATUS.read_text())['outcome']=='failed'


def test_no_web_permissions_to_sign_or_manage_scheduled_secret():
    root=Path(__file__).resolve().parents[1]
    source=(root/'servicegateway/agent.py').read_text()
    assert '("bootstrap-ingress", "sync-certificates", "reload-tls", "install-crl") and uid != 0' in source
    app=(root/'deploy/servicegateway.service').read_text()
    unit=(root/'deploy/servicegateway-pki-refresh.service').read_text()
    assert 'LoadCredentialEncrypted=pki-passphrase:' in unit and 'User=root' in unit
    assert 'LoadCredential' not in app and 'ProtectSystem=strict' in app
    timer=(root/'deploy/servicegateway-pki-refresh.timer').read_text()
    assert 'OnCalendar=daily' in timer and 'Persistent=true' in timer


def test_agent_directory_group_and_post_start_check():
    root=Path(__file__).resolve().parents[1]
    unit=(root/'deploy/servicegateway-agent.service').read_text()
    assert 'Group=servicegateway' in unit and 'Group=root' not in unit
    assert 'ExecStartPre=/usr/bin/chgrp' not in unit and 'RuntimeDirectoryMode=0750' in unit
    installer=(root/'deploy/install.sh').read_text()
    assert installer.index('servicegateway.ipc_check')>installer.index('systemctl restart servicegateway-agent.service')
    assert 'chmod 777' not in installer


def test_missing_socket_directory_permission_is_explained(monkeypatch):
    import socket
    monkeypatch.setattr(socket.socket,'connect',lambda *a:(_ for _ in ()).throw(PermissionError()))
    with pytest.raises(AgentError,match='root:servicegateway'):
        AgentClient('/run/servicegateway-agent/agent.sock').call('traffic')


def test_crl_journal_restores_config_and_crl_without_touching_credentials(tmp_path,monkeypatch):
    monkeypatch.setattr(pki,'JOURNAL',tmp_path/'journal.json')
    monkeypatch.setattr(agent,'CONFIG',tmp_path/'nginx.conf')
    monkeypatch.setattr(agent,'CERTS',tmp_path/'certs')
    monkeypatch.setattr(agent,'root_file',lambda p:Path(p))
    (agent.CERTS/'admin-ca').mkdir(parents=True)
    agent.CONFIG.write_text('new config')
    (agent.CERTS/'admin-ca/crl.pem').write_text('new CRL')
    pki.JOURNAL.write_text(json.dumps({'config':'old config','crl':'old CRL'}))
    assert pki.restore_pending()
    assert agent.CONFIG.read_text()=='old config'
    assert (agent.CERTS/'admin-ca/crl.pem').read_text()=='old CRL'
    assert pki.JOURNAL.exists()
    pki.finish();assert not pki.JOURNAL.exists()

@pytest.mark.parametrize('fail_test,fail_rollback',[(False,False),(True,False),(True,True)])
def test_crl_install_transaction_and_verified_rollback(ca,tmp_path,monkeypatch,fail_test,fail_rollback):
    from servicegateway import ingress
    certs=tmp_path/'certs';(certs/'admin-ca').mkdir(parents=True)
    old=crl(ca,days=10);new=crl(ca,days=90)
    (certs/'admin-ca/crl.pem').write_bytes(old)
    (certs/'admin-ca/ca.pem').write_bytes(ca[1])
    (certs/'admin-ca/probe.crt').write_bytes(ca[1])
    config=tmp_path/'nginx.conf'
    before='add_header X-SG-Generation '+('a'*32)+'; return 200 "ready";'
    config.write_text(before)
    monkeypatch.setattr(agent,'CERTS',certs);monkeypatch.setattr(agent,'CONFIG',config)
    monkeypatch.setattr(agent,'root_file',lambda p:Path(p))
    monkeypatch.setattr(pki,'JOURNAL',tmp_path/'crl-pending.json')
    monkeypatch.setattr(certificates,'JOURNAL',tmp_path/'tls-pending.json')
    monkeypatch.setattr(recovery,'JOURNAL',tmp_path/'publish-pending.json')
    monkeypatch.setattr(agent,'load_policy',lambda _: {})
    monkeypatch.setattr(ingress,'check_frontdoor',lambda *a:True)
    marker=[None];tests=[0]
    monkeypatch.setattr(pki,'live_marker',lambda:marker[0])
    def command(args):
        if args[0].endswith('nginx'):
            tests[0]+=1
            if fail_test and tests[0]==1:raise ValueError('simulated nginx failure')
        else:
            if fail_rollback:raise ValueError('simulated rollback failure')
            import re
            m=re.search('X-SG-CRL-Generation ([a-f0-9]+)',config.read_text())
            marker[0]=m[1] if m else None
        return ''
    monkeypatch.setattr(agent,'command',command)
    broker=SimpleNamespace(lock=threading.RLock(),settings=None,live_identity=lambda:{'digest':'a'*64,'generation':'a'*32})
    if fail_test:
        with pytest.raises(ValueError):pki.install_crl(broker,new.decode())
        assert config.read_text()==before and (certs/'admin-ca/crl.pem').read_bytes()==old
        assert pki.JOURNAL.exists()==fail_rollback
    else:
        assert pki.install_crl(broker,new.decode())['changed']
        assert (certs/'admin-ca/crl.pem').read_bytes()==new
        assert 'X-SG-CRL-Generation' in config.read_text()
        assert not pki.JOURNAL.exists()
