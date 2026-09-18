"""Installer safety and generated PKI. No host package/firewall/production DB mutations."""
import argparse
from datetime import datetime, UTC, timedelta
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import ssl
import sys
from types import SimpleNamespace
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from servicegateway import deploykit, certificates
from servicegateway.acme import http_vhost
from servicegateway.ingress import validate_ingress_policy
from test_unified_ingress import policy

MODULE = Path(__file__).parents[1] / 'deploy/bootstrap.py'
spec = importlib.util.spec_from_file_location('sg_bootstrap_test', MODULE)
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


@pytest.mark.parametrize('host', ['*.example.com','http://admin.example.com','127.0.0.1','x;id.example.com','x\n.example.com','a..example.com','admin.invalid'])
def test_domain_input_rejected(host):
    with pytest.raises(argparse.ArgumentTypeError): bootstrap.domain(host)


@pytest.mark.parametrize('value', ['0.0.0.0/0','192.168.0.1/24','10.0.0.0/8','::/0'])
def test_source_policy_rejected(value):
    with pytest.raises(argparse.ArgumentTypeError): bootstrap.cidr(value)


def test_valid_parameters_and_ca_terms_required():
    p = bootstrap.parser()
    args = p.parse_args(['--domain','ADMIN.example.com','--email','admin@example.com','--admin-cidr','203.0.113.9/32'])
    with pytest.raises(bootstrap.Stop): bootstrap.validate_args(args)
    args.agree_tos = True
    bootstrap.validate_args(args)
    assert args.domain == 'admin.example.com'


def test_dry_run_has_no_host_commands_or_mutations(monkeypatch,capsys):
    monkeypatch.setattr(bootstrap,'run',lambda *a,**kw:pytest.fail('Dry run executed a command'))
    monkeypatch.setattr(bootstrap,'write',lambda *a,**kw:pytest.fail('Dry run wrote a file'))
    monkeypatch.setattr(bootstrap,'dns_check',lambda *a:pytest.fail('Dry run used DNS'))
    assert bootstrap.main(['--dry-run']) == 0
    assert '未执行' in capsys.readouterr().out


def test_changed_management_policy_refused_on_rerun():
    saved={'domain':'admin.example.com','admin_user':'rffanlab','email':'a@example.com','admin_cidrs':['203.0.113.1/32']}
    args=bootstrap.parser().parse_args(['--domain','other.example.com','--agree-tos'])
    with pytest.raises(bootstrap.Stop): bootstrap.validate_args(args,saved)


def test_database_sql_uses_separate_accounts_and_does_not_reset(monkeypatch,tmp_path):
    queries=[]
    monkeypatch.setattr(bootstrap,'mkdir',lambda p,mode=0o700:Path(p).mkdir(parents=True,exist_ok=True))
    monkeypatch.setattr(bootstrap,'CFG',tmp_path)
    monkeypatch.setattr(bootstrap,'STATE',tmp_path/'bootstrap.json')
    monkeypatch.setattr(bootstrap,'owned',lambda path,*args:Path(path))
    monkeypatch.setattr(bootstrap,'mysql',lambda args,sql:queries.append(sql) or '')
    args=bootstrap.parser().parse_args(['--domain','admin.example.com','--email','a@example.com','--admin-cidr','203.0.113.1/32','--agree-tos'])
    first=bootstrap.setup_database(args,{})
    original=(tmp_path/'app.env').read_bytes()
    second=bootstrap.setup_database(args,first)
    assert first==second and (tmp_path/'app.env').read_bytes()==original
    sql='\n'.join(queries)
    assert 'DROP ' not in sql and 'ALTER USER' not in sql
    assert "GRANT SELECT, INSERT, UPDATE, DELETE ON servicegateway.* TO 'sg_runtime'" in sql
    assert 'sg_migrate' in (tmp_path/'migrate.env').read_text()
    assert 'sg_runtime' in original.decode()
    assert (tmp_path/'app.env').stat().st_mode & 0o777 == 0o600


def test_existing_schema_aborts_before_writing(monkeypatch,tmp_path):
    monkeypatch.setattr(bootstrap,'mkdir',lambda p,mode=0o700:Path(p).mkdir(parents=True,exist_ok=True))
    monkeypatch.setattr(bootstrap,'CFG',tmp_path)
    monkeypatch.setattr(bootstrap,'mysql',lambda *args:'servicegateway')
    monkeypatch.setattr(bootstrap,'write',lambda *args:pytest.fail('Must refuse before writing'))
    with pytest.raises(bootstrap.Stop):bootstrap.setup_database(SimpleNamespace(),{})


def test_no_sql_or_password_echo(monkeypatch):
    monkeypatch.setattr(subprocess,'run',lambda *a,**kw:SimpleNamespace(returncode=1,stdout='',stderr='SECRET_FROM_SQL'))
    with pytest.raises(bootstrap.Stop) as error:
        bootstrap.run(['/usr/bin/mysql'],data="CREATE USER test IDENTIFIED BY 'SECRET_FROM_SQL'")
    assert 'SECRET_FROM_SQL' not in str(error.value)


def test_symlink_config_rejected(tmp_path):
    secret=tmp_path/'secret';secret.write_text('secret')
    link=tmp_path/'link';link.symlink_to(secret)
    with pytest.raises(bootstrap.Stop):bootstrap.owned(link)


def test_dns_ipv6_fails_instead_of_silently_ignoring(monkeypatch):
    import socket
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**kw:[(socket.AF_INET6,None,None,None,('::1',80))])
    with pytest.raises(bootstrap.Stop):bootstrap.dns_check('admin.example.com')


def test_acme_is_separate_location_not_server_return():
    config='\n'.join(http_vhost('0.0.0.0','admin.example.com',True,True))
    assert 'try_files $uri =404' in config and 'disable_symlinks on' in config
    assert 'location / { return 308' in config
    assert 'proxy_pass' not in config
    with pytest.raises(ValueError):validate_ingress_policy({**policy(False),'acme_enabled':'true'},False)


def test_encrypted_recovery_authenticated_roundtrip():
    encrypted=deploykit.seal(b'CA_PRIVATE_KEY',b'long-passphrase-12345')
    assert b'CA_PRIVATE_KEY' not in encrypted
    assert deploykit.unseal(encrypted,b'long-passphrase-12345')==b'CA_PRIVATE_KEY'
    with pytest.raises(ValueError):deploykit.unseal(encrypted,b'wrong-passphrase-1234')
    corrupted=encrypted[:-1]+bytes([encrypted[-1]^1])
    with pytest.raises(ValueError):deploykit.unseal(corrupted,b'long-passphrase-12345')


def test_real_pki_initialization_and_refresh(monkeypatch,tmp_path):
    ca=tmp_path/'certs';ca.mkdir()
    access=tmp_path/'access'
    monkeypatch.setattr(deploykit,'PKI_TEMP',tmp_path)
    monkeypatch.setattr(deploykit,'mkdir',lambda p,mode=0o700:Path(p).mkdir(parents=True,exist_ok=True))
    monkeypatch.setattr(deploykit,'CERTS',ca)
    monkeypatch.setattr(deploykit,'ACCESS',access)
    monkeypatch.setattr(deploykit,'ARCHIVE',access/'client-ca.sgpki')
    monkeypatch.setattr(deploykit,'root_file',lambda p:Path(p))
    # root_file owns permission enforcement in production; tests use disposable temp files.
    from servicegateway import agent
    monkeypatch.setattr(agent,'root_file',lambda p:Path(p))
    secret=b'a-local-test-password-1234'
    monkeypatch.setattr(deploykit,'password',lambda _:secret)
    reloads=[]
    monkeypatch.setattr(deploykit,'settings',lambda:SimpleNamespace(agent_socket='test'))
    monkeypatch.setattr(deploykit,'AgentClient',lambda _:SimpleNamespace(call=lambda action:reloads.append(action)))
    args=SimpleNamespace(pki_pass_file=None)
    deploykit.init_pki(args)
    directory=ca/'admin-ca'
    original=(directory/'ca.pem').read_bytes()
    assert not (directory/'ca.key').exists()
    assert (directory/'probe.key').stat().st_mode & 0o777 == 0o600
    assert (access/'admin-browser.p12').exists()
    cert=x509.load_pem_x509_certificate((directory/'browser.crt').read_bytes())
    assert x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    result=subprocess.run(['openssl','verify','-purpose','sslclient','-CAfile',str(directory/'ca.pem'),str(directory/'browser.crt')],capture_output=True)
    assert result.returncode==0,result.stderr
    deploykit.init_pki(args)
    assert (directory/'ca.pem').read_bytes()==original
    deploykit.init_pki(args,refresh=True)
    assert (directory/'ca.pem').read_bytes()==original
    assert reloads==['reload-tls']


def test_certificate_key_pair_and_exact_domain(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME,'admin.example.com')])
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(1).not_valid_before(datetime.now(UTC)-timedelta(minutes=1))
          .not_valid_after(datetime.now(UTC)+timedelta(days=2))
          .add_extension(x509.SubjectAlternativeName([x509.DNSName('admin.example.com')]),critical=False).sign(key,hashes.SHA256()))
    c=cert.public_bytes(serialization.Encoding.PEM)
    k=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    assert len(certificates.certificate_pair(c,k,'admin.example.com'))==64
    with pytest.raises(ValueError):certificates.certificate_pair(c,k,'other.example.com')
    wrong=rsa.generate_private_key(public_exponent=65537,key_size=2048).private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    with pytest.raises(ValueError):certificates.certificate_pair(c,wrong,'admin.example.com')


def test_certificate_recovery_restores_old_files(monkeypatch,tmp_path):
    from servicegateway import agent
    monkeypatch.setattr(agent,'CERTS',tmp_path)
    monkeypatch.setattr(agent,'root_file',lambda p:Path(p))
    monkeypatch.setattr(certificates,'JOURNAL',tmp_path/'tls-pending.json')
    (tmp_path/'admin').mkdir()
    (tmp_path/'admin/fullchain.pem').write_text('unverified-certificate')
    certificates.JOURNAL.write_text(json.dumps({'admin/fullchain.pem':'old-certificate','admin/privkey.pem':None}))
    assert certificates.restore_files()
    assert (tmp_path/'admin/fullchain.pem').read_text()=='old-certificate'
    assert certificates.JOURNAL.exists()
    certificates.finish()
    assert not certificates.JOURNAL.exists()


def test_certbot_dry_run_no_deploy_hook(monkeypatch):
    commands=[]
    monkeypatch.setattr(deploykit,'certbot_args',lambda:['certbot','--config-dir','isolated'])
    monkeypatch.setattr(deploykit,'command',lambda args:commands.append(args))
    deploykit.renew_test()
    assert commands==[['certbot','--config-dir','isolated','renew','--dry-run']]


def test_sync_retried_when_certbot_did_not_need_to_renew(monkeypatch):
    calls=[]
    monkeypatch.setattr(deploykit,'certbot_args',lambda:['certbot'])
    monkeypatch.setattr(deploykit,'command',lambda args:calls.append('renew'))
    monkeypatch.setattr(deploykit,'sync_certificates',lambda:calls.append('sync'))
    monkeypatch.setattr(deploykit,'health_report',lambda:calls.append('health'))
    deploykit.renew()
    assert calls==['renew','sync','health']


def test_archive_symlink_escape_is_rejected(monkeypatch,tmp_path):
    acme=tmp_path/'acme';(acme/'live/sg-admin').mkdir(parents=True)
    outside=tmp_path/'not-a-cert.pem';outside.write_text('secret')
    (acme/'live/sg-admin/fullchain.pem').symlink_to(outside)
    monkeypatch.setattr(certificates,'ACME',acme)
    with pytest.raises(ValueError):certificates.source_file('sg-admin','fullchain.pem')


def test_root_only_maintenance_gate_for_web_user(monkeypatch):
    import struct
    from servicegateway import agent
    for action in ('sync-certificates','reload-tls'):
        handler=agent.Handler.__new__(agent.Handler)
        handler.connection=SimpleNamespace(settimeout=lambda _:None,getsockopt=lambda *a:struct.pack('3i',1,5000,5000))
        handler.rfile=io.BytesIO((json.dumps({'action':action})+'\n').encode())
        handler.wfile=io.BytesIO()
        handler.server=SimpleNamespace(allowed_uid=5000,broker=SimpleNamespace(
            dispatch=lambda _:pytest.fail('Web UID must not reach root maintenance'),
            settings=SimpleNamespace(auth_secret=lambda:'A'*64)))
        handler.handle()
        assert json.loads(handler.wfile.getvalue())['ok'] is False
