"""Production topology tests: one TLS listener, distinct SNI identities and no spare public ports."""
import http.client
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import threading
import time
import pytest
from pydantic import ValidationError
from servicegateway.agent import validate_snapshot
from servicegateway.schemas import Snapshot, ServiceSpec, RouteSpec
from servicegateway.config import Settings
from servicegateway.ingress import LoopbackTLS, validate_ingress_policy
from servicegateway.nginx import render
from conftest import POLICY, SPEC, SECRET


def policy(enabled=True):
    return {**POLICY, 'remote_mode':True, 'ingress_enabled':enabled, 'listen_ports':[443],
            'management_host':'admin.example.test', 'management_certificate':'admin',
            'management_client_ca':'admin-ca', 'management_allow_cidrs':['127.0.0.1/32']}


def route(name='api', **changes):
    return RouteSpec(id=name, name=name, service_id='demo', listen_port=443,
                     host=name+'.example.test', certificate=name, auth='api_key',
                     rate_per_second=100, upstreams=[{'port':18188}], **changes)


def test_default_port_and_staged_gateway():
    assert RouteSpec(id='example',name='Example',service_id='demo',upstreams=[{'port':18188}]).listen_port == 443
    conf=render(Snapshot(),policy(False),Snapshot().digest(),SECRET)
    assert ':80 ' not in conf and ':443 ' not in conf
    assert ':19091' not in conf and ':19100' not in conf
    assert ':19093' in conf


def test_separate_certs_on_one_port_but_not_on_one_host():
    snap=Snapshot(services=[ServiceSpec(**SPEC)],routes=[route('api'),route('web')])
    # Build mTLS via validated schema rather than bypassing its invariant.
    snap.routes[1]=RouteSpec(**{**route('api').model_dump(),'id':'web','host':'web.example.test','certificate':'web','auth':'mtls','client_ca':'web-ca'})
    validate_snapshot(snap,policy(),inspect_units=False)
    snap.routes[1].host=snap.routes[0].host
    snap.routes[1].path='/other/'
    with pytest.raises(ValidationError): Snapshot.model_validate(snap.model_dump())


@pytest.mark.parametrize('port',[80,19100,8080])
def test_no_other_remote_business_listener(port):
    with pytest.raises(ValueError):
        data=route().model_dump();data['listen_port']=port
        validate_snapshot(Snapshot(services=[ServiceSpec(**SPEC)],routes=[RouteSpec(**data)]),policy(),inspect_units=False)


def test_staged_or_broad_management_policy_refused():
    with pytest.raises(ValueError):
        validate_snapshot(Snapshot(services=[ServiceSpec(**SPEC)],routes=[route()]),policy(False),inspect_units=False)
    with pytest.raises(ValueError): validate_ingress_policy({**policy(),'listen_ports':[443,19100]},False)
    with pytest.raises(ValueError): validate_ingress_policy({**policy(),'management_allow_cidrs':['0.0.0.0/0']},False)
    with pytest.raises(ValueError): Settings(public_origin='https://admin.example.test:8443',_env_file=None)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


@pytest.fixture
def unified_edge(tmp_path):
    nginx,openssl=shutil.which('nginx'),shutil.which('openssl')
    if not nginx or not openssl:pytest.skip('Requires Nginx and OpenSSL')
    def run(*args):
        result=subprocess.run([openssl,*map(str,args)],capture_output=True,text=True)
        assert result.returncode==0,result.stderr
    trust=[]
    for name in ('admin','api','web'):
        directory=tmp_path/name;directory.mkdir()
        run('req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN='+name+'.example.test',
            '-addext','subjectAltName=DNS:'+name+'.example.test','-keyout',directory/'privkey.pem','-out',directory/'fullchain.pem')
        trust.append((directory/'fullchain.pem').read_text())
    trust_path=tmp_path/'trust.pem';trust_path.write_text('\n'.join(trust))
    for name in ('admin-ca','web-ca'):
        ca=tmp_path/name;ca.mkdir();(ca/'newcerts').mkdir()
        for filename,value in [('index',''),('serial','1000\n'),('crlnumber','1000\n')]: (ca/filename).write_text(value)
        config=ca/'openssl.cnf'
        config.write_text(f'''[ ca ]
default_ca = local
[ local ]
database = {ca}/index
new_certs_dir = {ca}/newcerts
certificate = {ca}/ca.pem
private_key = {ca}/ca.key
serial = {ca}/serial
crlnumber = {ca}/crlnumber
default_md = sha256
default_days = 2
default_crl_days = 2
policy = any
[ any ]
commonName = supplied
''')
        run('req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN='+name,'-keyout',ca/'ca.key','-out',ca/'ca.pem')
        run('req','-new','-newkey','rsa:2048','-nodes','-subj','/CN='+name+'-client','-keyout',ca/'probe.key','-out',ca/'client.csr')
        run('ca','-batch','-config',config,'-in',ca/'client.csr','-out',ca/'probe.crt')
        run('ca','-gencrl','-config',config,'-out',ca/'crl.pem')
    class Backend(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            if self.path=='/internal/auth':
                valid=self.headers.get('X-SG-Secret')==SECRET and self.headers.get('X-Gateway-Key')=='good'
                self.send_response(204 if valid else 401);self.send_header('Content-Length','0');self.end_headers();return
            data=json.dumps({'host':self.headers.get('Host'),'path':self.path,'cookie':self.headers.get('Cookie','')}).encode()
            self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    backend=ThreadingHTTPServer(('127.0.0.1',0),Backend)
    threading.Thread(target=backend.serve_forever,daemon=True).start()
    api=route().model_dump();api['upstreams']=[{'port':backend.server_port}]
    web={**api,'id':'web','name':'web','host':'web.example.test','certificate':'web','auth':'mtls','client_ca':'web-ca'}
    snap=Snapshot(services=[ServiceSpec(**SPEC)],routes=[RouteSpec(**api),RouteSpec(**web)])
    acme_policy = {**policy(), 'acme_enabled': True}
    conf=render(snap,acme_policy,snap.digest(),SECRET,backend.server_port)
    tls_port,http_port,status_port=free_port(),free_port(),free_port()
    import os, pwd
    conf=conf.replace('user www-data;', 'user '+pwd.getpwuid(os.getuid()).pw_name+';').replace('/run/servicegateway-edge/nginx.pid',str(tmp_path/'pid')).replace('/srv/e5-logs/servicegateway',str(tmp_path)).replace('/var/lib/servicegateway/edge',str(tmp_path)).replace('/etc/servicegateway/certs',str(tmp_path))
    conf=conf.replace('/var/lib/servicegateway/acme-webroot', str(tmp_path/'acme'))
    challenge=tmp_path/'acme/.well-known/acme-challenge';challenge.mkdir(parents=True)
    (challenge/'test_token-123').write_text('public-acme-proof')
    (tmp_path/'private-secret').write_text('MUST-NOT-LEAK')
    (challenge/'link_token').symlink_to(tmp_path/'private-secret')
    conf=conf.replace('127.0.0.1:443',f'127.0.0.1:{tls_port}').replace('127.0.0.1:80',f'127.0.0.1:{http_port}').replace('127.0.0.1:19093',f'127.0.0.1:{status_port}')
    for directory in ('client','proxy'):(tmp_path/directory).mkdir()
    path=tmp_path/'nginx.conf';path.write_text(conf)
    checked=subprocess.run([nginx,'-t','-p',str(tmp_path),'-c',str(path)],capture_output=True,text=True)
    assert checked.returncode==0,checked.stderr
    proc=subprocess.Popen([nginx,'-p',str(tmp_path),'-c',str(path),'-g','daemon off;'],stderr=subprocess.PIPE)
    try:
        for _ in range(50):
            try:
                with socket.create_connection(('127.0.0.1',tls_port),timeout=.1):break
            except OSError:time.sleep(.05)
        else:pytest.fail('Nginx did not start')
        def request(host,cert=None,path='/',plain=False,sni=None,headers=None):
            if plain:
                conn=http.client.HTTPConnection('127.0.0.1',http_port,timeout=3)
            else:
                ctx=ssl.create_default_context(cafile=str(trust_path))
                if cert:ctx.load_cert_chain(str(tmp_path/cert/'probe.crt'),str(tmp_path/cert/'probe.key'))
                conn=LoopbackTLS(sni or host,tls_port,context=ctx,timeout=3)
            try:
                conn.request('GET',path,headers={'Host':host,**(headers or {})})
                response=conn.getresponse();return response.status,dict(response.getheaders()),response.read()
            finally:conn.close()
        yield request
    finally:
        proc.terminate()
        try:proc.wait(timeout=5)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()
        backend.shutdown();backend.server_close()


def test_real_shared_443_distinct_certificates_and_auth(unified_edge):
    req=unified_edge
    assert req('admin.example.test',cert='admin-ca')[0]==200
    assert req('admin.example.test')[0] in (400,401,403)
    assert req('admin.example.test',cert='web-ca')[0] in (400,401,403)
    assert req('admin.example.test',cert='admin-ca',path='/internal/auth')[0]==404
    assert req('api.example.test')[0]==401
    assert req('api.example.test',headers={'X-Gateway-Key':'good'})[0]==200
    assert req('web.example.test',cert='web-ca')[0]==200
    assert req('web.example.test',cert='admin-ca')[0] in (400,401,403)
    assert req('web.example.test')[0] in (400,401,403)


def test_real_80_only_redirects_known_names(unified_edge):
    status,headers,_=unified_edge('api.example.test',path='/a?q=1',plain=True)
    assert status==308 and headers['Location']=='https://api.example.test/a?q=1'
    assert unified_edge('admin.example.test',plain=True)[0]==308
    assert unified_edge('evil.example.test',plain=True)[0]==404


def test_real_sni_host_mismatch_and_unknown_sni_fail_closed(unified_edge):
    req=unified_edge
    assert req('admin.example.test',sni='api.example.test')[0] in (403,421)
    assert req('admin.example.test',sni='web.example.test',cert='web-ca')[0] in (403,421)
    assert req('web.example.test',sni='admin.example.test',cert='admin-ca')[0]==421
    with pytest.raises(ssl.SSLError):req('unknown.example.test')


def test_real_acme_token_only_and_unchanged_https(unified_edge):
    req = unified_edge
    for host in ('admin.example.test', 'api.example.test', 'new.example.test'):
        status, _, body = req(host, path='/.well-known/acme-challenge/test_token-123', plain=True)
        assert status == 200 and body == b'public-acme-proof'
        assert req(host, path='/.well-known/acme-challenge/missing_token', plain=True)[0] == 404
        assert req(host, path='/.well-known/acme-challenge/link_token', plain=True)[0] in (403, 404)
    assert req('admin.example.test', path='/.well-known/acme-challenge/.env', plain=True)[0] == 404
    assert req('admin.example.test', path='/.well-known/acme-challenge/', plain=True)[0] == 404
    assert req('admin.example.test', cert='admin-ca')[0] == 200
