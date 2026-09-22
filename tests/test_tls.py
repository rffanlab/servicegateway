"""Nginx mTLS is tested with a real CA, issued client certificate and CRL."""
import http.client
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import subprocess
import threading
import time
from pathlib import Path
import shutil
import socket
import pytest
from servicegateway.nginx import render
from servicegateway.schemas import RouteSpec, ServiceSpec, Snapshot
from conftest import SPEC, SECRET


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@pytest.fixture
def tls_edge(tmp_path, request):
    nginx=shutil.which('nginx')
    openssl=shutil.which('openssl')
    if not nginx or not openssl:
        pytest.skip('Requires Nginx and OpenSSL')
    ca=tmp_path/'ca'; ca.mkdir()
    for p, data in [('index',''),('serial','1000\n'),('crlnumber','1000\n')]:
        (ca/p).write_text(data)
    (ca/'newcerts').mkdir()
    conf=ca/'openssl.cnf'
    conf.write_text(f'''[ ca ]
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
policy = policy_any
[ policy_any ]
commonName = supplied
''')
    def run(*args):
        p=subprocess.run([openssl,*map(str,args)],capture_output=True,text=True)
        assert p.returncode==0,p.stderr
    run('req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=Test-CA','-keyout',ca/'ca.key','-out',ca/'ca.pem')
    run('req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=Test-client','-keyout',ca/'probe.key','-out',ca/'client.csr')
    run('ca','-batch','-config',conf,'-in',ca/'client.csr','-out',ca/'probe.crt')
    if getattr(request,'param','valid')=='revoked':
        run('ca','-config',conf,'-revoke',ca/'probe.crt')
    run('ca','-gencrl','-config',conf,'-out',ca/'crl.pem')
    srv=tmp_path/'srv';srv.mkdir()
    run('req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1,DNS:localhost','-keyout',srv/'privkey.pem','-out',srv/'fullchain.pem')
    class Backend(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            if self.path == '/internal/auth':
                good=self.headers.get('X-Gateway-Key')=='valid-test-key'
                self.send_response(204 if good else 401);self.send_header('Content-Length','0');self.end_headers();return
            self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'OK')
    backend=ThreadingHTTPServer(('127.0.0.1',0),Backend)
    threading.Thread(target=backend.serve_forever,daemon=True).start()
    port,status=free_port(),free_port()
    mode=getattr(request,'param','valid')
    auth='mtls_api_key' if mode=='combined' else 'mtls'
    snap=Snapshot(services=[ServiceSpec(**SPEC)],routes=[RouteSpec(id='tls-test',name='mTLS',service_id='demo',host='app.example.test',listen_port=port,auth=auth,certificate='srv',client_ca='ca',rate_per_second=10,upstreams=[{'port':backend.server_port}])])
    text=render(snap,{'listen_address':'127.0.0.1','allowed_cidrs':['127.0.0.1/32'],'services':{'demo':{'source_cidrs':['127.0.0.1/32']}}},snap.digest(),SECRET,admin_port=backend.server_port)
    text=text.replace('user www-data;','').replace('/run/servicegateway-edge/nginx.pid',str(tmp_path/'pid')).replace('/srv/e5-logs/servicegateway',str(tmp_path)).replace('/var/lib/servicegateway/edge',str(tmp_path)).replace('/etc/servicegateway/certs',str(tmp_path)).replace('127.0.0.1:19093',f'127.0.0.1:{status}')
    for directory in ('client','proxy'):(tmp_path/directory).mkdir()
    config=tmp_path/'nginx.conf';config.write_text(text)
    checked=subprocess.run([nginx,'-t','-p',str(tmp_path),'-c',str(config)],capture_output=True,text=True)
    assert checked.returncode==0,checked.stderr
    proc=subprocess.Popen([nginx,'-p',str(tmp_path),'-c',str(config),'-g','daemon off;'],stderr=subprocess.PIPE)
    try:
        for _ in range(60):
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.1):break
            except OSError:time.sleep(.05)
        else:pytest.fail('TLS edge did not start')
        def get(client_cert=True, path='/', host='app.example.test', extra=None):
            ctx=ssl.create_default_context(cafile=str(srv/'fullchain.pem'))
            if client_cert:ctx.load_cert_chain(str(ca/'probe.crt'),str(ca/'probe.key'))
            c=http.client.HTTPSConnection('127.0.0.1',port,context=ctx,timeout=3)
            try:
                c.request('GET',path,headers={'Host':host,**(extra or {})})
                res=c.getresponse();body=res.read();return res.status,body
            finally:c.close()
        yield get
    finally:
        proc.terminate()
        try:proc.wait(timeout=5)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()
        backend.shutdown();backend.server_close()


def test_real_tls_requires_cert_and_exact_host(tls_edge):
    assert tls_edge()[0]==200
    assert tls_edge(client_cert=False)[0] in (400,401,403)
    assert tls_edge(host='unknown.example.test')[0]==421
    assert tls_edge(extra={'Origin':'https://evil.example.test'})[0]==403
    assert tls_edge(client_cert=False,path='/_sg/ready')[0] in (400,401,403)


@pytest.mark.parametrize('tls_edge',['revoked'],indirect=True)
def test_real_tls_rejects_revoked_certificate(tls_edge):
    assert tls_edge()[0] in (400,401,403)


@pytest.mark.parametrize('tls_edge',['combined'],indirect=True)
def test_real_tls_and_api_key_are_both_required(tls_edge):
    assert tls_edge(extra={'X-Gateway-Key':'valid-test-key'})[0] == 200
    assert tls_edge()[0] == 401
    assert tls_edge(client_cert=False, extra={'X-Gateway-Key':'valid-test-key'})[0] in (400,401,403)
