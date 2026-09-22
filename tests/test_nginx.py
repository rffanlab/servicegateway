"""Real Nginx integration: no mocked reverse proxy or systemd commands."""
import base64
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import time
import pytest
import httpx
from servicegateway.nginx import render
from servicegateway.schemas import RouteSpec, ServiceSpec, Snapshot
from conftest import SPEC, SECRET


def unused_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0))
        return s.getsockname()[1]


@pytest.fixture
def real_edge(tmp_path):
    nginx=shutil.which('nginx') or ('/usr/sbin/nginx' if Path('/usr/sbin/nginx').exists() else None)
    if not nginx:
        pytest.skip('Nginx binary is not installed')
    gate=threading.Event()
    class Backend(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def log_message(self,*args):
            pass
        def do_GET(self):
            if self.path=='/internal/auth':
                route=self.headers.get('X-SG-Route')
                if route=='wechat-route':
                    good=self.headers.get('X-SG-Secret')==SECRET and self.headers.get('Authorization')=='Bearer valid-user-token'
                    self.send_response(204 if good else 401)
                    if good:
                        self.send_header('X-SG-User-ID','user-from-auth')
                        self.send_header('X-SG-User-Service','demo')
                        self.send_header('X-SG-User-Role','user')
                        self.send_header('X-SG-OpenID','openid-from-auth')
                        self.send_header('X-SG-UnionID','unionid-from-auth')
                    self.send_header('Content-Length','0'); self.end_headers(); return
                good=self.headers.get('X-SG-Secret')==SECRET and self.headers.get('X-Gateway-Key')=='valid-test-key'
                self.send_response(204 if good else 401); self.send_header('Content-Length','0'); self.end_headers(); return
            if self.path=='/events':
                self.send_response(200); self.send_header('Content-Type','text/event-stream'); self.send_header('Connection','close'); self.end_headers()
                self.wfile.write(b'data: first\n\n'); self.wfile.flush()
                gate.wait(5)
                self.wfile.write(b'data: last\n\n'); self.wfile.flush(); self.close_connection=True; return
            if self.path=='/ws':
                key=self.headers.get('Sec-WebSocket-Key','')
                accept=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
                self.send_response(101); self.send_header('Upgrade','websocket'); self.send_header('Connection','Upgrade'); self.send_header('Sec-WebSocket-Accept',accept); self.end_headers(); self.wfile.flush()
                head=self.rfile.read(2)
                if len(head)!=2: return
                n=head[1]&127; mask=self.rfile.read(4); body=self.rfile.read(n)
                decoded=bytes(x^mask[i%4] for i,x in enumerate(body))
                self.wfile.write(bytes([129,len(decoded)])+decoded); self.wfile.flush(); self.close_connection=True; return
            self.echo()
        def do_POST(self):
            self.echo()
        def echo(self):
            size=int(self.headers.get('Content-Length','0'))
            body=self.rfile.read(size).decode() if size else ''
            data=json.dumps({'path':self.path,'method':self.command,'body':body,'cookie':self.headers.get('Cookie',''),'gateway_key':self.headers.get('X-Gateway-Key',''),'forwarded_for':self.headers.get('X-Forwarded-For',''),'upstream_token':self.headers.get('X-SG-Upstream-Token',''),'sg_route':self.headers.get('X-SG-Route',''),'sg_auth':self.headers.get('X-SG-Auth',''),'user_id':self.headers.get('X-SG-User-ID',''),'user_service':self.headers.get('X-SG-User-Service',''),'user_role':self.headers.get('X-SG-User-Role',''),'openid':self.headers.get('X-SG-OpenID',''),'unionid':self.headers.get('X-SG-UnionID','')}).encode()
            self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
    upstream=ThreadingHTTPServer(('127.0.0.1',0),Backend)
    thread=threading.Thread(target=upstream.serve_forever,daemon=True); thread.start()
    port=unused_port(); status_port=unused_port()
    routes=[RouteSpec(id='test-route',name='Test',service_id='demo',listen_port=port,path='/api/',strip_prefix=True,auth='api_key',upstream_auth={'mode':'route_secret'},upstreams=[{'port':upstream.server_port}]),RouteSpec(id='wechat-route',name='WeChat user',service_id='demo',listen_port=port,path='/user/',auth='wechat',upstream_auth={'mode':'route_secret'},upstreams=[{'port':upstream.server_port}]),RouteSpec(id='stream-route',name='Streams',service_id='demo',listen_port=port,path='/',auth='public',upstreams=[{'port':upstream.server_port}])]
    snap=Snapshot(services=[ServiceSpec(**SPEC)],routes=routes)
    config=render(snap,{'listen_address':'127.0.0.1','allowed_cidrs':['127.0.0.1/32'],'services':{'demo':{'source_cidrs':['127.0.0.1/32']}}},snap.digest(),SECRET,upstream.server_port,upstream_secrets={'test-route':'server-route-secret','wechat-route':'wechat-route-secret'})
    config=config.replace('user www-data;','').replace('/run/servicegateway-edge/nginx.pid',str(tmp_path/'nginx.pid')).replace('/srv/e5-logs/servicegateway',str(tmp_path)).replace('/var/lib/servicegateway/edge',str(tmp_path)).replace('127.0.0.1:19093',f'127.0.0.1:{status_port}')
    (tmp_path/'client').mkdir(); (tmp_path/'proxy').mkdir()
    conf=tmp_path/'nginx.conf'; conf.write_text(config)
    tested=subprocess.run([nginx,'-t','-p',str(tmp_path),'-c',str(conf)],capture_output=True,text=True)
    assert tested.returncode==0,tested.stderr
    process=subprocess.Popen([nginx,'-p',str(tmp_path),'-c',str(conf),'-g','daemon off;'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    try:
        for _ in range(50):
            try:
                with httpx.Client(trust_env=False,timeout=.3) as client:
                    if client.get(f'http://127.0.0.1:{status_port}/_sg/ready').status_code==200:break
            except httpx.HTTPError:time.sleep(.05)
        else:pytest.fail('Nginx failed to start')
        yield port,gate
    finally:
        gate.set(); process.terminate()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill(); process.wait()
        upstream.shutdown(); upstream.server_close()


def test_real_proxy_query_body_auth_and_header_sanitization(real_edge):
    port,_=real_edge
    with httpx.Client(trust_env=False) as c:
        assert c.get(f'http://127.0.0.1:{port}/api/hello').status_code==401
        response=c.post(f'http://127.0.0.1:{port}/api/hello?q=one%20two',content='actual request body',headers={'X-Gateway-Key':'valid-test-key','X-Forwarded-For':'evil','X-SG-Upstream-Token':'evil-client-value','X-SG-Route':'evil-route','X-SG-Auth':'evil-auth','Cookie':'app_cookie=keep; sg_session=do-not-forward; other=keep'})
        assert response.status_code==200,response.text
        data=response.json()
        assert data['path']=='/hello?q=one%20two'
        assert data['body']=='actual request body'
        assert data['gateway_key']==''
        assert data['forwarded_for']=='127.0.0.1'
        assert data['upstream_token']=='server-route-secret'
        assert data['sg_route']=='test-route' and data['sg_auth']=='api_key'
        assert 'app_cookie=keep' in data['cookie']
        assert 'sg_session' not in data['cookie']


def test_real_sse_delivered_before_upstream_finishes(real_edge):
    port,gate=real_edge
    connection=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
    try:
        connection.request('GET','/events')
        response=connection.getresponse()
        assert response.status==200
        assert response.read(len(b'data: first\n\n'))==b'data: first\n\n'
        assert not gate.is_set()
    finally:
        gate.set(); connection.close()


def test_real_websocket_upgrade_and_echo(real_edge):
    port,_=real_edge
    with socket.create_connection(('127.0.0.1',port),timeout=3) as sock:
        key=base64.b64encode(os.urandom(16)).decode()
        request=f'GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n'
        sock.sendall(request.encode()); header=b''
        while not header.endswith(b'\r\n\r\n'):header+=sock.recv(1)
        assert b' 101 ' in header,header
        data=b'gateway-ws'; mask=b'abcd'
        sock.sendall(bytes([129,128+len(data)])+mask+bytes(x^mask[i%4] for i,x in enumerate(data)))
        with sock.makefile('rb') as stream:
            head=stream.read(2); assert head==bytes([129,len(data)])
            assert stream.read(len(data))==data


def test_real_wechat_route_requires_token_and_overwrites_user_headers(real_edge):
    port,_=real_edge
    with httpx.Client(trust_env=False) as c:
        assert c.get(f'http://127.0.0.1:{port}/user/profile').status_code == 401
        response=c.get(f'http://127.0.0.1:{port}/user/profile',headers={
            'Authorization':'Bearer valid-user-token',
            'X-SG-User-ID':'client-spoof',
            'X-SG-User-Service':'evil',
            'X-SG-User-Role':'admin',
            'X-SG-OpenID':'spoof-openid',
            'X-SG-UnionID':'spoof-unionid',
        })
        assert response.status_code == 200,response.text
        data=response.json()
        assert data['sg_route']=='wechat-route' and data['sg_auth']=='wechat'
        assert data['user_id']=='user-from-auth'
        assert data['user_service']=='demo'
        assert data['user_role']=='user'
        assert data['openid']=='openid-from-auth'
        assert data['unionid']=='unionid-from-auth'


def test_real_wechat_reserved_login_endpoints_do_not_fall_through_to_business_root(real_edge):
    port,_=real_edge
    with httpx.Client(trust_env=False) as c:
        login=c.post(f'http://127.0.0.1:{port}/_sg/wechat/demo/login',json={'code':'one-time-code'})
        assert login.status_code == 200,login.text
        assert login.json()['path'] == '/internal/wechat/login/demo'
        me=c.get(f'http://127.0.0.1:{port}/_sg/wechat/demo/me',headers={'Authorization':'Bearer opaque-user-token'})
        assert me.status_code == 200,me.text
        assert me.json()['path'] == '/internal/wechat/me/demo'
