import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from conftest import SECRET, SPEC, POLICY, register, save_route, publish
from servicegateway.nginx import render
from servicegateway.schemas import RouteSpec, ServiceSpec, Snapshot


def edge_headers(active):
    return {
        'X-SG-Secret': SECRET,
        'X-SG-Digest': active['digest'],
        'X-SG-Service': 'demo',
        'X-SG-Business-Host': '_',
        'X-SG-Client-IP': '203.0.113.10',
    }


def test_wechat_login_creates_service_user_and_token_userinfo(signed):
    client, _, agent = signed
    register(client)
    save_route(client, auth='wechat_user')
    active = publish(client)
    headers = edge_headers(active)

    login = client.post('/internal/wechat/login', headers=headers, json={'code':'abc123'})
    assert login.status_code == 200, login.text
    body = login.json()
    assert body['access_token'].startswith('sgu_')
    assert body['user']['service_id'] == 'demo'
    assert body['user']['wechat']['openid'] == 'openid_abc123'
    assert 'session_key' not in login.text

    bearer = {'Authorization':'Bearer ' + body['access_token']}
    info = client.get('/internal/wechat/userinfo', headers={**headers, **bearer})
    assert info.status_code == 200
    assert info.json()['wechat']['openid'] == 'openid_abc123'

    introspect = client.post('/internal/business-users/introspect',
                             json={'service_id':'demo','token':body['access_token']})
    assert introspect.status_code == 200
    assert introspect.json()['token']['active'] is True
    assert introspect.json()['wechat']['openid'] == 'openid_abc123'

    wrong_service = client.post('/internal/business-users/introspect',
                                 json={'service_id':'other','token':body['access_token']})
    assert wrong_service.status_code == 403

    auth = client.get('/internal/auth', headers={
        'X-SG-Secret':SECRET, 'X-SG-Route':'demo-route',
        'X-SG-Digest':active['digest'], **bearer})
    assert auth.status_code == 204
    assert auth.headers['X-SG-User-ID'] == body['user']['id']
    assert auth.headers['X-SG-User-Role'] == 'user'
    assert auth.headers['X-SG-WeChat-OpenID'] == 'openid_abc123'
    assert any(action == 'wechat-login' for action, _ in agent.calls)


def test_business_role_and_disable_are_enforced(signed):
    client, _, _ = signed
    register(client)
    save_route(client, auth='wechat_user', business_roles=['vip'])
    active = publish(client)
    login = client.post('/internal/wechat/login', headers=edge_headers(active), json={'code':'role123'})
    assert login.status_code == 200
    token = login.json()['access_token']
    user_id = login.json()['user']['id']
    auth_headers = {'X-SG-Secret':SECRET,'X-SG-Route':'demo-route',
                    'X-SG-Digest':active['digest'],'Authorization':'Bearer '+token}
    assert client.get('/internal/auth', headers=auth_headers).status_code == 403

    update = client.patch('/api/business-users/' + user_id,
                          json={'role':'vip','enabled':True,'display_name':'VIP','remark':'test'})
    assert update.status_code == 200, update.text
    assert client.get('/internal/auth', headers=auth_headers).status_code == 204

    disabled = client.patch('/api/business-users/' + user_id,
                            json={'role':'vip','enabled':False,'display_name':'VIP','remark':'blocked'})
    assert disabled.status_code == 200
    assert client.get('/internal/auth', headers=auth_headers).status_code in (401,403)


def test_business_user_admin_list_and_revoke(signed):
    client, _, _ = signed
    register(client)
    save_route(client, auth='wechat_user')
    active = publish(client)
    login = client.post('/internal/wechat/login', headers=edge_headers(active), json={'code':'list123'}).json()
    users = client.get('/api/business-users?service_id=demo')
    assert users.status_code == 200 and len(users.json()) == 1
    assert users.json()[0]['wechat']['openid'] == 'openid_list123'
    status = client.get('/api/business-auth/wechat/demo')
    assert status.status_code == 200 and status.json()['enabled'] is True
    revoke = client.post('/api/business-users/' + login['user']['id'] + '/revoke-sessions', json={})
    assert revoke.status_code == 200
    assert client.post('/internal/business-users/introspect',
                       json={'service_id':'demo','token':login['access_token']}).status_code == 401


def test_login_requires_published_wechat_route(signed):
    client, _, _ = signed
    register(client)
    # No published wechat_user route.
    empty = {'X-SG-Secret':SECRET,'X-SG-Digest':Snapshot(services=[ServiceSpec(**SPEC)]).digest(),
             'X-SG-Service':'demo','X-SG-Business-Host':'_','X-SG-Client-IP':'203.0.113.1'}
    assert client.post('/internal/wechat/login', headers=empty, json={'code':'abc'}).status_code == 403


def test_wechat_exchange_discards_session_key(monkeypatch):
    from servicegateway import wechat

    monkeypatch.setattr(wechat, 'read', lambda sid: {
        'service_id':sid,'appid':'wx0123456789abcdef','app_secret':'s'*32,'enabled':True
    })

    class Response:
        def raise_for_status(self): pass
        def json(self):
            return {'openid':'openid_demo','unionid':'union_demo','session_key':'MUST-NOT-ESCAPE'}
    class Client:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, url, params):
            assert url == 'https://api.weixin.qq.com/sns/jscode2session'
            assert params['grant_type'] == 'authorization_code'
            return Response()
    monkeypatch.setattr(wechat.httpx, 'Client', Client)
    result = wechat.exchange_code('demo','valid_code')
    assert result == {'appid':'wx0123456789abcdef','openid':'openid_demo','unionid':'union_demo'}


def test_wechat_route_nginx_config_has_public_login_and_trusted_identity(tmp_path):
    nginx = shutil.which('nginx')
    route = RouteSpec(id='wx-route', name='WX', service_id='demo', listen_port=19155,
                      path='/api/', auth='wechat_user', rate_per_second=10,
                      upstreams=[{'address':'127.0.0.1','port':18188}])
    snap = Snapshot(services=[ServiceSpec(**SPEC)], routes=[route])
    policy = {**POLICY, 'listen_ports':[19155], 'services':{
        'demo':{**POLICY['services']['demo'], 'source_cidrs':['0.0.0.0/0']}
    }}
    text = render(snap, policy, snap.digest(), SECRET)
    assert 'location = /_sg/wechat/demo/login' in text
    assert 'location = /_sg/wechat/demo/userinfo' in text
    assert 'proxy_set_header Authorization $http_authorization;' in text
    assert 'auth_request /_sg/auth/wx-route;' in text
    assert 'proxy_set_header X-SG-User-ID $sg_user_id_wx_route;' in text
    assert 'proxy_set_header X-SG-WeChat-OpenID $sg_openid_wx_route;' in text
    assert 'allow 0.0.0.0/0;' in text
    if not nginx:
        return
    # Syntax-check the actual generated config.
    status_port = 19156
    text = text.replace('user www-data;','').replace('/run/servicegateway-edge/nginx.pid',str(tmp_path/'pid'))
    text = text.replace('/srv/e5-logs/servicegateway',str(tmp_path)).replace('/var/lib/servicegateway/edge',str(tmp_path))
    text = text.replace('127.0.0.1:19093',f'127.0.0.1:{status_port}')
    for name in ('client','proxy','fastcgi','uwsgi','scgi'):
        (tmp_path/name).mkdir()
    conf = tmp_path/'nginx.conf'; conf.write_text(text)
    result = subprocess.run([nginx,'-t','-p',str(tmp_path),'-c',str(conf)],
                            capture_output=True,text=True)
    assert result.returncode == 0, result.stderr
