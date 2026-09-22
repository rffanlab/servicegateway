import json
from urllib.parse import parse_qs, urlsplit

import pytest
from pydantic import ValidationError

from servicegateway import wechat_apps
from servicegateway.schemas import RouteSpec
from conftest import SECRET, register, route, save_route, publish

ROUTE_SECRET = 'route-secret-test-value-abcdefghijklmnopqrstuvwxyz012345'


def setup_wechat(client, roles=None, route_secret=True):
    register(client)
    save_route(
        client,
        auth='wechat',
        host='app.example.test',
        user_roles=roles or [],
        upstream_auth={'mode':'route_secret' if route_secret else 'none'},
    )
    active = publish(client)
    gateway = {
        'X-SG-Secret': SECRET,
        'X-SG-Digest': active['digest'],
        'X-SG-Business-Host': 'app.example.test',
        'X-SG-Client-IP': '127.0.0.1',
    }
    return active, gateway


def login_wechat(client, gateway, code='temporary-wx-code'):
    response = client.post('/internal/wechat/login/demo', headers=gateway, json={'code': code})
    assert response.status_code == 200, response.text
    data = response.json()
    assert data['access_token'].startswith('sgu_')
    assert data['token_type'] == 'Bearer'
    assert data['user']['openid'] == 'openid-test-user'
    assert data['user']['unionid'] == 'unionid-test-user'
    assert 'session_key' not in json.dumps(data)
    assert 'remark' not in data['user']
    return data


def route_auth_headers(active, token):
    return {
        'X-SG-Secret': SECRET,
        'X-SG-Route': 'demo-route',
        'X-SG-Digest': active['digest'],
        'Authorization': 'Bearer ' + token,
    }


def test_wechat_login_issues_service_token_and_auth_injects_identity(signed):
    client, _, _ = signed
    active, gateway = setup_wechat(client)
    data = login_wechat(client, gateway)
    response = client.get('/internal/auth', headers=route_auth_headers(active, data['access_token']))
    assert response.status_code == 204, response.text
    assert response.headers['X-SG-User-ID'] == data['user']['user_id']
    assert response.headers['X-SG-User-Service'] == 'demo'
    assert response.headers['X-SG-User-Role'] == 'user'
    assert response.headers['X-SG-OpenID'] == 'openid-test-user'
    assert response.headers['X-SG-UnionID'] == 'unionid-test-user'


def test_wechat_me_logout_and_active_release_binding(signed):
    client, _, _ = signed
    _, gateway = setup_wechat(client)
    data = login_wechat(client, gateway)
    bearer = {'Authorization': 'Bearer ' + data['access_token'], **gateway}
    me = client.get('/internal/wechat/me/demo', headers=bearer)
    assert me.status_code == 200
    assert me.json()['openid'] == 'openid-test-user'
    assert 'remark' not in me.json()
    bad = dict(gateway)
    bad['X-SG-Digest'] = '0' * 64
    assert client.post('/internal/wechat/login/demo', headers=bad, json={'code':'new-code'}).status_code == 403
    assert client.post('/internal/wechat/logout/demo', headers=bearer).status_code == 200
    auth = client.get('/internal/auth', headers={
        'X-SG-Secret': SECRET, 'X-SG-Route':'demo-route',
        'X-SG-Digest': gateway['X-SG-Digest'],
        'Authorization':'Bearer ' + data['access_token'],
    })
    assert auth.status_code == 401


def test_business_user_role_gate_admin_edit_and_disable_revokes_tokens(signed):
    client, _, _ = signed
    active, gateway = setup_wechat(client, roles=['vip'])
    data = login_wechat(client, gateway)
    token = data['access_token']
    headers = route_auth_headers(active, token)
    assert client.get('/internal/auth', headers=headers).status_code == 403

    user_id = data['user']['user_id']
    changed = client.patch('/api/business-users/' + user_id, json={
        'role':'vip', 'display_name':'Test User', 'avatar_url':'https://example.test/avatar.png',
        'remark':'gateway-only note', 'enabled':True,
    })
    assert changed.status_code == 200, changed.text
    assert changed.json()['remark'] == 'gateway-only note'
    assert client.get('/internal/auth', headers=headers).status_code == 204

    listed = client.get('/api/business-users?service_id=demo').json()
    assert len(listed) == 1 and listed[0]['openid'] == 'openid-test-user'
    assert listed[0]['remark'] == 'gateway-only note'

    me = client.get('/internal/wechat/me/demo', headers={**gateway, 'Authorization':'Bearer ' + token})
    assert me.status_code == 200 and 'remark' not in me.json()

    disabled = client.patch('/api/business-users/' + user_id, json={'enabled':False})
    assert disabled.status_code == 200
    assert client.get('/internal/auth', headers=headers).status_code == 401


def test_downstream_introspection_returns_openid_but_not_gateway_remark(signed):
    client, _, _ = signed
    _, gateway = setup_wechat(client, route_secret=True)
    data = login_wechat(client, gateway)
    user_id = data['user']['user_id']
    client.patch('/api/business-users/' + user_id, json={'remark':'private admin note'})
    headers = {
        'Authorization':'Bearer ' + data['access_token'],
        'X-SG-Route':'demo-route',
        'X-SG-Upstream-Token':ROUTE_SECRET,
    }
    result = client.post('/internal/business-users/introspect', headers=headers)
    assert result.status_code == 200, result.text
    body = result.json()
    assert body['user_id'] == user_id
    assert body['service_id'] == 'demo'
    assert body['openid'] == 'openid-test-user'
    assert body['unionid'] == 'unionid-test-user'
    assert 'remark' not in body
    assert client.post('/internal/business-users/introspect', headers={**headers, 'X-SG-Upstream-Token':'wrong'}).status_code != 200


def test_revoke_tokens_requires_admin_and_invalidates_current_token(signed):
    client, _, _ = signed
    active, gateway = setup_wechat(client)
    data = login_wechat(client, gateway)
    user_id = data['user']['user_id']
    response = client.post('/api/business-users/' + user_id + '/revoke-tokens', json={})
    assert response.status_code == 200
    assert response.json()['revoked'] >= 1
    assert client.get('/internal/auth', headers=route_auth_headers(active, data['access_token'])).status_code == 401


def test_wechat_route_roles_are_only_valid_for_wechat_auth():
    spec = RouteSpec(**route(auth='wechat', user_roles=['vip','user']))
    assert spec.user_roles == ['vip','user']
    with pytest.raises(ValidationError):
        RouteSpec(**route(auth='api_key', user_roles=['vip']))


def test_code2session_discards_session_key_and_uses_fixed_endpoint(monkeypatch):
    monkeypatch.setattr(wechat_apps, '_read', lambda service_id: {
        'service_id': service_id, 'appid':'wx-test-appid', 'appsecret':'test-app-secret-value-123456',
    })
    captured = {}
    payload = json.dumps({
        'openid':'openid-1', 'unionid':'union-1', 'session_key':'must-never-leave-agent',
    }).encode()

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, limit): return payload

    class Opener:
        def open(self, request, timeout):
            captured['url'] = request.full_url
            captured['timeout'] = timeout
            return Response()

    result = wechat_apps.exchange_code('demo', 'one-time-code', opener=Opener())
    assert result == {'appid':'wx-test-appid', 'openid':'openid-1', 'unionid':'union-1'}
    assert 'session_key' not in result
    parsed = urlsplit(captured['url'])
    assert parsed.scheme == 'https' and parsed.netloc == 'api.weixin.qq.com'
    query = parse_qs(parsed.query)
    assert query['appid'] == ['wx-test-appid']
    assert query['secret'] == ['test-app-secret-value-123456']
    assert query['js_code'] == ['one-time-code']
    assert query['grant_type'] == ['authorization_code']
    assert captured['timeout'] == 8


def test_code2session_rejects_wechat_error_without_echoing_secret(monkeypatch):
    monkeypatch.setattr(wechat_apps, '_read', lambda service_id: {
        'service_id': service_id, 'appid':'wx-test-appid', 'appsecret':'test-app-secret-value-123456',
    })

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, limit): return b'{"errcode":40029,"errmsg":"invalid code"}'

    class Opener:
        def open(self, request, timeout): return Response()

    with pytest.raises(wechat_apps.WechatConfigError) as error:
        wechat_apps.exchange_code('demo', 'bad-code', opener=Opener())
    assert '40029' in str(error.value)
    assert 'test-app-secret' not in str(error.value)
