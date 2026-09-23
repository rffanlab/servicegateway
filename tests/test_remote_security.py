from copy import deepcopy
from datetime import timedelta
import pytest
from pydantic import ValidationError
from sqlalchemy import select
from fastapi.testclient import TestClient
from servicegateway.agent import validate_snapshot
from servicegateway.nginx import render
from servicegateway.config import Settings
from servicegateway.db import LoginSession, now
from servicegateway.schemas import Snapshot, RouteSpec, ServiceSpec
from conftest import POLICY, SPEC, PASSWORD, SECRET, route, register, save_route, publish


def remote_policy():
    return {**deepcopy(POLICY), 'remote_mode': True, 'listen_ports': [443], 'ingress_enabled': True, 'management_host': 'admin.example.test', 'management_certificate':'admin', 'management_client_ca':'admin-ca', 'management_allow_cidrs':['127.0.0.1/32']}


def remote_route(**extra):
    return route(listen_port=443, auth='api_key', host='app.example.test', certificate='tls-app', rate_per_second=10, **extra)


@pytest.mark.parametrize('bad', [dict(secure_cookie=False),dict(cookie_domain='example.test'),dict(public_origin='http://admin.example.test')])
def test_remote_settings_fail_closed(bad):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, deployment_mode='remote', **bad)


@pytest.mark.parametrize('bad', [dict(auth='public'),dict(auth='e5'),dict(auth='session'),dict(certificate=None),dict(host='_'),dict(host='admin.example.test'),dict(rate_per_second=0)])
def test_remote_routes_fail_closed(bad):
    data=remote_route(); data.update(bad)
    with pytest.raises(ValueError):
        validate_snapshot(Snapshot(services=[ServiceSpec(**SPEC)],routes=[RouteSpec(**data)]), remote_policy(), inspect_units=False)


def test_remote_service_auth_and_mixed_mtls_paths_are_allowed():
    policy = remote_policy()
    public_data = remote_route()
    public_data.update(id='public-api', name='Public API', path='/open/', auth='service_auth')
    admin_data = remote_route()
    admin_data.update(id='admin-api', name='Admin API', path='/admin/', auth='mtls', client_ca='admin-ca')
    snap = Snapshot(services=[ServiceSpec(**SPEC)],
                    routes=[RouteSpec(**public_data), RouteSpec(**admin_data)])
    validate_snapshot(snap, policy, inspect_units=False)
    config = render(snap, policy, snap.digest(), SECRET)
    assert "ssl_verify_client optional;" in config
    assert "location ^~ /open/" in config
    assert "location ^~ /admin/" in config
    assert "if ($ssl_client_verify != SUCCESS) { return 403; }" in config


def test_remote_tls_key_route_allowed_and_metadata_forbidden():
    p=remote_policy()
    data=remote_route()
    validate_snapshot(Snapshot(services=[ServiceSpec(**SPEC)],routes=[RouteSpec(**data)]),p,inspect_units=False)
    data['upstreams']=[{'address':'169.254.169.254','port':8080}]
    p['services']['demo']['upstreams'].append('169.254.169.254:8080')
    with pytest.raises(ValueError):
        validate_snapshot(Snapshot(services=[ServiceSpec(**SPEC)],routes=[RouteSpec(**data)]),p,inspect_units=False)


def test_host_origin_duplicate_headers_and_body_limit(signed):
    c,_,_=signed
    assert c.get('/api/overview',headers={'Host':'attacker.example'}).status_code==400
    assert c.post('/api/registry/services',json=SPEC,headers={'Origin':'https://evil.example'}).status_code==403
    assert c.post('/api/registry/services',json=SPEC,headers={'Sec-Fetch-Site':'same-site'}).status_code==403
    assert c.post('/api/registry/services',content='x'*2097153,headers={'Content-Type':'application/json'}).status_code==413
    assert c.post('/api/auth/login',content='username=x&password=do-not-echo',headers={'Content-Type':'application/x-www-form-urlencoded'}).status_code==415
    assert c.get('/api/overview',headers=[('X-Gateway-Key','one'),('X-Gateway-Key','two')]).status_code==400
    assert c.get('/api/overview',headers={'Cookie':'sg_session=one; sg_session=two'}).status_code==400


def test_validation_does_not_echo_password(env):
    c,_,_=env
    secret='private-test-password-marker'*20
    response=c.post('/api/auth/login',json={'username':'admin','password':secret})
    assert response.status_code==422
    assert 'private-test-password-marker' not in response.text


def test_idle_expiry_and_recent_auth_gate(signed):
    c,app,_=signed
    with app.state.sessions.begin() as db:
        row=db.scalar(select(LoginSession))
        row.reauthenticated_at=now()-timedelta(minutes=10)
    result=c.post('/api/keys',json={'name':'new','route_ids':['demo-route']})
    assert result.status_code==428
    assert c.post('/api/auth/reauth',json={'password':PASSWORD}).status_code==200
    assert c.post('/api/keys',json={'name':'new','route_ids':['demo-route']}).status_code==200
    with app.state.sessions.begin() as db:
        row=db.scalar(select(LoginSession))
        row.last_seen_at=now()-timedelta(minutes=31)
    assert c.get('/api/overview').status_code==401


def test_old_nginx_worker_never_uses_new_weaker_auth(signed):
    c,_,_=signed
    register(c);save_route(c);first=publish(c)
    save_route(c,auth='api_key');second=publish(c)
    headers={'X-SG-Secret':SECRET,'X-SG-Route':'demo-route','X-SG-Digest':first['digest']}
    assert c.get('/internal/auth',headers=headers).status_code==403


def test_remote_cookie_is_secure_host_only(signed):
    c,app,_=signed
    old=app.state.settings
    app.state.settings=Settings(testing=True, deployment_mode='remote', _env_file=None,
                                public_origin='https://admin.example.test', database_url=old.database_url,
                                monitor_enabled=False, auth_secret_file=old.auth_secret_file)
    # The factory closes over settings for cookie issuance. Build a separate app using same DB.
    from servicegateway.main import create_app
    remote=create_app(app.state.settings, app.state.agent)
    with TestClient(remote,base_url='https://admin.example.test') as browser:
        response=browser.post('/api/auth/login',json={'username':'admin','password':PASSWORD})
        assert response.status_code==200,response.text
        cookie=response.headers['set-cookie']
        assert '__Host-sg_session=' in cookie
        assert 'Secure' in cookie and 'HttpOnly' in cookie and 'SameSite=strict' in cookie
        assert 'Domain=' not in cookie
        assert browser.get('/api/overview').status_code==200
        assert browser.post('/api/auth/logout',headers={'Origin':'https://other.example.test','X-CSRF-Token':response.json()['csrf']}).status_code==403


def test_unlisted_viewer_cannot_open_session_service(signed):
    c,app,_=signed
    register(c); save_route(c); first=publish(c)
    assert c.post('/api/users',json={'username':'view','password':PASSWORD,'role':'viewer'}).status_code==200
    c.post('/api/auth/logout')
    c.post('/api/auth/login',json={'username':'view','password':PASSWORD})
    assert c.get('/internal/auth',headers={'X-SG-Secret':SECRET,'X-SG-Route':'demo-route','X-SG-Digest':first['digest']}).status_code==403
