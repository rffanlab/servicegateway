import os
from urllib.parse import urlsplit
import pytest
from fastapi.testclient import TestClient
from servicegateway.agent import validate_snapshot
from servicegateway.config import Settings
from servicegateway.db import Base, GatewayState, User
from servicegateway.ipc import AgentError
from servicegateway.main import create_app
from servicegateway.schemas import Snapshot
from servicegateway.security import ph

PASSWORD = 'A-test-password-only-12'
SECRET = 'a' * 64
SPEC = {'id':'demo', 'name':'Demo', 'description':'Test service', 'services':['demo.service'], 'url':'http://127.0.0.1:19100', 'port':19100, 'health_url':'http://127.0.0.1:18188/healthz', 'gpu':'CPU / API', 'accent':'cyan', 'warning':'Test warning'}
POLICY = {'remote_mode':False, 'listen_address':'127.0.0.1', 'listen_ports':[19100,19101], 'allowed_cidrs':['127.0.0.1/32'], 'allow_public':False, 'services':{'demo':{'units':['demo.service'], 'upstreams':['127.0.0.1:18188'], 'health_url':SPEC['health_url']}}}


class FakeAgent:
    def __init__(self):
        self.digest = Snapshot().digest()
        self.generation = self.digest
        self.calls = []
        self.fail_apply = False

    def call(self, action, **payload):
        self.calls.append((action, payload))
        if action == 'service':
            spec = payload['spec']
            if spec['id'] != 'demo' or spec['services'] != SPEC['services'] or spec['health_url'] != SPEC['health_url']:
                raise AgentError('Unapproved service')
            return {'state':'running','startup':'enabled','units':[{'unit':'demo.service','active':'active','startup':'enabled','pid':123}]}
        if action == 'status':
            return {'running':True,'digest':self.digest,'generation':self.generation}
        if action == 'inventory':
            return {'manifests':[SPEC], 'grants':POLICY['services'], 'listen_ports':POLICY['listen_ports']}
        if action in ('validate','apply'):
            snap = Snapshot.model_validate(payload['snapshot'])
            try:
                validate_snapshot(snap, POLICY, inspect_units=False)
            except ValueError as exc:
                raise AgentError(str(exc)) from exc
            if action == 'apply':
                if payload['expected'] != self.digest or self.fail_apply:
                    raise AgentError('Simulated publish failure; original edge unchanged')
                self.digest = snap.digest()
                self.generation = payload["generation"]
            return {'digest':snap.digest(),'config':'# REDACTED validated config'}
        if action == 'traffic':
            return {'sample':[], 'sampled_bytes':0}
        if action == 'wechat-config-status':
            return {'configured': True, 'appid': 'wx-test-appid'}
        if action == 'wechat-code2session':
            if payload.get('service_id') != 'demo' or not payload.get('code'):
                raise AgentError('Invalid WeChat login')
            return {'appid':'wx-test-appid','openid':'openid-test-user','unionid':'unionid-test-user'}
        if action == 'route-secret-check':
            if payload.get('route_id') != 'demo-route' or payload.get('token') != 'route-secret-test-value-abcdefghijklmnopqrstuvwxyz012345':
                raise AgentError('Invalid route secret')
            return {'route_id':'demo-route','service_id':'demo'}
        raise AssertionError(action)


@pytest.fixture
def env(tmp_path):
    url = os.environ.get('TEST_MYSQL_URL')
    if url and urlsplit(url).path != '/servicegateway_test':
        pytest.fail('Refusing destructive tests on any database except servicegateway_test')
    secret = tmp_path / 'auth-secret'
    secret.write_text(SECRET)
    settings = Settings(testing=True, deployment_mode="lan", database_url=url or f'sqlite:///{tmp_path}/test.db', secure_cookie=False, monitor_enabled=False, auth_secret_file=str(secret), _env_file=None)
    agent = FakeAgent()
    app = create_app(settings, agent)
    Base.metadata.drop_all(app.state.engine)
    Base.metadata.create_all(app.state.engine)
    with app.state.sessions.begin() as db:
        db.add(GatewayState(id=1, revision=0))
        db.add(User(username='admin', password_hash=ph.hash(PASSWORD), role='admin'))
    with TestClient(app) as client:
        yield client, app, agent


@pytest.fixture
def signed(env):
    client, app, agent = env
    result = client.post('/api/auth/login', json={'username':'admin','password':PASSWORD})
    assert result.status_code == 200, result.text
    client.headers['X-CSRF-Token'] = result.json()['csrf']
    return client, app, agent


def route(**extra):
    return {'id':'demo-route','name':'Demo route','service_id':'demo','listen_port':19100,'upstreams':[{'address':'127.0.0.1','port':18188}], **extra}


def register(client):
    result = client.post('/api/registry/services', json=SPEC)
    assert result.status_code == 200, result.text
    return result.json()['revision']


def save_route(client, **extra):
    revision = client.get('/api/overview').json()['revision']
    result = client.put(f'/api/routes/demo-route?revision={revision}', json=route(**extra))
    assert result.status_code == 200, result.text
    return result.json()['revision']


def publish(client):
    p = client.post('/api/gateway/preview').json()
    result = client.post('/api/gateway/publish', json={'revision':p['revision'],'digest':p['digest'],'note':'test'})
    assert result.status_code == 200, result.text
    return result.json()
