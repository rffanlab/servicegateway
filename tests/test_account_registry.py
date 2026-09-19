import base64
from datetime import timedelta
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from fastapi.testclient import TestClient
from sqlalchemy import select
import pytest
from conftest import PASSWORD, SPEC, SECRET, register
from servicegateway.db import ApiKey, Audit, LoginSession, User, now
from servicegateway.security import verify
from servicegateway.ipc import AgentError

NEW = 'new-password-for-test-54321'


def test_password_change_revokes_every_session(signed):
    c, app, _ = signed
    old_cookie = c.cookies.get('sg_session')
    # A second device with a separate session must also be revoked.
    with TestClient(app) as other:
        assert other.post('/api/auth/login', json={'username':'admin','password':PASSWORD}).status_code == 200
        response = c.post('/api/account/password', json={'current_password':PASSWORD,'new_password':NEW,'confirm_password':NEW})
        assert response.status_code == 200, response.text
        assert c.get('/api/overview').status_code == 401
        assert other.get('/api/overview').status_code == 401
        with app.state.sessions() as db:
            assert not list(db.scalars(select(LoginSession)))
            assert verify(NEW, db.scalar(select(User)).password_hash)
        assert other.post('/api/auth/login',json={'username':'admin','password':PASSWORD}).status_code == 401
        assert other.post('/api/auth/login',json={'username':'admin','password':NEW}).status_code == 200
        text = other.get('/api/audit').text
        assert PASSWORD not in text and NEW not in text and old_cookie not in text


@pytest.mark.parametrize('change,status',[
    ({'current_password':'wrong-password'},403),
    ({'confirm_password':'not-the-same-password'},422),
    ({'new_password':'short','confirm_password':'short'},422),
    ({'new_password':PASSWORD,'confirm_password':PASSWORD},422),
])
def test_bad_password_changes_preserve_session(signed,change,status):
    c,app,_=signed
    data={'current_password':PASSWORD,'new_password':NEW,'confirm_password':NEW,**change}
    response=c.post('/api/account/password',json=data)
    assert response.status_code==status,response.text
    assert c.get('/api/overview').status_code==200
    assert NEW not in response.text and PASSWORD not in response.text
    with app.state.sessions() as db:
        assert verify(PASSWORD, db.scalar(select(User)).password_hash)


def test_password_csrf_required(signed):
    c,_,_=signed
    c.headers.pop('X-CSRF-Token')
    assert c.post('/api/account/password',json={'current_password':PASSWORD,'new_password':NEW,'confirm_password':NEW}).status_code==403


def test_viewer_can_change_own_password_but_not_download_admin_bundle(signed):
    c,_,_=signed
    assert c.post('/api/users',json={'username':'viewer','role':'viewer','password':PASSWORD}).status_code==200
    c.post('/api/auth/logout')
    result=c.post('/api/auth/login',json={'username':'viewer','password':PASSWORD}).json()
    c.headers['X-CSRF-Token']=result['csrf']
    assert c.get('/api/account/security').status_code==200
    assert c.post('/api/account/client-certificate',json={'current_password':PASSWORD}).status_code==403
    assert c.post('/api/account/password',json={'current_password':PASSWORD,'new_password':NEW,'confirm_password':NEW}).status_code==200


def test_encrypted_bundle_is_post_only_authenticated_no_cache(signed,monkeypatch):
    c,app,agent=signed
    binary=b'encrypted-P12-test-body'
    original=agent.call
    calls=[]
    def call(action,**payload):
        calls.append(action)
        if action=='client-bundle':return {'base64':base64.b64encode(binary).decode()}
        return original(action,**payload)
    monkeypatch.setattr(agent,'call',call)
    assert c.get('/api/account/client-certificate').status_code==405
    assert c.post('/api/account/client-certificate',json={'current_password':'wrong'}).status_code==403
    assert 'client-bundle' not in calls
    response=c.post('/api/account/client-certificate',json={'current_password':PASSWORD})
    assert response.status_code==200,response.text
    assert response.content==binary
    assert response.headers['content-type']=='application/x-pkcs12'
    assert response.headers['cache-control']=='no-store, private'
    assert response.headers['content-disposition']=='attachment; filename="admin-browser.p12"'
    assert PASSWORD not in c.get('/api/audit').text
    c.cookies.clear()
    calls.clear()
    assert c.post('/api/account/client-certificate',json={'current_password':PASSWORD}).status_code==401
    assert not calls


def test_bundle_agent_failure_never_leaks_internal_data(signed,monkeypatch):
    c,_,agent=signed
    monkeypatch.setattr(agent,'call',lambda *a,**k: (_ for _ in ()).throw(AgentError('PRIVATE_MARKER')))
    r=c.post('/api/account/client-certificate',json={'current_password':PASSWORD})
    assert r.status_code==503 and 'PRIVATE_MARKER' not in r.text


def key(c,scope='service_ids'):
    result=c.post('/api/keys',json={'name':'local-business',scope:['demo']})
    assert result.status_code==200,result.text
    return result.json()


def test_local_business_key_and_root_approval_required(signed):
    c,app,agent=signed
    token=key(c)
    with TestClient(app,client=('127.0.0.1',23456)) as local:
        local.headers['X-Gateway-Key']=token['token']
        first=local.post('/internal/registry/services',json=SPEC)
        assert first.status_code==200,first.text
        second=local.post('/internal/registry/services',json=SPEC)
        assert second.json()['changed'] is False and second.json()['revision']==first.json()['revision']
        assert local.post('/internal/registry/services',json={**SPEC,'id':'other'}).status_code==403
        assert local.post('/internal/registry/services',json={**SPEC,'services':['unapproved.service']}).status_code==503
        assert local.post('/api/services/demo/actions',json={'action':'start'}).status_code==401
        assert c.delete('/api/keys/'+token['id']).status_code==200
        assert local.post('/internal/registry/services',json=SPEC).status_code==403


def test_local_endpoint_rejects_public_peer_and_cookie_only(signed):
    c,app,_=signed
    token=key(c)
    assert c.post('/internal/registry/services',json=SPEC,headers={'X-Gateway-Key':token['token'],'X-Forwarded-For':'127.0.0.1'}).status_code==403
    with TestClient(app,client=('127.0.0.1',23456)) as local:
        local.cookies.update(c.cookies)
        local.headers.update(c.headers)
        assert local.post('/internal/registry/services',json=SPEC).status_code==403


def test_route_only_key_cannot_register_locally(signed):
    c,app,_=signed
    token=key(c,scope='route_ids')
    with TestClient(app,client=('127.0.0.1',10000)) as local:
        assert local.post('/internal/registry/services',json=SPEC,headers={'X-Gateway-Key':token['token']}).status_code==403


def test_local_key_file_permissions_and_no_follow(tmp_path):
    spec=importlib.util.spec_from_file_location('register_script',Path(__file__).resolve().parents[1]/'deploy/register-local.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    p=tmp_path/'key';p.write_text('sg_example-key-value');p.chmod(0o600)
    assert module.key_from_file(p)=='sg_example-key-value'
    p.chmod(0o644)
    with pytest.raises(ValueError):module.key_from_file(p)
    link=tmp_path/'link';link.symlink_to(p)
    with pytest.raises(OSError):module.key_from_file(link)


def test_form_is_default_and_converts_without_json(tmp_path):
    import subprocess
    root=Path(__file__).resolve().parents[1]
    source=(root/'servicegateway/static/service-form.js').as_uri()
    code=f'''import assert from 'node:assert/strict';import {{serviceFromForm}} from '{source}';
    const form=new FormData();
    for(const [k,v] of Object.entries({{id:'demo',name:'业务',port:'443',health_url:'http://127.0.0.1:18188/healthz',accent:'cyan'}}))form.set(k,v);
    form.append('unit','api.service');form.append('unit','worker.service');
    assert.deepEqual(serviceFromForm(form).services,['api.service','worker.service']);
    assert.equal(serviceFromForm(form).port,443);
    assert.throws(()=>serviceFromForm(form,'different'));
    form.append('unit','api.service');assert.throws(()=>serviceFromForm(form));
    console.log('Form conversion passed');'''
    result=subprocess.run(['node','--input-type=module','-e',code],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    ui=(root/'servicegateway/static/app.js').read_text()
    assert 'serviceFromForm(form' in ui and 'async function serviceEditor' in ui
    assert "field('spec','服务登记 JSON'" not in ui


def test_root_approval_is_explicit_and_preserves_existing_grants(tmp_path,monkeypatch):
    from servicegateway import local_registration as local
    from servicegateway.schemas import ServiceSpec
    path=tmp_path/'policy.json'
    path.write_text('{"services": {}}')
    monkeypatch.setattr(local.os,'geteuid',lambda:0)
    monkeypatch.setattr(local,'root_file',lambda p:Path(p))
    units=[]
    monkeypatch.setattr(local,'unit_info',lambda u:units.append(u))
    settings=SimpleNamespace(policy_file=str(path))
    spec=ServiceSpec(**SPEC)
    local.approve(spec,settings)
    result=path.read_bytes()
    local.approve(spec,settings)
    assert path.read_bytes()==result
    assert units==['demo.service','demo.service']
    with pytest.raises(ValueError):local.approve(ServiceSpec(**{**SPEC,'health_url':'http://127.0.0.1:19092/healthz'}),settings)
    with pytest.raises(ValueError):local.approve(ServiceSpec(**{**SPEC,'services':['other.service']}),settings)
    assert path.read_bytes()==result
    monkeypatch.setattr(local.os,'geteuid',lambda:1234)
    with pytest.raises(PermissionError):local.approve(spec,settings)
