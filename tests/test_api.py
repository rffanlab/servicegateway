from conftest import PASSWORD, SECRET, SPEC, publish, register, route, save_route
from servicegateway.db import ApiKey, Audit, LoginSession, User
from sqlalchemy import select
from servicegateway.security import ph


def test_unauthenticated_requests_and_wrong_password(env):
    c, _, _ = env
    assert c.get('/api/overview').status_code == 401
    assert c.post('/api/auth/login',json={'username':'admin','password':'wrong'}).status_code == 401
    assert c.get('/internal/auth').status_code == 403
    assert c.get('/healthz').status_code == 200
    assert c.get('/').status_code == 200


def test_csrf_and_hashed_sessions(signed):
    c, app, _ = signed
    csrf = c.headers.pop('X-CSRF-Token')
    assert c.post('/api/registry/services',json=SPEC).status_code == 403
    c.headers['X-CSRF-Token'] = csrf
    register(c)
    with app.state.sessions() as db:
        session = db.scalar(select(LoginSession))
        assert session.token_hash != c.cookies['sg_session']
        user = db.scalar(select(User))
        assert PASSWORD not in user.password_hash


def test_registration_idempotency_and_approval(signed):
    c, _, _ = signed
    revision = register(c)
    second = c.post('/api/registry/services',json=SPEC).json()
    assert second['revision'] == revision and not second['changed']
    result = c.post('/api/registry/services',json={**SPEC,'services':['unapproved.service']})
    assert result.status_code == 503
    assert c.get('/api/registry/services').json()[0]['services'] == SPEC['services']


def test_optimistic_routes_preview_publish_rollback(signed):
    c, _, agent = signed
    register(c)
    save_route(c)
    assert c.get('/api/overview').json()['active_release'] is None
    assert c.put('/api/routes/demo-route?revision=0',json=route()).status_code == 409
    first = publish(c)
    assert first['status'] == 'active' and agent.digest == first['digest']
    save_route(c, auth='api_key')
    # Unpublished draft cannot alter auth on the live route.
    headers={'X-SG-Secret':SECRET,'X-SG-Route':'demo-route','X-SG-Digest':first['digest']}
    assert c.get('/internal/auth',headers=headers).status_code == 204
    second = publish(c)
    assert second['digest'] != first['digest']
    overview = c.get('/api/overview').json()
    result=c.post('/api/gateway/rollback/'+first['id'],json={'revision':overview['revision'],'digest':first['digest'],'note':'rollback'})
    assert result.status_code == 200, result.text
    assert agent.digest == first['digest']
    assert c.get('/api/overview').json()['routes'][0]['auth']=='api_key'


def test_publish_failure_preserves_active(signed):
    c, _, agent=signed
    register(c); save_route(c)
    first=publish(c)
    save_route(c, timeout_seconds=60)
    agent.fail_apply=True
    preview=c.post('/api/gateway/preview').json()
    result=c.post('/api/gateway/publish',json={'revision':preview['revision'],'digest':preview['digest']})
    assert result.status_code == 502, result.text
    overview=c.get('/api/overview').json()
    assert overview['active_release']['id']==first['id']
    assert overview['pending_release'] is None
    assert agent.digest == first['digest']


def test_api_key_scopes_hashing_and_immediate_revocation(signed):
    c, app, _=signed
    register(c); save_route(c,auth='api_key'); active=publish(c)
    result=c.post('/api/keys',json={'name':'scoped','route_ids':['demo-route']})
    assert result.status_code==200,result.text
    key=result.json()
    with app.state.sessions() as db:
        assert db.get(ApiKey,key['id']).token_hash != key['token']
    headers={'X-SG-Secret':SECRET,'X-SG-Route':'demo-route','X-SG-Digest':active['digest'],'X-Gateway-Key':key['token']}
    assert c.get('/internal/auth',headers=headers).status_code==204
    assert key['token'] not in c.get('/api/keys').text
    assert c.delete('/api/keys/'+key['id']).status_code==200
    assert c.get('/internal/auth',headers=headers).status_code==401


def test_key_scope_ids_must_exist_or_be_root_approved(signed):
    c, _, _ = signed
    # Root-approved service IDs are valid registration scopes even before MySQL registration.
    result = c.post('/api/keys', json={'name':'pre-register','service_ids':['demo']})
    assert result.status_code == 200, result.text
    assert c.post('/api/keys', json={'name':'bad-register','service_ids':['not-approved']}).status_code == 422

    register(c)
    # User introspection scope requires an actually registered service.
    assert c.post('/api/keys', json={'name':'user-scope','user_service_ids':['demo']}).status_code == 200
    assert c.post('/api/keys', json={'name':'bad-user-scope','user_service_ids':['not-registered']}).status_code == 422

    # Route scope requires an existing route draft.
    assert c.post('/api/keys', json={'name':'missing-route','route_ids':['demo-route']}).status_code == 422
    save_route(c, auth='api_key')
    assert c.post('/api/keys', json={'name':'route-scope','route_ids':['demo-route']}).status_code == 200


def test_key_scope_picker_exposes_route_and_service_ids():
    from pathlib import Path
    import subprocess
    module = (Path(__file__).parents[1] / 'servicegateway/static/key-tools.js').as_uri()
    script = r"""
import assert from 'node:assert/strict';
const {keyScopeData,collectKeyScopes}=await import(process.argv[1]);
const overview={
  assets:[{id:'music',name:'AI Music'}],
  routes:[{id:'music-public',name:'Public API',service_id:'music',host:'music.example.test',path:'/api/',auth:'service_auth'}]
};
const inventory={grants:{music:{},avatar:{}}};
const data=keyScopeData(overview,inventory);
assert.deepEqual(data.routes.map(x=>x.id),['music-public']);
assert.deepEqual(data.services.map(x=>x.id),['music']);
assert.deepEqual(data.approved_services.map(x=>x.id),['avatar','music']);
assert.equal(data.approved_services.find(x=>x.id==='avatar').name,'avatar');
const fake={getAll(name){return {
  route_ids:['music-public','music-public'],
  service_ids:['avatar'],
  user_service_ids:['music']
}[name]??[];}};
assert.deepEqual(collectKeyScopes(fake),{
  route_ids:['music-public'],
  service_ids:['avatar'],
  user_service_ids:['music']
});
"""
    result = subprocess.run(['node','--input-type=module','-e',script,module],
                            capture_output=True,text=True,timeout=10)
    assert result.returncode == 0, result.stderr


def test_registry_key_is_not_a_lifecycle_admin(signed):
    c, _, _=signed
    key=c.post('/api/keys',json={'name':'deploy-demo','service_ids':['demo']}).json()['token']
    c.cookies.clear()
    c.headers.pop('X-CSRF-Token',None)
    c.headers['X-Gateway-Key']=key
    assert c.post('/api/registry/services',json=SPEC).status_code==200
    assert c.post('/api/services/demo/actions',json={'action':'start'}).status_code==401
    assert c.post('/api/registry/services',json={**SPEC,'id':'other'}).status_code==401


def test_import_preview_conflicts_and_no_override(signed):
    c, _, _=signed
    preview=c.post('/api/import/e5',json={'services':[SPEC]}).json()
    assert preview['additions']==['demo']
    assert c.get('/api/registry/services').json()==[]
    result=c.post('/api/import/e5',json={'services':[SPEC],'apply':True,'revision':preview['revision']})
    assert result.status_code==200,result.text
    result=c.post('/api/import/e5',json={'services':[{**SPEC,'name':'overwrite'}],'apply':True,'revision':1})
    assert result.status_code==409
    assert c.get('/api/registry/services').json()[0]['name']=='Demo'


def test_draft_deletion_does_not_delete_live_service(signed):
    c, _, _=signed
    register(c); save_route(c); publish(c)
    assert c.delete('/api/registry/services/demo').status_code==409
    revision=c.get('/api/overview').json()['revision']
    assert c.delete('/api/routes/demo-route?revision='+str(revision)).status_code==200
    assert c.delete('/api/registry/services/demo').status_code==409
    publish(c)
    assert c.delete('/api/registry/services/demo').status_code==200


def test_viewer_permissions_and_disable_session(signed):
    c, app, _=signed
    assert c.post('/api/users',json={'username':'viewer','password':PASSWORD,'role':'viewer'}).status_code==200
    c.post('/api/auth/logout')
    login=c.post('/api/auth/login',json={'username':'viewer','password':PASSWORD}).json()
    c.headers['X-CSRF-Token']=login['csrf']
    assert c.get('/api/overview').status_code==200
    assert c.get('/api/keys').status_code==403
    assert c.post('/api/gateway/preview').status_code==403
    assert c.post('/api/services/demo/actions',json={'action':'start'}).status_code==403


def test_stop_confirmation_and_audit(signed):
    c, app, agent=signed
    register(c)
    assert c.post('/api/services/demo/actions',json={'action':'stop','confirm':'wrong'}).status_code==409
    # Network probe is allowed to fail; it must not turn a completed lifecycle request into an error.
    result=c.post('/api/services/demo/actions',json={'action':'stop','confirm':'Demo'})
    assert result.status_code==200,result.text
    records=c.get('/api/audit').json()
    assert any(x['action']=='service.stop' and x['outcome']=='started' for x in records)
    assert any(x['action']=='service.stop' and x['outcome']=='success' for x in records)
    assert PASSWORD not in str(records)
