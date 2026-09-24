from copy import deepcopy
from pathlib import Path
import subprocess
import pytest
from pydantic import ValidationError
from servicegateway.agent import validate_snapshot
from servicegateway.nginx import render
from servicegateway.routing_policy import effective_route_cidrs, normalize_service_source_cidrs
from servicegateway.schemas import RouteSpec, ServiceSpec, Snapshot
from conftest import POLICY, SPEC, SECRET, route, register, save_route, publish


def service_policy():
    policy = deepcopy(POLICY)
    policy['services']['demo']['source_cidrs'] = ['0.0.0.0/0']
    return normalize_service_source_cidrs(policy)


def test_service_source_cidr_can_expand_one_service_without_global_expansion():
    policy = service_policy()
    spec = RouteSpec(**route(auth='api_key', allow_cidrs=['0.0.0.0/0']))
    validate_snapshot(Snapshot(services=[ServiceSpec(**SPEC)], routes=[spec]), policy, inspect_units=False)
    assert effective_route_cidrs(policy, spec) == ['0.0.0.0/0']
    assert policy['allowed_cidrs'] == ['127.0.0.1/32']
    restricted = deepcopy(policy)
    restricted['services']['demo'].pop('source_cidrs')
    with pytest.raises(ValueError):
        validate_snapshot(Snapshot(services=[ServiceSpec(**SPEC)], routes=[spec]), restricted, inspect_units=False)


def test_route_without_explicit_cidr_inherits_service_ceiling_in_nginx():
    policy = service_policy()
    spec = RouteSpec(**route(auth='api_key', allow_cidrs=[]))
    text = render(Snapshot(services=[ServiceSpec(**SPEC)], routes=[spec]), policy,
                  Snapshot(services=[ServiceSpec(**SPEC)], routes=[spec]).digest(), SECRET)
    assert '      allow 0.0.0.0/0;' in text
    assert '      allow 127.0.0.1/32;' not in text


def test_mtls_or_api_key_requires_certificate_ca_and_is_digest_sensitive():
    combined = RouteSpec(**route(auth='mtls_or_api_key', certificate='music-cert', client_ca='admin-ca'))
    assert combined.auth == 'mtls_or_api_key'
    with pytest.raises(ValidationError):
        RouteSpec(**route(auth='mtls_or_api_key', certificate='music-cert'))
    # Compatibility for the briefly shipped old name: semantics are OR, not AND.
    legacy = RouteSpec(**route(auth='mtls_api_key', certificate='music-cert', client_ca='admin-ca'))
    assert legacy.auth == 'mtls_api_key'
    plain = RouteSpec(**route(auth='api_key'))
    assert Snapshot(services=[ServiceSpec(**SPEC)], routes=[combined]).digest() != Snapshot(services=[ServiceSpec(**SPEC)], routes=[plain]).digest()


def test_non_mtls_route_with_stale_client_ca_is_rejected_by_schema():
    with pytest.raises(ValidationError):
        RouteSpec(**route(auth='service_auth', client_ca='admin-ca'))
    with pytest.raises(ValidationError):
        RouteSpec(**route(auth='wechat_user', client_ca='admin-ca'))


def test_internal_auth_allows_verified_certificate_or_scoped_api_key(signed):
    client, _, _ = signed
    register(client)
    save_route(client, auth='mtls_or_api_key', certificate='music-cert', client_ca='admin-ca')
    active = publish(client)
    token = client.post('/api/keys', json={'name':'music','route_ids':['demo-route']}).json()['token']
    base = {'X-SG-Secret':SECRET,'X-SG-Route':'demo-route','X-SG-Digest':active['digest']}
    assert client.get('/internal/auth', headers={**base,'X-SG-Client-Verify':'SUCCESS'}).status_code == 204
    assert client.get('/internal/auth', headers={**base,'X-Gateway-Key':token,'X-SG-Client-Verify':'NONE'}).status_code == 204
    assert client.get('/internal/auth', headers=base).status_code == 401
    assert client.get('/internal/auth', headers={**base,'X-Gateway-Key':'wrong'}).status_code == 401


def test_upstream_secret_preview_is_redacted_and_missing_is_reported(monkeypatch, tmp_path):
    from servicegateway import upstream_secrets as us
    monkeypatch.setattr(us, 'STORE', tmp_path/'store')
    monkeypatch.setattr(us, '_private_dir', lambda: us.STORE.mkdir(exist_ok=True))
    # avoid root-file ownership requirements in a temp test namespace
    monkeypatch.setattr(us, '_read', lambda rid: (_ for _ in ()).throw(FileNotFoundError()))
    r = RouteSpec(**route(upstream_auth={'mode':'route_secret'}))
    snap = Snapshot(services=[ServiceSpec(**SPEC)], routes=[r])
    values, missing = us.resolve(snap, strict=False, preview=True)
    assert values == {} and missing == ['demo-route']


def test_route_clone_helper_keeps_service_and_config_but_changes_identity():
    module = (Path(__file__).parents[1] / 'servicegateway/static/route-tools.js').as_uri()
    script = r"""
import assert from 'node:assert/strict';
const {authUsesClientCa,cloneRouteDraft,normalizeRouteAuthFields}=await import(process.argv[1]);
const routes=[{id:'music-api',name:'Music API',service_id:'music',auth:'mtls_or_api_key',client_ca:'admin-ca',session_users:['legacy'],business_roles:['vip'],upstream_auth:{mode:'route_secret'},upstreams:[{address:'127.0.0.1',port:18888}]},{id:'music-api-copy',name:'existing',service_id:'music'}];
const clone=cloneRouteDraft(routes,'music-api');
assert.equal(clone.id,'music-api-copy-2');
assert.equal(clone.service_id,'music');
assert.equal(clone.auth,'mtls_or_api_key');
assert.equal(clone.client_ca,'admin-ca');
assert.equal(clone.upstream_auth.mode,'route_secret');
clone.upstreams[0].port=19999;
assert.equal(routes[0].upstreams[0].port,18888);
assert.equal(authUsesClientCa('mtls'),true);
assert.equal(authUsesClientCa('mtls_or_api_key'),true);
assert.equal(authUsesClientCa('service_auth'),false);
clone.auth='service_auth';
const publicClone=normalizeRouteAuthFields(clone);
assert.equal(publicClone.client_ca,null);
assert.deepEqual(publicClone.session_users,[]);
assert.deepEqual(publicClone.business_roles,[]);
assert.equal(clone.client_ca,'admin-ca');
const wechat=normalizeRouteAuthFields({...clone,auth:'wechat_user',business_roles:['vip']});
assert.equal(wechat.client_ca,null);
assert.deepEqual(wechat.business_roles,['vip']);
"""
    result = subprocess.run(['node','--input-type=module','-e',script,module],capture_output=True,text=True,timeout=10)
    assert result.returncode == 0, result.stderr
