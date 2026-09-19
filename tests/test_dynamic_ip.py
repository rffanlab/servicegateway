"""Dynamic admin egress: optional IP filtering never weakens certificate/password auth."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from servicegateway.ingress import render_frontdoor, validate_ingress_policy
from servicegateway.schemas import Snapshot
from test_deployment import bootstrap
from test_unified_ingress import policy, unified_edge

DYNAMIC = {'management_ip_filter': False, 'management_allow_cidrs': []}


def install_args(*extra):
    return bootstrap.parser().parse_args([
        '--domain', 'admin.example.com', '--email', 'admin@example.com', '--agree-tos', *extra])


def test_install_needs_domain_and_email_not_a_fixed_ip():
    args = install_args()
    bootstrap.validate_args(args)
    assert args.admin_cidr == []
    for missing in ('domain', 'email'):
        invalid = deepcopy(args)
        setattr(invalid, missing, None)
        with pytest.raises(bootstrap.Stop):
            bootstrap.validate_args(invalid)


@pytest.mark.parametrize('sources', [[], ['203.0.113.9/32', '203.0.113.10/32']])
def test_installer_emits_explicit_access_mode_and_preserves_it_on_rerun(monkeypatch, tmp_path, sources):
    monkeypatch.setattr(bootstrap, 'mkdir', lambda p, mode=0o700: Path(p).mkdir(parents=True, exist_ok=True))
    monkeypatch.setattr(bootstrap, 'CFG', tmp_path)
    monkeypatch.setattr(bootstrap, 'STATE', tmp_path/'bootstrap.json')
    monkeypatch.setattr(bootstrap, 'owned', lambda p, *a: Path(p))
    monkeypatch.setattr(bootstrap, 'mysql', lambda *a: '')
    args = install_args(*[item for address in sources for item in ('--admin-cidr', address)])
    bootstrap.validate_args(args)
    saved = bootstrap.setup_database(args, {})
    expected = (tmp_path/'policy.json').read_bytes()
    actual = json.loads(expected)
    assert actual['management_ip_filter'] is bool(sources)
    assert actual['management_allow_cidrs'] == (['127.0.0.1/32', *sources] if sources else [])
    assert actual['allowed_cidrs'] == ['127.0.0.1/32']  # Business ACL is independent.
    assert actual['management_client_ca'] == 'admin-ca'
    args2 = bootstrap.parser().parse_args(['--agree-tos'])
    bootstrap.validate_args(args2, saved)
    bootstrap.setup_database(args2, saved)
    assert (tmp_path/'policy.json').read_bytes() == expected
    assert args2.admin_cidr == sources


def test_legacy_bootstrap_keeps_its_allowlist_when_flag_is_omitted():
    saved = {'domain': 'admin.example.com', 'email': 'admin@example.com',
             'admin_user': 'rffanlab', 'admin_cidrs': ['203.0.113.9/32']}
    args = bootstrap.parser().parse_args(['--agree-tos'])
    bootstrap.validate_args(args, saved)
    assert args.admin_cidr == saved['admin_cidrs']
    changed = install_args('--admin-cidr', '203.0.113.10/32')
    with pytest.raises(bootstrap.Stop):
        bootstrap.validate_args(changed, saved)


def test_dynamic_mode_omits_only_source_restrictions():
    p = {**policy(), **DYNAMIC}
    validate_ingress_policy(p, inspect_files=False)
    conf = '\n'.join(render_frontdoor(Snapshot(), p, 'a'*64, 'b'*32, 19092))
    assert '    allow ' not in conf
    assert '    deny all;' not in conf
    for invariant in ('ssl_verify_client on', 'ssl_crl ', '$ssl_client_verify != SUCCESS',
                      'limit_conn sg_admin_conn 16', 'zone=sg_admin_login',
                      'location ^~ /internal/ { return 404; }', 'proxy_pass http://127.0.0.1:19092'):
        assert invariant in conf
    assert 'ssl_verify_client optional' not in conf
    assert 'satisfy any' not in conf


def test_legacy_policy_still_enforces_its_acl():
    p = policy()
    assert 'management_ip_filter' not in p
    conf = '\n'.join(render_frontdoor(Snapshot(), p, 'a'*64, 'b'*32, 19092))
    assert 'allow 127.0.0.1/32;' in conf and 'deny all;' in conf


@pytest.mark.parametrize('value', ['false', 'true', 0, 1, None])
def test_access_toggle_requires_an_actual_boolean_even_when_staged(value):
    with pytest.raises(ValueError):
        validate_ingress_policy({**policy(False), **DYNAMIC, 'management_ip_filter': value}, False)


@pytest.mark.parametrize('changes', [
    {'management_allow_cidrs': ['203.0.113.9/32']},
    {'management_allow_cidrs': '[]'},
    {'management_client_ca': ''},
    {'management_certificate': ''},
])
def test_dynamic_mode_cannot_ignore_ambiguous_acl_or_omit_certificates(changes):
    with pytest.raises(ValueError):
        validate_ingress_policy({**policy(), **DYNAMIC, **changes}, False)


@pytest.mark.parametrize('unified_edge', [{'policy': DYNAMIC}], indirect=True)
def test_real_nginx_same_certificate_from_two_source_addresses(unified_edge):
    for source in ('127.0.0.2', '127.0.0.3'):
        code, _, body = unified_edge('admin.example.test', cert='admin-ca', source=source)
        assert code == 200
        assert json.loads(body)['forwarded_for'] == source
        assert unified_edge('admin.example.test', source=source)[0] in (400, 401, 403)
        assert unified_edge('admin.example.test', cert='web-ca', source=source)[0] in (400, 401, 403)
        assert unified_edge('admin.example.test', cert='admin-ca', path='/internal/auth', source=source)[0] == 404
    # Dynamic management IP does not widen business route ACLs.
    assert unified_edge('web.example.test', cert='web-ca', source='127.0.0.2')[0] == 403


@pytest.mark.parametrize('unified_edge', [{'policy': DYNAMIC, 'revoke_admin': True}], indirect=True)
def test_real_nginx_dynamic_access_still_rejects_revoked_client(unified_edge):
    assert unified_edge('admin.example.test', cert='admin-ca', source='127.0.0.2')[0] in (400, 401, 403)


def test_real_nginx_optional_acl_rejects_valid_cert_from_unlisted_ip(unified_edge):
    assert unified_edge('admin.example.test', cert='admin-ca')[0] == 200
    assert unified_edge('admin.example.test', cert='admin-ca', source='127.0.0.2',
                        headers={'X-Forwarded-For': '127.0.0.1'})[0] == 403
