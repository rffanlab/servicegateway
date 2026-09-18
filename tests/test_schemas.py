import pytest
from pydantic import ValidationError
from servicegateway.agent import validate_snapshot
from servicegateway.config import Settings
from servicegateway.schemas import ServiceSpec, RouteSpec, Snapshot
from conftest import POLICY, SPEC, route


@pytest.mark.parametrize('units', [['../x.service'], ['a.service;whoami'], ['x@a.service'], ['*.service'], ['a.service','a.service']])
def test_unit_input_is_not_a_command(units):
    with pytest.raises(ValidationError):
        ServiceSpec(**{**SPEC, 'services':units})


@pytest.mark.parametrize('path', ['/foo', '/a/../b/', '/_sg/x/', '/a;return 200;/', '/%2f/', '//evil/', '/x\n/'])
def test_nginx_path_injection_rejected(path):
    with pytest.raises(ValidationError):
        RouteSpec(**route(path=path))


@pytest.mark.parametrize('address', ['localhost', 'metadata.google.internal', '127.0.0.1;include /etc/passwd;', '127.1'])
def test_only_explicit_ipv4_targets(address):
    with pytest.raises(ValidationError):
        RouteSpec(**route(upstreams=[{'address':address,'port':18188}]))


def test_production_is_mysql_only():
    with pytest.raises(ValidationError):
        Settings(database_url='sqlite:///bad.db', testing=False, _env_file=None)
    assert Settings(database_url='sqlite:///test.db', testing=True, _env_file=None).testing


def test_duplicate_route_conflict():
    first = RouteSpec(**route())
    second = first.model_copy(update={'id':'another-route'})
    with pytest.raises(ValidationError):
        Snapshot(services=[ServiceSpec(**SPEC)], routes=[first, second])


def test_policy_restricts_port_upstream_public_and_cidr():
    for change in [dict(listen_port=19333), dict(upstreams=[{'address':'169.254.169.254','port':8080}]), dict(auth='public'), dict(allow_cidrs=['0.0.0.0/0'])]:
        s = Snapshot(services=[ServiceSpec(**SPEC)],routes=[RouteSpec(**route(**change))])
        with pytest.raises(ValueError):
            validate_snapshot(s, POLICY, inspect_units=False)


def test_tls_listener_consistency():
    with pytest.raises(ValidationError):
        Snapshot(services=[ServiceSpec(**SPEC)], routes=[RouteSpec(**route(certificate='cert-one')),RouteSpec(**route(id='other',host='example.test',certificate='cert-two'))])


def test_digest_stable_and_sensitive():
    a = Snapshot(services=[ServiceSpec(**SPEC)],routes=[RouteSpec(**route())])
    b = Snapshot.model_validate_json(a.model_dump_json())
    assert a.digest() == b.digest()
    b.routes[0].auth = 'api_key'
    assert a.digest() != b.digest()
