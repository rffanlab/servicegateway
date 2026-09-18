from copy import deepcopy
import pytest
from servicegateway import agent as mod
from servicegateway.config import Settings
from conftest import POLICY, SPEC


def test_lifecycle_dependency_order_and_disable_is_not_stop(monkeypatch):
    policy=deepcopy(POLICY)
    spec={**SPEC,'services':['one.service','two.service','three.service']}
    policy['services']['demo']['units']=spec['services']
    calls=[]
    monkeypatch.setattr(mod,'load_policy',lambda _:policy)
    monkeypatch.setattr(mod,'unit_info',lambda unit:{'unit':unit,'active':'active','startup':'enabled','pid':1})
    monkeypatch.setattr(mod,'command',lambda args,**kw:calls.append(args) or '')
    broker=mod.Broker(Settings(testing=True,_env_file=None))
    broker.dispatch({'action':'service','spec':spec,'operation':'restart'})
    assert [c[1:] for c in calls]==[['stop','three.service'],['stop','two.service'],['stop','one.service'],['start','one.service'],['start','two.service'],['start','three.service']]
    calls.clear()
    broker.dispatch({'action':'service','spec':spec,'operation':'disable'})
    assert all('stop' not in c for c in calls)
    assert [c[-2] for c in calls if c[0] == '/usr/bin/busctl'] == ['one.service','two.service','three.service']
    assert all(c[5] == 'DisableUnitFiles' for c in calls if c[0] == '/usr/bin/busctl')


def test_no_shell_or_arbitrary_agent_requests():
    broker=mod.Broker(Settings(testing=True,_env_file=None))
    for request in [{'action':'shell','command':'id'}, {'action':'status','path':'/etc/passwd'}]:
        with pytest.raises(ValueError):broker.dispatch(request)


@pytest.mark.parametrize('unit',['ssh.service','mysql.service','servicegateway.service','nginx.service'])
def test_protected_services_never_reach_systemctl(monkeypatch,unit):
    monkeypatch.setattr(mod,'command',lambda *_:pytest.fail('Must reject before executing'))
    with pytest.raises(ValueError):mod.unit_info(unit)
