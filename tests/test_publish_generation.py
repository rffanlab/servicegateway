from conftest import SPEC, register, save_route, publish


def test_same_snapshot_reload_failure_is_not_reported_success(signed):
    c,_,agent=signed
    register(c);save_route(c);first=publish(c)
    agent.fail_apply=True
    preview=c.post('/api/gateway/preview').json()
    response=c.post('/api/gateway/publish',json={'revision':preview['revision'],'digest':preview['digest']})
    assert response.status_code == 502,response.text
    current=c.get('/api/overview').json()
    assert current['active_release']['id']==first['id']
    assert current['pending_release'] is None
    assert agent.generation == first['id']


def test_repeated_import_stays_unchanged(signed):
    c,_,_=signed
    register(c)
    result=c.post('/api/import/e5',json={'services':[SPEC]}).json()
    assert result['unchanged']==['demo']
    assert result['conflicts']==[]
