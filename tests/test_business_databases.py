import json
import re
import stat
from datetime import timedelta
from pathlib import Path
import pytest
from pydantic import ValidationError
from sqlalchemy import select
from servicegateway import business_databases as d
from servicegateway import agent as agent_module
from servicegateway.db import LoginSession, now
from servicegateway.ipc import AgentError
from conftest import POLICY, PASSWORD, register

SPEC = {'service_id': 'demo', 'database_name': 'sgb_demo'}


class FakeMySQL:
    def __init__(self):
        self.schemas = set()
        self.users = {}
        self.sql = []
        self.failure = None
        self.partial = False
        self.result = []

    def cursor(self): return self
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def close(self): pass
    def fetchall(self): return self.result
    def fetchone(self): return self.result[0] if self.result else None

    def execute(self, sql, args=()):
        self.sql.append((sql, args))
        self.result = []
        if self.failure and sql.startswith(self.failure):
            raise RuntimeError(1234, 'simulated SQL with SECRET-PASSWORD never echo')
        if sql.startswith(('SELECT GET_LOCK', 'SELECT RELEASE_LOCK')): self.result = [(1,)]
        elif sql.startswith('SELECT VERSION'): self.result = [('8.4.1', self.partial, '', 3306)]
        elif 'information_schema.SCHEMATA' in sql: self.result = [(args[0],)] if args[0] in self.schemas else []
        elif sql.startswith('SELECT User, Host'): self.result = [(u, '127.0.0.1') for u in args if u in self.users]
        elif sql.startswith('SELECT User FROM mysql.db'): pass
        elif sql.startswith('CREATE DATABASE'): self.schemas.add(sql.split('`')[1])
        elif sql.startswith('CREATE USER'): self.users[args[0]] = {'password': args[2], 'locked': True, 'grants': []}
        elif sql.startswith('GRANT '): self.users[args[0]]['grants'].append(sql.rsplit(' TO ', 1)[0] + f" TO `{args[0]}`@`127.0.0.1`")
        elif sql.startswith('SHOW GRANTS'): self.result = [('GRANT USAGE ON *.* TO `user`@`127.0.0.1`',)] + [(g,) for g in self.users[args[0]]['grants']]
        elif sql.startswith('ALTER USER'): self.users[args[0]]['locked'] = sql.endswith('ACCOUNT LOCK')
        else: raise AssertionError(sql)


@pytest.fixture
def provision(tmp_path, monkeypatch):
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({'username': 'root', 'password': '', 'enabled': True}))
    config.chmod(0o600)
    monkeypatch.setattr(d, 'CONFIG', config)
    monkeypatch.setattr(d, 'STORE', tmp_path / 'records')
    # Tests own only this temporary namespace, not production /etc paths.
    def private_file(path):
        path = Path(path)
        assert path.is_relative_to(tmp_path)
        assert not path.is_symlink() and stat.S_IMODE(path.stat().st_mode) == 0o600
        return path
    def private_dir(path):
        assert path.is_relative_to(tmp_path) and not path.is_symlink()
        path.mkdir(mode=0o700, exist_ok=True)
    monkeypatch.setattr(d, 'private_file', private_file)
    monkeypatch.setattr(d, 'private_directory', private_dir)
    monkeypatch.setattr(agent_module, 'unit_info', lambda unit: {'unit': unit})
    connection = FakeMySQL()
    monkeypatch.setattr(d, 'connect_admin', lambda config: connection)
    return connection


@pytest.mark.parametrize('name', ['mysql','servicegateway','sys','information_schema','performance_schema','sgb_%','sgb_x`; DROP DATABASE mysql;--','sgb_测试','sgb_X','sgb_a\n','sgb_'+'a'*60])
def test_forbid_system_names_and_sql_input(name):
    with pytest.raises(ValidationError): d.DatabaseRequest(service_id='demo', database_name=name)


@pytest.mark.parametrize('mode', [True, False])
def test_schema_grant_escape(mode):
    assert d.grant_target('sgb_a_b', mode) == ('`sgb_a_b`.*' if mode else '`sgb\\_a\\_b`.*')


def test_create_runtime_and_migration_are_isolated_and_idempotent(provision):
    first = d.create(SPEC, POLICY)
    assert first['changed'] and first['status'] == 'ready'
    record = d.read(d.record_path('demo'))
    assert len(set(record['passwords'].values())) == 2
    assert all(len(x) >= 43 for x in record['passwords'].values())
    assert all(not x['locked'] for x in provision.users.values())
    assert 'CREATE' not in d.RUNTIME and 'DROP' in d.MIGRATION
    before = len(provision.sql)
    again = d.create(SPEC, POLICY)
    assert not again['changed']
    assert all(sql.startswith(('SELECT', 'SHOW')) for sql, _ in provision.sql[before:])
    metadata = json.dumps(d.status())
    assert all(p not in metadata for p in record['passwords'].values())
    for account in ('runtime', 'migration'):
        data = d.credentials('demo', account)
        assert data['password'] == record['passwords'][account]
        assert data['host'] == '127.0.0.1'
        assert '%21@127.0.0.1' in d.env_file(data)
    assert not any(' ON *.* TO ' in sql or sql.startswith('DROP ') for sql, _ in provision.sql)


def test_disabled_does_not_contact_mysql(provision):
    d.save(d.CONFIG, {'enabled': False})
    assert not d.status()['enabled']
    with pytest.raises(d.ProvisionError): d.create(SPEC, POLICY)
    assert provision.sql == []


def test_unapproved_service_rejected_before_mysql(provision):
    with pytest.raises(d.ProvisionError): d.create(SPEC, {'services': {}})
    assert provision.sql == []


@pytest.mark.parametrize('collision', ['database', 'user'])
def test_existing_resources_not_taken_over(provision, collision):
    if collision == 'database': provision.schemas.add('sgb_demo')
    else: provision.users[d.names('demo')['runtime']] = {'password': 'EXISTING'}
    with pytest.raises(d.ProvisionError): d.create(SPEC, POLICY)
    assert all(sql.startswith(('SELECT', 'SHOW')) for sql, _ in provision.sql)
    assert not d.record_path('demo').exists()


def test_ddl_failure_never_drops_or_blindly_retries(provision):
    provision.failure = 'GRANT '
    with pytest.raises(d.ProvisionError) as error: d.create(SPEC, POLICY)
    assert 'SECRET-PASSWORD' not in str(error.value)
    assert provision.schemas == {'sgb_demo'}
    assert all(u['locked'] for u in provision.users.values())
    record = d.read(d.record_path('demo'))
    assert record['status'] == 'needs_review'
    assert not any(sql.startswith('DROP') for sql, _ in provision.sql)
    before = len(provision.sql)
    with pytest.raises(d.ProvisionError): d.create(SPEC, POLICY)
    assert len(provision.sql) == before
    with pytest.raises(d.ProvisionError): d.credentials('demo','runtime')


def test_changed_root_approval_or_db_name_not_overwritten(provision):
    d.create(SPEC, POLICY)
    from copy import deepcopy
    changed = deepcopy(POLICY)
    changed['services']['demo']['upstreams'].append('127.0.0.1:18189')
    with pytest.raises(d.ProvisionError): d.create(SPEC, changed)
    with pytest.raises(d.ProvisionError): d.create({**SPEC, 'database_name':'sgb_other'}, POLICY)


def test_drifted_grants_block_repeat_without_regrant(provision):
    d.create(SPEC, POLICY)
    user = provision.users[d.names('demo')['runtime']]
    user['grants'].append('GRANT CREATE ON *.* TO `x`@`127.0.0.1`')
    start = len(provision.sql)
    with pytest.raises(d.ProvisionError): d.create(SPEC, POLICY)
    assert all(sql.startswith(('SELECT', 'SHOW')) for sql, _ in provision.sql[start:])


def test_bad_credential_paths_never_read_other_file(provision):
    for sid in ('../app.env', '/etc/passwd', 'a/b'):
        with pytest.raises(d.ProvisionError): d.credentials(sid, 'runtime')
    with pytest.raises(d.ProvisionError): d.credentials('demo', 'root')


def test_store_lock_is_exclusive(provision):
    with d.store_lock():
        with pytest.raises(d.ProvisionError):
            with d.store_lock(): pass


def test_private_directory_refuses_writable_ancestors(tmp_path):
    with pytest.raises(d.ProvisionError): d.private_directory(tmp_path/'blocked')
    assert not (tmp_path/'blocked').exists()


def test_cli_denies_unprivileged_users(monkeypatch):
    from servicegateway import database_cli as cli
    from types import SimpleNamespace
    monkeypatch.setattr(cli.os, 'geteuid', lambda: 1000)
    with pytest.raises(d.ProvisionError): cli.run(SimpleNamespace(command='database-enable'))


@pytest.fixture
def api_database(signed, monkeypatch):
    c, app, agent = signed
    register(c)
    old = agent.call
    calls = []
    def call(action, **payload):
        if action.startswith('database-'):
            calls.append((action, payload))
            if action == 'database-status': return {'enabled': True, 'items': []}
            if action == 'database-create': return {'changed': True, 'status': 'ready', **payload['spec']}
            if action == 'database-credentials': return {'database':'sgb_demo','username':'sgb_test_r','password':'Db-Secret-aA7!', **payload}
        return old(action, **payload)
    monkeypatch.setattr(agent, 'call', call)
    return c, app, agent, calls


def test_api_create_recent_auth_scope_and_audit(api_database):
    c, app, _, calls = api_database
    assert c.get('/api/databases').status_code == 200
    assert c.post('/api/databases', json=SPEC).status_code == 200
    with app.state.sessions.begin() as db:
        db.scalar(select(LoginSession)).reauthenticated_at = now() - timedelta(minutes=10)
    count = len(calls)
    assert c.post('/api/databases', json=SPEC).status_code == 428
    assert len(calls) == count
    assert c.post('/api/auth/reauth', json={'password': PASSWORD}).status_code == 200
    assert c.post('/api/databases', json={**SPEC, 'service_id':'unregistered'}).status_code == 409
    assert c.post('/api/databases', json={**SPEC, 'sql':'arbitrary sql'}).status_code == 422
    assert any(a['action']=='database.create' for a in c.get('/api/audit').json())


def test_credentials_need_password_csrf_and_never_list_secrets(api_database):
    c, _, _, calls = api_database
    url = '/api/databases/demo/credentials'
    assert c.post(url,json={'current_password':'wrong'}).status_code == 403
    assert not any(a == 'database-credentials' for a,_ in calls)
    result = c.post(url,json={'current_password':PASSWORD,'account':'runtime'})
    assert result.status_code == 200
    assert 'Db-Secret-aA7!' in result.text and 'no-store' in result.headers['cache-control']
    assert 'attachment;' in result.headers['content-disposition']
    assert 'Db-Secret' not in c.get('/api/databases').text
    assert 'Db-Secret' not in c.get('/api/audit').text and PASSWORD not in c.get('/api/audit').text
    del c.headers['X-CSRF-Token']
    assert c.post(url,json={'current_password':PASSWORD}).status_code == 403


@pytest.mark.parametrize('role', ['operator', 'viewer'])
def test_non_admin_cannot_create_or_download(api_database, role):
    c, _, _, calls = api_database
    assert c.post('/api/users',json={'username':'ordinary','role':role,'password':PASSWORD}).status_code == 200
    c.post('/api/auth/logout')
    login = c.post('/api/auth/login',json={'username':'ordinary','password':PASSWORD}).json()
    c.headers['X-CSRF-Token'] = login['csrf']
    count = len(calls)
    assert c.get('/api/databases').status_code == 403
    assert c.post('/api/databases',json=SPEC).status_code == 403
    assert c.post('/api/databases/demo/credentials',json={'current_password':PASSWORD}).status_code == 403
    assert len(calls) == count


def test_registration_key_is_not_a_database_admin(api_database):
    c, _, _, calls = api_database
    key=c.post('/api/keys',json={'name':'register','service_ids':['demo']}).json()['token']
    c.cookies.clear(); c.headers['X-Gateway-Key'] = key
    assert c.post('/api/databases',json=SPEC).status_code == 401
    assert c.get('/api/databases').status_code == 401


def test_agent_accepts_structured_operations_only(provision, monkeypatch):
    from servicegateway.config import Settings
    monkeypatch.setattr(agent_module, 'load_policy', lambda _: POLICY)
    broker=agent_module.Broker(Settings(testing=True,_env_file=None))
    assert broker.dispatch({'action':'database-create','spec':SPEC})['status'] == 'ready'
    assert broker.dispatch({'action':'database-status'})['items'][0]['database_name'] == 'sgb_demo'
    for req in ({'action':'database-create','spec':SPEC,'sql':'SELECT 1'}, {'action':'database-enable'}, {'action':'database-drop'}, {'action':'database-credentials','service_id':'demo','account':'root'}):
        with pytest.raises(ValueError): broker.dispatch(req)


def test_database_ui_form_and_escaped_metadata_without_browser():
    import subprocess
    module = (Path(__file__).parents[1] / 'servicegateway/static/database-ui.js').as_uri()
    script = r"""
import assert from 'node:assert/strict';
const {databaseUI} = await import(process.argv[1]);
let editor, submitted;
const esc = v=>String(v??'').replaceAll('<','&lt;').replaceAll('>','&gt;');
const ui = databaseUI({
  api: async (url, method, body)=>{if(method==='POST'){submitted={url,body};return {status:'ready'};}return {enabled:true,items:[],notice:'<unsafe>'};},
  edit: (...args)=>{editor=args;}, field:(name)=>`[${name}]`, table:()=>'', badge:()=>'', button:()=>'', empty:(...v)=>v.join(' '),esc,
  getOverview:()=>({assets:[{id:'demo',name:'Demo'}]}),getUser:()=>({csrf:'test'}),showLogin:()=>{}
});
const html=await ui.render(); assert(!html.includes('<unsafe>'));assert(html.includes('&lt;unsafe&gt;'));
assert(await ui.perform('database-new','demo'));
assert(editor[1].includes('[database_name]'));assert(editor[1].includes('[service_id]'));
await editor[2](new Map([['service_id','demo'],['database_name','sgb_demo']]));
assert.deepEqual(submitted,{url:'/api/databases',body:{service_id:'demo',database_name:'sgb_demo'}});
assert.equal(await ui.perform('unrelated','demo'),false);
assert(await ui.perform('database-download','demo'));
assert(editor[1].includes('[current_password]')&&editor[1].includes('[account]'));
"""
    result = subprocess.run(['node','--input-type=module','-e',script,module], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
