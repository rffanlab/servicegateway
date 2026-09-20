#!/usr/bin/env python3
"""Real MySQL 8.0/8.4 provisioning and denied-operation tests on disposable CI only.

Use the Docker service's network namespace so TCP 127.0.0.1 really reaches
MySQL as a local client. Admin uses its actual UNIX socket through /proc.
No weakening of the production account Host or connector is needed.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--container')
    parser.add_argument('--inner-socket')
    args = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('This destructive isolated smoke test only runs as root in GitHub Actions')
    if args.container:
        if not re.fullmatch(r'[a-f0-9]{12,64}', args.container):
            raise SystemExit('Invalid CI container ID')
        pid = subprocess.check_output(['docker', 'inspect', '--format', '{{.State.Pid}}', args.container], text=True).strip()
        if not pid.isdigit() or int(pid) <= 1:
            raise SystemExit('Invalid CI MySQL PID')
        socket = f'/proc/{pid}/root/var/run/mysqld/mysqld.sock'
        subprocess.run(['nsenter', '--target', pid, '--net', sys.executable, __file__, '--inner-socket', socket], check=True)
        return
    if not args.inner_socket or not re.fullmatch(r'/proc/[0-9]+/root/var/run/mysqld/mysqld.sock', args.inner_socket):
        raise SystemExit('Use --container with the current CI MySQL service only')
    import pymysql
    from servicegateway import business_databases as d
    from servicegateway import agent
    from servicegateway.database_cli import write_new_private

    # A fixed, disposable CI password; never reads production connection variables.
    ci_password = 'ci-only-password'
    admin = pymysql.connect(unix_socket=args.inner_socket, user='root', password=ci_password,
                            charset='utf8mb4', autocommit=True)
    with admin.cursor() as cur:
        cur.execute("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='servicegateway_test'")
        if cur.fetchone() is None:
            raise SystemExit('Disposable servicegateway_test marker missing; no DDL executed')
        cur.execute('SELECT VERSION(), @@global.partial_revokes')
        version, old_partial = cur.fetchone()
    work = Path(tempfile.mkdtemp(prefix='sg-database-ci-', dir='/run'))
    d.CONFIG, d.STORE, d.SOCKET = work/'database-admin.json', work/'records', args.inner_socket
    (work/'policy.json').write_text('{}\n')
    (work/'policy.json').chmod(0o600)
    # Target service installation is already covered separately by unit/Agent tests.
    # This fixture supplies only that approved-unit check; ALL SQL uses production code.
    agent.unit_info = lambda unit: {'unit':unit, 'active':'inactive'}
    original_prompt = d.getpass.getpass
    d.getpass.getpass = lambda _: ci_password
    cleaned_schemas, cleaned_users, checks = [], [], []
    original_connect = d.connect_admin
    clients = []

    def passed(label):
        checks.append(label)
        print('PASS:', label, flush=True)

    def denied(cursor, statement, args=()):
        try:
            cursor.execute(statement, args)
        except pymysql.MySQLError as exc:
            assert exc.args[0] in (1044, 1142, 1143, 1227, 1410), f'Unexpected error code {exc.args[0]}'
        else:
            raise AssertionError('Forbidden operation unexpectedly succeeded')

    def reserve(sid, schema):
        with admin.cursor() as cur:
            cur.execute('SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s', (schema,))
            assert cur.fetchone() is None
            users = d.names(sid)
            cur.execute('SELECT User FROM mysql.user WHERE User IN (%s,%s)', tuple(users.values()))
            assert cur.fetchone() is None
        cleaned_schemas.append(schema)
        cleaned_users.extend((u, '127.0.0.1') for u in users.values())
        return {'services': {sid: {'units':['ci-demo.service'], 'upstreams':['127.0.0.1:18088'], 'health_url':'http://127.0.0.1:18088/healthz'}}}

    try:
        d.enable(ask_password=True)
        assert d.status()['enabled']
        passed('production UNIX-socket administrator connection and explicit enable')
        for partial in (0, 1):
            with admin.cursor() as cur:
                cur.execute('SET GLOBAL partial_revokes=%s', (partial,))
            sid = 'ci-db-' + uuid.uuid4().hex[:12]
            schema = 'sgb_ci_' + uuid.uuid4().hex[:12]
            sibling = schema.replace('_', 'x')  # Would match unescaped GRANT underscores.
            unknown = 'sgb_ci_' + uuid.uuid4().hex[:12]
            policy = reserve(sid, schema)
            for name in (sibling, unknown):
                with admin.cursor() as cur:
                    cur.execute('SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s', (name,))
                    assert cur.fetchone() is None
                cleaned_schemas.append(name)
            with admin.cursor() as cur:
                cur.execute(f'CREATE DATABASE `{sibling}`')
                cur.execute(f'CREATE TABLE `{sibling}`.sentinel (id INT)')
            spec = {'service_id':sid, 'database_name':schema}
            result = d.create(spec, policy)
            assert result['changed'] and result['status'] == 'ready'
            assert d.create(spec, policy)['changed'] is False
            record = d.read(d.record_path(sid))
            assert record['passwords']['runtime'] != record['passwords']['migration']
            sessions = {}
            for account in ('runtime', 'migration'):
                credentials = d.credentials(sid, account)
                conn = pymysql.connect(host='127.0.0.1', port=3306, user=credentials['username'],
                                       password=credentials['password'], database=schema, autocommit=True)
                sessions[account] = conn; clients.append(conn)
                with conn.cursor() as cur:
                    cur.execute('SELECT CURRENT_USER()')
                    assert cur.fetchone()[0] == credentials['username'] + '@127.0.0.1'
            with sessions['migration'].cursor() as cur:
                cur.execute('CREATE TABLE work (id INT PRIMARY KEY, value INT)')
                cur.execute('ALTER TABLE work ADD COLUMN note VARCHAR(10)')
                cur.execute('CREATE VIEW work_view AS SELECT id FROM work')
                cur.execute('DROP VIEW work_view')
            with sessions['runtime'].cursor() as cur:
                cur.execute('INSERT INTO work (id,value) VALUES (1,2)')
                cur.execute('UPDATE work SET value=3 WHERE id=1')
                cur.execute('SELECT value FROM work WHERE id=1')
                assert cur.fetchone() == (3,)
                cur.execute('DELETE FROM work WHERE id=1')
                denied(cur, 'CREATE TABLE forbidden (id INT)')
                denied(cur, 'DROP TABLE work')
                denied(cur, 'GRANT SELECT ON ' + d.grant_target(schema, bool(partial)) + ' TO %s@%s',
                       (record['accounts']['migration'], '127.0.0.1'))
            for conn in sessions.values():
                with conn.cursor() as cur:
                    denied(cur, f'SELECT * FROM `{sibling}`.sentinel')
                    denied(cur, 'SELECT User FROM mysql.user')
                    denied(cur, f'CREATE DATABASE `{unknown}`')
                    denied(cur, f'DROP DATABASE `{sibling}`')
            passed(f'partial_revokes={partial}: real account login, DML/DDL separation and cross-schema/GRANT denial')
            output = d.env_file(d.credentials(sid, 'runtime'))
            exported = write_new_private(work/(sid+'.env'), output)
            assert exported.stat().st_mode & 0o777 == 0o600
            assert d.record_path(sid).stat().st_mode & 0o777 == 0o600
            for path in (exported, d.record_path(sid), d.CONFIG):
                assert subprocess.run(['runuser','-u','nobody','--','test','-r',str(path)],capture_output=True).returncode != 0
            assert all(p not in json.dumps(d.status()) for p in record['passwords'].values())
            # Close clients before switching global privilege interpretation.
            for conn in sessions.values(): conn.close(); clients.remove(conn)
        passed('private credential export and metadata contain no passwords')
        with admin.cursor() as cur:
            cur.execute('SET GLOBAL partial_revokes=0')
        sid = 'ci-fail-' + uuid.uuid4().hex[:12]
        schema = 'sgb_ci_' + uuid.uuid4().hex[:12]
        policy = reserve(sid, schema)
        spec = {'service_id':sid, 'database_name':schema}
        class FailCursor:
            def __init__(self, cur): self.cur = cur
            def __enter__(self): self.cur.__enter__(); return self
            def __exit__(self,*args): return self.cur.__exit__(*args)
            def __getattr__(self, name): return getattr(self.cur, name)
            def execute(self, sql, args=()):
                if sql.startswith('GRANT '): raise RuntimeError('injected pre-GRANT interruption')
                return self.cur.execute(sql,args)
        class FailConnection:
            def __init__(self, conn): self.conn = conn
            def cursor(self): return FailCursor(self.conn.cursor())
            def close(self): return self.conn.close()
        d.connect_admin = lambda config: FailConnection(original_connect(config))
        try: d.create(spec, policy)
        except d.ProvisionError: pass
        else: raise AssertionError('Injected failure was hidden')
        d.connect_admin = original_connect
        record = d.read(d.record_path(sid))
        assert record['status'] == 'needs_review'
        with admin.cursor() as cur:
            cur.execute('SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s',(schema,))
            assert cur.fetchone() == (schema,)
            cur.execute('SELECT account_locked FROM mysql.user WHERE User=%s',(record['accounts']['runtime'],))
            assert cur.fetchone() == ('Y',)
        try: d.create(spec, policy)
        except d.ProvisionError: pass
        else: raise AssertionError('Interrupted DDL was replayed')
        passed('partial real DDL retained, created user locked, blind retry blocked')
        sid2 = 'ci-collision-' + uuid.uuid4().hex[:12]
        collision = 'sgb_ci_' + uuid.uuid4().hex[:12]
        policy2 = reserve(sid2, collision)
        with admin.cursor() as cur:
            cur.execute(f'CREATE DATABASE `{collision}`')
            cur.execute(f'CREATE TABLE `{collision}`.sentinel (id INT)')
        try: d.create({'service_id':sid2,'database_name':collision}, policy2)
        except d.ProvisionError: pass
        else: raise AssertionError('Existing unrelated database was taken over')
        with admin.cursor() as cur:
            cur.execute(f'SELECT * FROM `{collision}`.sentinel')
        passed('existing database refusal without destructive cleanup')
        evidence = {'mysql_version':version, 'checks':checks, 'result':'passed',
                    'scope':'ephemeral CI MySQL; target-host services and backup recovery not executed'}
        (ROOT/'database-mysql-evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
    finally:
        d.connect_admin = original_connect
        d.getpass.getpass = original_prompt
        for conn in clients: conn.close()
        with admin.cursor() as cur:
            for user, host in cleaned_users:
                cur.execute('DROP USER IF EXISTS %s@%s',(user,host))
            for name in cleaned_schemas:
                cur.execute(f'DROP DATABASE IF EXISTS `{name}`')
            cur.execute('SET GLOBAL partial_revokes=%s',(old_partial,))
        admin.close()
        shutil.rmtree(work)


if __name__ == '__main__':
    main()
