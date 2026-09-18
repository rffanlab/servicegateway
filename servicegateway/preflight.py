"""No network mutations. Refuse unsafe remote settings before any schema migration."""
import argparse
from urllib.parse import urlsplit
from pathlib import Path
import subprocess
from sqlalchemy.engine import make_url
from .config import Settings
from .agent import load_policy, root_file


def check(settings, policy):
    if settings.testing:
        raise ValueError('Production install cannot use SG_TESTING')
    db = make_url(settings.database_url)
    if db.database != 'servicegateway':
        raise ValueError('Use a separate servicegateway database; never the old Manager schema')
    if db.host not in ('127.0.0.1', 'localhost'):
        raise ValueError('Default deployment requires local MySQL; remote DB TLS needs a separate reviewed setup')
    if settings.deployment_mode == 'remote':
        host = urlsplit(settings.public_origin).hostname
        if host.endswith('.invalid') or policy.get('management_host') != host:
            raise ValueError('Configure the same real management hostname in SG_PUBLIC_ORIGIN and policy.json')
        if not policy.get('remote_mode', True):
            raise ValueError('Remote application cannot run with a LAN root policy')
    return True


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--migrate', action='store_true')
    args = p.parse_args()
    settings = Settings()
    root_file('/etc/servicegateway/app.env')
    check(settings, load_policy(settings))
    print('Deployment settings validated; no secrets printed')
    if args.migrate:
        executable = Path(__import__('sys').executable).with_name('alembic')
        subprocess.run([str(executable), 'upgrade', 'head'], check=True)


if __name__ == '__main__':
    main()
