"""Read-only, non-root deployment preflight run inside the production sandbox.

No schema creation, migrations, user resets, service operations or network
exposure. The unit receives app.env from PID 1, not by reading it as the user.
"""
import os
from pathlib import Path
import sys


def check():
    if os.geteuid() == 0:
        raise RuntimeError('Runtime verification must run as the non-root service user')
    executable = Path(sys.prefix) / 'bin/uvicorn'
    if not os.access(executable, os.R_OK | os.X_OK):
        raise PermissionError('Runtime entrypoint is not readable/executable')
    # Test the same import search behavior as Uvicorn's default --app-dir="".
    sys.path.insert(0, str(Path.cwd()))
    from .config import Settings
    from .db import GatewayState
    from .main import create_app
    from sqlalchemy import text
    import uvicorn

    settings = Settings()
    settings.auth_secret()  # Must be group-readable, unlike app.env/private keys.
    app = create_app(settings)
    try:
        static = Path(__import__('servicegateway.main', fromlist=['__file__']).__file__).parent / 'static'
        for filename in ('index.html', 'app.js', 'style.css'):
            (static / filename).read_bytes()
        with app.state.sessions() as db:
            db.execute(text('SELECT 1'))
            if db.get(GatewayState, 1) is None:
                raise RuntimeError('Missing migrated gateway state')
    finally:
        app.state.engine.dispose()
    print('Non-root runtime verification passed: executable, imports, static files, auth-secret, MySQL schema')


def main():
    try:
        check()
    except Exception as exc:
        # Database/library exceptions can embed credentials. Never dump their repr.
        print(f'Non-root runtime verification failed: {type(exc).__name__}. '
              'Inspect runtime path permissions, mount options and private deployment diagnostics; '
              'no configuration or credentials printed.', file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
