"""Public application factory composing the control plane and business modules.

The existing control-plane factory remains in core_app unchanged; tests and
systemd keep using servicegateway.main:create_app.
"""
from .core_app import LoginBody, ReauthBody, UserBody, ImportBody  # compatibility exports
from .core_app import audit, state_lock, snapshot, release_view
from .core_app import create_app as core_create_app
from .database_api import routes as database_routes
from .business_users import routes as business_user_routes
from .security import LoginLimiter


def create_app(settings=None, agent=None):
    app = core_create_app(settings, agent)
    app.include_router(database_routes(app.state.sessions, app.state.agent, LoginLimiter()))
    app.include_router(business_user_routes(app.state.sessions, app.state.agent, LoginLimiter(), app.state.settings))
    return app
