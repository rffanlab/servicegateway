"""Initial MySQL schema. Immutable schema definition; no runtime create_all."""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("users", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("username", sa.String(64), nullable=False, unique=True), sa.Column("password_hash", sa.String(255), nullable=False), sa.Column("role", sa.String(16), nullable=False), sa.Column("enabled", sa.Boolean(), nullable=False))
    op.create_table("login_sessions", sa.Column("token_hash", sa.String(64), primary_key=True), sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False), sa.Column("csrf", sa.String(64), nullable=False), sa.Column("expires_at", sa.DateTime(), nullable=False))
    op.create_index("ix_login_sessions_user_id", "login_sessions", ["user_id"])
    op.create_index("ix_login_sessions_expires_at", "login_sessions", ["expires_at"])
    op.create_table("api_keys", sa.Column("id", sa.String(32), primary_key=True), sa.Column("name", sa.String(80), nullable=False), sa.Column("token_hash", sa.String(64), nullable=False, unique=True), sa.Column("route_ids", sa.JSON(), nullable=False), sa.Column("service_ids", sa.JSON(), nullable=False), sa.Column("expires_at", sa.DateTime(), nullable=False), sa.Column("revoked", sa.Boolean(), nullable=False))
    op.create_table("services", sa.Column("id", sa.String(64), primary_key=True), sa.Column("spec", sa.JSON(), nullable=False))
    op.create_table("routes", sa.Column("id", sa.String(64), primary_key=True), sa.Column("service_id", sa.String(64), sa.ForeignKey("services.id"), nullable=False), sa.Column("spec", sa.JSON(), nullable=False))
    op.create_index("ix_routes_service_id", "routes", ["service_id"])
    op.create_table("gateway_state", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("revision", sa.Integer(), nullable=False), sa.Column("active_release", sa.String(32)), sa.Column("pending_release", sa.String(32)))
    op.execute(sa.text("INSERT INTO gateway_state (id, revision) VALUES (1, 0)"))
    op.create_table("releases", sa.Column("id", sa.String(32), primary_key=True), sa.Column("digest", sa.String(64), nullable=False), sa.Column("snapshot", sa.JSON(), nullable=False), sa.Column("revision", sa.Integer(), nullable=False), sa.Column("status", sa.String(24), nullable=False), sa.Column("note", sa.String(300), nullable=False), sa.Column("error", sa.Text(), nullable=False), sa.Column("created_at", sa.DateTime(), nullable=False))
    op.create_index("ix_releases_digest", "releases", ["digest"])
    op.create_index("ix_releases_created_at", "releases", ["created_at"])
    op.create_table("audit", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("actor", sa.String(80), nullable=False), sa.Column("action", sa.String(64), nullable=False), sa.Column("target", sa.String(80), nullable=False), sa.Column("outcome", sa.String(24), nullable=False), sa.Column("detail", sa.String(500), nullable=False), sa.Column("created_at", sa.DateTime(), nullable=False))
    op.create_index("ix_audit_created_at", "audit", ["created_at"])
    op.create_table("health", sa.Column("service_id", sa.String(64), primary_key=True), sa.Column("state", sa.String(24), nullable=False), sa.Column("startup", sa.String(24), nullable=False), sa.Column("healthy", sa.Boolean()), sa.Column("latency_ms", sa.Integer()), sa.Column("units", sa.JSON(), nullable=False), sa.Column("checked_at", sa.DateTime(), nullable=False), sa.Column("detail", sa.String(300), nullable=False))


def downgrade():
    raise RuntimeError("Destructive downgrade disabled. Restore a verified MySQL backup instead.")
