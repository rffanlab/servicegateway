"""Service-scoped business users, WeChat identities and opaque access tokens."""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "business_users",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("service_id", sa.String(64), sa.ForeignKey("services.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("display_name", sa.String(100), nullable=False),
        sa.Column("avatar_url", sa.String(500), nullable=False),
        sa.Column("remark", sa.String(300), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_business_users_service_id", "business_users", ["service_id"])
    op.create_index("ix_business_users_created_at", "business_users", ["created_at"])

    op.create_table(
        "wechat_identities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("service_id", sa.String(64), sa.ForeignKey("services.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.String(32), sa.ForeignKey("business_users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("appid", sa.String(64), nullable=False),
        sa.Column("openid", sa.String(128), nullable=False),
        sa.Column("unionid", sa.String(128), nullable=True),
        sa.UniqueConstraint("service_id", "appid", "openid", name="uq_wechat_service_app_openid"),
    )
    op.create_index("ix_wechat_identities_service_id", "wechat_identities", ["service_id"])
    op.create_index("ix_wechat_identities_user_id", "wechat_identities", ["user_id"])

    op.create_table(
        "business_access_tokens",
        sa.Column("token_hash", sa.String(64), primary_key=True),
        sa.Column("service_id", sa.String(64), sa.ForeignKey("services.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.String(32), sa.ForeignKey("business_users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_business_access_tokens_service_id", "business_access_tokens", ["service_id"])
    op.create_index("ix_business_access_tokens_user_id", "business_access_tokens", ["user_id"])
    op.create_index("ix_business_access_tokens_expires_at", "business_access_tokens", ["expires_at"])


def downgrade():
    raise RuntimeError("Destructive business-user downgrade disabled; restore a verified MySQL backup instead.")
