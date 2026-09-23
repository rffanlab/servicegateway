"""Business users, WeChat identities and opaque service sessions."""
from alembic import op
import sqlalchemy as sa

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('api_keys', sa.Column('user_service_ids', sa.JSON(), nullable=True))
    op.create_table(
        'business_users',
        sa.Column('id', sa.String(length=32), primary_key=True),
        sa.Column('service_id', sa.String(length=64), sa.ForeignKey('services.id', ondelete='CASCADE'), nullable=False),
        sa.Column('role', sa.String(length=32), nullable=False, server_default='user'),
        sa.Column('display_name', sa.String(length=100), nullable=False, server_default=''),
        sa.Column('remark', sa.String(length=300), nullable=False, server_default=''),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_login_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_business_users_service_id', 'business_users', ['service_id'])
    op.create_index('ix_business_users_service_enabled', 'business_users', ['service_id', 'enabled'])

    op.create_table(
        'wechat_identities',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('user_id', sa.String(length=32), sa.ForeignKey('business_users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('service_id', sa.String(length=64), sa.ForeignKey('services.id', ondelete='CASCADE'), nullable=False),
        sa.Column('appid', sa.String(length=32), nullable=False),
        sa.Column('openid', sa.String(length=128), nullable=False),
        sa.Column('unionid', sa.String(length=128), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_login_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('service_id', 'appid', 'openid', name='uq_wechat_identity_service_app_openid'),
    )
    op.create_index('ix_wechat_identities_user_id', 'wechat_identities', ['user_id'])
    op.create_index('ix_wechat_identities_service_id', 'wechat_identities', ['service_id'])

    op.create_table(
        'business_sessions',
        sa.Column('token_hash', sa.String(length=64), primary_key=True),
        sa.Column('user_id', sa.String(length=32), sa.ForeignKey('business_users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('service_id', sa.String(length=64), sa.ForeignKey('services.id', ondelete='CASCADE'), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_business_sessions_user_id', 'business_sessions', ['user_id'])
    op.create_index('ix_business_sessions_service_expires', 'business_sessions', ['service_id', 'expires_at'])


def downgrade():
    raise RuntimeError('Destructive security downgrade disabled')
