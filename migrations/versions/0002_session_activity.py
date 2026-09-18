"""Server-side idle expiry and recent-authentication tracking."""
from alembic import op
import sqlalchemy as sa

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade():
    # Existing sessions receive a null timestamp and fail closed (login required).
    op.add_column('login_sessions', sa.Column('last_seen_at', sa.DateTime(), nullable=True))
    op.add_column('login_sessions', sa.Column('reauthenticated_at', sa.DateTime(), nullable=True))


def downgrade():
    raise RuntimeError('Destructive security downgrade disabled')
