"""Store API keys encrypted for admin recovery/copy."""
from alembic import op
import sqlalchemy as sa

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('api_keys', sa.Column('token_ciphertext', sa.Text(), nullable=True))


def downgrade():
    raise RuntimeError('Destructive security downgrade disabled')
