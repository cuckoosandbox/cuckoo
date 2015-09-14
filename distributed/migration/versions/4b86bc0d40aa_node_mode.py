"""node mode

Revision ID: 4b86bc0d40aa
Revises: 2aa59981b59d
Create Date: 2015-09-09 00:04:56.119968

"""

revision = "4b86bc0d40aa"
down_revision = "2aa59981b59d"
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa

def upgrade():
    op.add_column("node", sa.Column("mode", sa.Text()))
    op.execute("update node set mode = 'normal'")
    op.alter_column("node", "mode", nullable=False)

def downgrade():
    op.drop_column("node", "mode")
