"""timestamps

Revision ID: 3d1d8fd2cdbb
Revises: 69ecf07a99b
Create Date: 2015-06-03 22:55:51.357575

"""

revision = "3d1d8fd2cdbb"
down_revision = "69ecf07a99b"
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa

def upgrade():
    op.add_column("task", sa.Column("submitted", sa.DateTime(), nullable=True))
    op.add_column("task", sa.Column("delegated", sa.DateTime(), nullable=True))
    op.add_column("task", sa.Column("started", sa.DateTime(), nullable=True))
    op.add_column("task", sa.Column("completed", sa.DateTime(), nullable=True))

def downgrade():
    op.drop_column("task", "submitted")
    op.drop_column("task", "started")
    op.drop_column("task", "delegated")
    op.drop_column("task", "completed")
