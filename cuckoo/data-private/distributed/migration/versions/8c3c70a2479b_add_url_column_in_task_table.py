"""add url column in task table

Revision ID: 8c3c70a2479b
Revises: 4b86bc0d40aa
Create Date: 2017-07-04 15:44:27.698132

"""

revision = '8c3c70a2479b'
down_revision = '4b86bc0d40aa'
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column("task", sa.Column("url", sa.Text(), nullable=True))

def downgrade():
    op.drop_column("task", "url")