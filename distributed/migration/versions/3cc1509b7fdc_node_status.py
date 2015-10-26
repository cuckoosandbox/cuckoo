"""node status

Revision ID: 3cc1509b7fdc
Revises: 37c08c9655bb
Create Date: 2015-03-30 17:14:39.604125

"""

revision = "3cc1509b7fdc"
down_revision = "37c08c9655bb"
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa

def upgrade():
    op.create_table(
        "node_status",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("node_id", sa.Integer(), nullable=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["node_id"], ["node.id"]),
        sa.PrimaryKeyConstraint("id")
    )

def downgrade():
    op.drop_table("node_status")
