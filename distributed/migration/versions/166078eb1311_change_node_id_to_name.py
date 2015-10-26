"""change node-id to name

Revision ID: 166078eb1311
Revises: 3d1d8fd2cdbb
Create Date: 2015-06-27 09:59:43.366796

"""

revision = "166078eb1311"
down_revision = "3d1d8fd2cdbb"
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa

def upgrade():
    op.add_column("node_status", sa.Column("name", sa.Text(), nullable=True))

    # Convert all .node_id's to .name's.
    op.execute("UPDATE node_status SET name = node.name FROM node WHERE node.id = node_status.node_id")

    op.drop_constraint("node_status_node_id_fkey", "node_status", type_="foreignkey")
    op.drop_column("node_status", "node_id")

    # Add the "assigned" value to the task status type. The "if not exists"
    # part seems to be a PostgreSQL 9.3+ feature, but that should be fine.
    op.execute("COMMIT")
    op.execute("ALTER TYPE task_status_type ADD VALUE IF NOT EXISTS 'assigned' AFTER 'pending'")

def downgrade():
    # There's not really a need for proper downgrade support, so we're just
    # going to ignore this. The complexity involved with removing a value from
    # an enum doesn't really make it worth the effort.
    pass
