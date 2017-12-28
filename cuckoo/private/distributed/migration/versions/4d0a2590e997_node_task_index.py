"""node task index

Revision ID: 4d0a2590e997
Revises: 166078eb1311
Create Date: 2015-06-30 15:46:11.780052

"""

revision = "4d0a2590e997"
down_revision = "166078eb1311"
branch_labels = None
depends_on = None

from alembic import op

def upgrade():
    op.create_index("ix_node_task", "task", ["node_id", "task_id"], unique=True)

def downgrade():
    op.drop_index("ix_node_task", table_name="task")
