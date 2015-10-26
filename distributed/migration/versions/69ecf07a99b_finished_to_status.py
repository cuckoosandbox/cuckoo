"""finished to status

Revision ID: 69ecf07a99b
Revises: 3cc1509b7fdc
Create Date: 2015-04-03 09:35:47.523157

"""

revision = "69ecf07a99b"
down_revision = "3cc1509b7fdc"
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa

def upgrade():
    op.add_column("task", sa.Column("status", sa.Enum("pending", "processing", "finished", "deleted", name="task_status_type"), server_default="pending", nullable=False))

    op.execute("update task set status = 'pending' where finished = false and node_id is null")
    op.execute("update task set status = 'processing' where finished = false and node_id is not null")
    op.execute("update task set status = 'finished' where finished = true")

    op.drop_column("task", "finished")

def downgrade():
    op.add_column("task", sa.Column("finished", sa.BOOLEAN(), autoincrement=False))

    op.execute("update task set finished = true where status = 'finished'")
    op.execute("update task set finished = false where status in ('pending', 'processing')")
    op.execute("delete from task where status = 'deleted'")

    op.alter_column("task", "finished", nullable=False)

    op.drop_column("task", "status")
