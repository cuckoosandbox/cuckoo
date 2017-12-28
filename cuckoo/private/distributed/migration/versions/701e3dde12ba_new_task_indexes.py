"""New task indexes

Revision ID: 701e3dde12ba
Revises: 4b86bc0d40aa
Create Date: 2017-10-05 15:11:20.568945

"""

revision = "701e3dde12ba"
down_revision = "4b86bc0d40aa"
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_index(
        "ix_completed_not_null", "task", ["completed"], unique=False,
        postgresql_where=sa.text("completed IS NOT NULL")
    )
    op.create_index(
        "ix_status_ltfinished_submitted", "task",
        ["submitted", "status"], unique=False,
        postgresql_where=sa.text("status < 'finished'")
    )

def downgrade():
    op.drop_index("ix_status_ltfinished_submitted", table_name="task")
    op.drop_index("ix_completed_not_null", table_name="task")
