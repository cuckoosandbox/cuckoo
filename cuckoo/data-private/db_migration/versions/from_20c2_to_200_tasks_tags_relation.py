# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""tasks tags relation

Revision ID: 5aa718cc79e1
Revises: af16beb71aa7
Create Date: 2017-02-07 00:37:15.017423

"""

# Revision identifiers, used by Alembic.
revision = "5aa718cc79e1"
down_revision = "af16beb71aa7"

from alembic import op
import sqlalchemy as sa

def upgrade():
    op.create_table(
        "tasks_tags",
        sa.Column("task_id", sa.Integer(), nullable=True),
        sa.Column("tag_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["tag_id"], ["tags.id"]),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"])
    )

def downgrade():
    pass
