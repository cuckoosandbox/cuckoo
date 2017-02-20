# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""tasks-submit-relation (from Cuckoo 2.0-rc2 to 2.0.0)

Revision ID: ef1ecf216392
Revises: a1c8aab9598e
Create Date: 2017-02-20 21:51:42.014175

"""

# Revision identifiers, used by Alembic.
revision = "ef1ecf216392"
down_revision = "a1c8aab9598e"

from alembic import op
import sqlalchemy as sa

def upgrade():
    op.add_column(
        "tasks", sa.Column("submit_id", sa.Integer(), nullable=True)
    )
    op.create_index(
        op.f("ix_tasks_submit_id"), "tasks", ["submit_id"], unique=False
    )
    if op.get_bind().engine.driver != "pysqlite":
        op.create_foreign_key(None, "tasks", "submit", ["submit_id"], ["id"])

def downgrade():
    pass
