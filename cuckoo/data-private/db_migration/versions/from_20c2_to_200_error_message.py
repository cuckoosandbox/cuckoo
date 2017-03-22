# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""Extend length of Error.message (from Cuckoo 2.0-rc2 to 2.0.0)

Revision ID: 796174689511
Revises: None

"""

# Revision identifiers, used by Alembic.
revision = "796174689511"
down_revision = "1f28e0e5aa6b"

import logging
import sqlalchemy as sa
from alembic import op

from cuckoo.core.database import Error

log = logging.getLogger(__name__)

def upgrade():
    conn = op.get_bind()

    if conn.engine.driver == "psycopg2":
        conn.execute(
            "ALTER TABLE errors ALTER COLUMN message TYPE text "
            "USING message::text"
        )
    elif conn.engine.driver == "mysqldb":
        conn.execute(
            "ALTER TABLE errors MODIFY message text"
        )
    elif conn.engine.driver == "pysqlite":
        old_errors = conn.execute(
            "SELECT id, message, task_id FROM errors"
        ).fetchall()

        errors = []
        for error in old_errors:
            errors.append(dict(zip(("id", "message", "task_id"), error)))

        op.rename_table("errors", "old_errors")
        op.drop_table("old_errors")
        op.create_table(
            "errors",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("message", sa.Text(), nullable=False),
            sa.Column("task_id", sa.Integer(), sa.ForeignKey("tasks.id"), nullable=False),
        )
        op.bulk_insert(Error.__table__, errors)

def downgrade():
    pass
