# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""Extend Task.options and Task.custom (from Cuckoo 2.0-rc2 to 2.0.0)

Revision ID: a1c8aab9598e
Revises: af16beb71aa7
Create Date: 2017-02-18 16:38:02.092102

"""

# Revision identifiers, used by Alembic.
revision = "a1c8aab9598e"
down_revision = "af16beb71aa7"

import datetime
import dateutil.parser

from alembic import op
import sqlalchemy as sa

from cuckoo.core.database import Task

TASK_PENDING = "pending"
TASK_RUNNING = "running"
TASK_COMPLETED = "completed"
TASK_RECOVERED = "recovered"
TASK_REPORTED = "reported"
TASK_FAILED_ANALYSIS = "failed_analysis"
TASK_FAILED_PROCESSING = "failed_processing"
TASK_FAILED_REPORTING = "failed_reporting"

status_type = sa.Enum(
    TASK_PENDING, TASK_RUNNING, TASK_COMPLETED, TASK_REPORTED, TASK_RECOVERED,
    TASK_FAILED_ANALYSIS, TASK_FAILED_PROCESSING, TASK_FAILED_REPORTING,
    name="status_type"
)

columns = (
    "id", "target", "category", "timeout", "priority", "custom", "owner",
    "machine", "package", "options", "platform", "memory", "enforce_timeout",
    "clock", "added_on", "started_on", "completed_on", "status", "sample_id",
    "processing", "route"
)

def parse_dates(obj, *fields):
    for field in fields:
        if obj[field]:
            obj[field] = dateutil.parser.parse(obj[field])

def upgrade():
    conn = op.get_bind()

    if conn.engine.driver == "psycopg2":
        conn.execute(
            "ALTER TABLE tasks ALTER COLUMN options TYPE text "
            "USING options::text"
        )
        conn.execute(
            "ALTER TABLE tasks ALTER COLUMN custom TYPE text "
            "USING custom::text"
        )
    elif conn.engine.driver == "mysqldb":
        conn.execute(
            "ALTER TABLE tasks MODIFY options text"
        )
        conn.execute(
            "ALTER TABLE tasks MODIFY custom text"
        )
    elif conn.engine.driver == "pysqlite":
        old_tasks = conn.execute(
            "SELECT %s FROM tasks" % ", ".join(columns)
        ).fetchall()

        tasks = []
        for task in old_tasks:
            tasks.append(dict(zip(columns, task)))
            parse_dates(
                tasks[-1], "clock", "added_on", "started_on", "completed_on"
            )

        op.rename_table("tasks", "old_tasks")
        op.drop_table("old_tasks")
        op.create_table(
            "tasks",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("target", sa.Text(), nullable=False),
            sa.Column("category", sa.String(255), nullable=False),
            sa.Column(
                "timeout", sa.Integer(), server_default="0", nullable=False
            ),
            sa.Column(
                "priority", sa.Integer(), server_default="1", nullable=False
            ),
            sa.Column("custom", sa.Text(), nullable=True),
            sa.Column("owner", sa.String(64), nullable=True),
            sa.Column("machine", sa.String(255), nullable=True),
            sa.Column("package", sa.String(255), nullable=True),
            sa.Column("options", sa.Text(), nullable=True),
            sa.Column("platform", sa.String(255), nullable=True),
            sa.Column("memory", sa.Boolean, nullable=False, default=False),
            sa.Column(
                "enforce_timeout", sa.Boolean, nullable=False, default=False
            ),
            sa.Column(
                "clock", sa.DateTime(timezone=False),
                default=datetime.datetime.now, nullable=False
            ),
            sa.Column(
                "added_on", sa.DateTime(timezone=False),
                default=datetime.datetime.now, nullable=False
            ),
            sa.Column(
                "started_on", sa.DateTime(timezone=False), nullable=True
            ),
            sa.Column(
                "completed_on", sa.DateTime(timezone=False), nullable=True
            ),
            sa.Column(
                "status", status_type, server_default=TASK_PENDING,
                nullable=False
            ),
            sa.Column(
                "sample_id", sa.Integer, sa.ForeignKey("samples.id"),
                nullable=True
            ),
            sa.Column("processing", sa.String(16), nullable=True),
            sa.Column("route", sa.String(16), nullable=True)
        )

        op.bulk_insert(Task.__table__, tasks)

def downgrade():
    pass
