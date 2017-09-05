# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""Experiment (from Cuckoo 2.0.4 to 2.0.5)

Revision ID: f37a6c6dde99
Revises: 181be2111077
Create Date: 2017-8-28

"""

# Revision identifiers, used by Alembic.
revision = "f37a6c6dde99"
down_revision = "181be2111077"

from alembic import op

import datetime
import dateutil.parser
import logging
import sqlalchemy as sa

from cuckoo.core.database import Task

log = logging.getLogger(__name__)

TASK_PENDING = "pending"
TASK_RUNNING = "running"
TASK_COMPLETED = "completed"
TASK_RECOVERED = "recovered"
TASK_REPORTED = "reported"
TASK_FAILED_ANALYSIS = "failed_analysis"
TASK_FAILED_PROCESSING = "failed_processing"
TASK_FAILED_REPORTING = "failed_reporting"

columns = (
    "id", "target", "category", "timeout", "priority", "custom", "owner",
    "machine", "package", "options", "platform", "memory", "enforce_timeout",
    "clock", "added_on", "started_on", "completed_on", "status", "sample_id",
    "submit_id", "processing", "route"
)

status_type = sa.Enum(
    TASK_PENDING, TASK_RUNNING, TASK_COMPLETED, TASK_REPORTED, TASK_RECOVERED,
    TASK_FAILED_ANALYSIS, TASK_FAILED_PROCESSING, TASK_FAILED_REPORTING,
    name="status_type"
)


def parse_dates(obj, *fields):
    for field in fields:
        if obj[field]:
            obj[field] = dateutil.parser.parse(obj[field])

def upgrade():
    conn = op.get_bind()

    # Try to select from experiments to determine if the table
    # already exists. If it does not, an exception is raised.
    try:
        conn.execute("SELECT 1 FROM experiments").fetchone()
        log.warning("The \'experiments\' table already exists."
                    " Skipping creation of this table")
    except (sa.exc.OperationalError, sa.exc.ProgrammingError):

        op.create_table(
            "experiments",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(length=255),
                      nullable=True, unique=True),
            sa.Column("added_on", sa.DateTime(), nullable=False,
                      default=datetime.datetime.now),
            sa.Column("delta", sa.String(length=255),
                      nullable=False, default="0s"),
            sa.Column("runs", sa.Integer(), nullable=False),
            sa.Column("times", sa.Integer(), nullable=False),
            sa.Column("machine_name", sa.String(length=255), nullable=True),
            sa.Column("last_completed", sa.Integer(), nullable=True),
            sa.PrimaryKeyConstraint("id")
        )

    op.add_column(
        "machines",
        sa.Column("locked_by", sa.Integer(), nullable=True, default=None)
    )
    op.add_column(
        "machines",
        sa.Column("rdp_port", sa.String(length=5), nullable=True)
    )

    # If engine is Python sqlite, retrieve contents of tasks, drop table
    # and recreate it with new column. Constraints in Sqlite cannot be altered.
    # In this case, experiment_id is added as a new column.
    if conn.engine.driver != "pysqlite":

        op.add_column(
            "tasks", sa.Column("experiment_id", sa.Integer,
                               sa.ForeignKey("experiment.id"), nullable=True)
        )

    else:
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
            sa.Column("experiment_id", sa.Integer,
                      sa.ForeignKey("experiment.id"), nullable=True),
            sa.Column("processing", sa.String(16), nullable=True),
            sa.Column("submit_id", sa.Integer, sa.ForeignKey("submit.id"),
                      nullable=True, index=True),
            sa.Column("route", sa.String(16), nullable=True)
        )

        op.bulk_insert(Task.__table__, tasks)

def downgrade():
    pass
