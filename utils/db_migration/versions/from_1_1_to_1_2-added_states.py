# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""Database migration from Cuckoo 1.1 to Cuckoo 1.2.
Added failed statuses to tasks.

Revision ID: 495d5a6edef3
Revises: 18eee46c6f81
Create Date: 2015-02-28 19:08:29.284111

"""
# Spaghetti as a way of life.

# Revision identifiers, used by Alembic.
revision = "495d5a6edef3"
down_revision = "18eee46c6f81"

import os.path
import sqlalchemy as sa
import sys
from datetime import datetime

try:
    from dateutil.parser import parse
except ImportError:
    print "Unable to import dateutil.parser",
    print "(install with `pip install python-dateutil`)"
    sys.exit()

try:
    from alembic import op
except ImportError:
    print "Unable to import alembic (install with `pip install alembic`)"
    sys.exit()

curdir = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(curdir, "..", ".."))

import lib.cuckoo.core.database as db

def _perform(upgrade):
    conn = op.get_bind()

    # Deal with Alembic shit.
    # Alembic is so ORMish that it was impossible to write code which works on different DBMS.
    if conn.engine.driver == "psycopg2":
        # Altering status ENUM.
        # This shit of raw SQL is here because alembic doesn't deal well with alter_colum of ENUM type.
        # Commit because SQLAlchemy doesn't support ALTER TYPE in a transaction.
        op.execute('COMMIT')
        if upgrade:
            conn.execute("ALTER TYPE status_type ADD VALUE 'failed_reporting'")
        else:
            conn.execute("ALTER TYPE status_type DROP ATTRIBUTE IF EXISTS failed_reporting")
    else:
        # Read data.
        tasks_data = []
        old_tasks = conn.execute("select id, target, category, timeout, priority, custom, machine, package, options, platform, memory, enforce_timeout, clock, added_on, started_on, completed_on, status, sample_id from tasks").fetchall()
        for item in old_tasks:
            d = {}
            d["id"] = item[0]
            d["target"] = item[1]
            d["category"] = item[2]
            d["timeout"] = item[3]
            d["priority"] = item[4]
            d["custom"] = item[5]
            d["machine"] = item[6]
            d["package"] = item[7]
            d["options"] = item[8]
            d["platform"] = item[9]
            d["memory"] = item[10]
            d["enforce_timeout"] = item[11]

            if isinstance(item[12], datetime):
                d["clock"] = item[12]
            elif item[12]:
                d["clock"] = parse(item[12])
            else:
                d["clock"] = None

            if isinstance(item[13], datetime):
                d["added_on"] = item[13]
            elif item[13]:
                d["added_on"] = parse(item[13])
            else:
                d["added_on"] = None

            if isinstance(item[14], datetime):
                d["started_on"] = item[14]
            elif item[14]:
                d["started_on"] = parse(item[14])
            else:
                d["started_on"] = None

            if isinstance(item[15], datetime):
                d["completed_on"] = item[15]
            elif item[15]:
                d["completed_on"] = parse(item[15])
            else:
                d["completed_on"] = None

            d["status"] = item[16]
            d["sample_id"] = item[17]

            tasks_data.append(d)
        if conn.engine.driver == "mysqldb":
            # Disable foreign key checking to migrate table avoiding checks.
            op.execute('SET foreign_key_checks = 0')

            # Drop old table.
            op.drop_table("tasks")

            # Drop old Enum.
            sa.Enum(name="status_type").drop(op.get_bind(), checkfirst=False)
            # Create table with 1.2 schema.
            if upgrade:
                op.create_table(
                    "tasks",
                    sa.Column("id", sa.Integer(), nullable=False),
                    sa.Column("target", sa.String(length=255), nullable=False),
                    sa.Column("category", sa.String(length=255), nullable=False),
                    sa.Column("timeout", sa.Integer(), server_default="0", nullable=False),
                    sa.Column("priority", sa.Integer(), server_default="1", nullable=False),
                    sa.Column("custom", sa.String(length=255), nullable=True),
                    sa.Column("machine", sa.String(length=255), nullable=True),
                    sa.Column("package", sa.String(length=255), nullable=True),
                    sa.Column("options", sa.String(length=255), nullable=True),
                    sa.Column("platform", sa.String(length=255), nullable=True),
                    sa.Column("memory", sa.Boolean(), nullable=False, default=False),
                    sa.Column("enforce_timeout", sa.Boolean(), nullable=False, default=False),
                    sa.Column("clock", sa.DateTime(timezone=False), default=datetime.now, nullable=False),
                    sa.Column("added_on", sa.DateTime(timezone=False), nullable=False),
                    sa.Column("started_on", sa.DateTime(timezone=False), nullable=True),
                    sa.Column("completed_on", sa.DateTime(timezone=False), nullable=True),
                    sa.Column("status", sa.Enum("pending", "running", "completed", "reported", "recovered", "failed_analysis", "failed_processing", "failed_reporting", name="status_type"), server_default="pending", nullable=False),
                    sa.Column("sample_id", sa.Integer, sa.ForeignKey("samples.id"), nullable=True),
                    sa.PrimaryKeyConstraint("id")
                )
            else:
                op.create_table(
                    "tasks",
                    sa.Column("id", sa.Integer(), nullable=False),
                    sa.Column("target", sa.String(length=255), nullable=False),
                    sa.Column("category", sa.String(length=255), nullable=False),
                    sa.Column("timeout", sa.Integer(), server_default="0", nullable=False),
                    sa.Column("priority", sa.Integer(), server_default="1", nullable=False),
                    sa.Column("custom", sa.String(length=255), nullable=True),
                    sa.Column("machine", sa.String(length=255), nullable=True),
                    sa.Column("package", sa.String(length=255), nullable=True),
                    sa.Column("options", sa.String(length=255), nullable=True),
                    sa.Column("platform", sa.String(length=255), nullable=True),
                    sa.Column("memory", sa.Boolean(), nullable=False, default=False),
                    sa.Column("enforce_timeout", sa.Boolean(), nullable=False, default=False),
                    sa.Column("clock", sa.DateTime(timezone=False), default=datetime.now, nullable=False),
                    sa.Column("added_on", sa.DateTime(timezone=False), nullable=False),
                    sa.Column("started_on", sa.DateTime(timezone=False), nullable=True),
                    sa.Column("completed_on", sa.DateTime(timezone=False), nullable=True),
                    sa.Column("status", sa.Enum("pending", "running", "completed", "reported", "recovered", "failed_analysis", "failed_processing", name="status_type"), server_default="pending", nullable=False),
                    sa.Column("sample_id", sa.Integer, sa.ForeignKey("samples.id"), nullable=True),
                    sa.PrimaryKeyConstraint("id")
                )
            op.execute('COMMIT')

            # Insert data.
            op.bulk_insert(db.Task.__table__, tasks_data)
            # Enable foreign key.
            op.execute('SET foreign_key_checks = 1')

        else:
            op.drop_table("tasks")

            # Create table with 1.2 schema.
            if upgrade:
                op.create_table(
                    "tasks",
                    sa.Column("id", sa.Integer(), nullable=False),
                    sa.Column("target", sa.String(length=255), nullable=False),
                    sa.Column("category", sa.String(length=255), nullable=False),
                    sa.Column("timeout", sa.Integer(), server_default="0", nullable=False),
                    sa.Column("priority", sa.Integer(), server_default="1", nullable=False),
                    sa.Column("custom", sa.String(length=255), nullable=True),
                    sa.Column("machine", sa.String(length=255), nullable=True),
                    sa.Column("package", sa.String(length=255), nullable=True),
                    sa.Column("options", sa.String(length=255), nullable=True),
                    sa.Column("platform", sa.String(length=255), nullable=True),
                    sa.Column("memory", sa.Boolean(), nullable=False, default=False),
                    sa.Column("enforce_timeout", sa.Boolean(), nullable=False, default=False),
                    sa.Column("clock", sa.DateTime(timezone=False), default=datetime.now, nullable=False),
                    sa.Column("added_on", sa.DateTime(timezone=False), nullable=False),
                    sa.Column("started_on", sa.DateTime(timezone=False), nullable=True),
                    sa.Column("completed_on", sa.DateTime(timezone=False), nullable=True),
                    sa.Column("status", sa.Enum("pending", "running", "completed", "reported", "recovered", "failed_analysis", "failed_processing", "failed_reporting", name="status_type"), server_default="pending", nullable=False),
                    sa.Column("sample_id", sa.Integer, sa.ForeignKey("samples.id"), nullable=True),
                    sa.PrimaryKeyConstraint("id")
                )
            else:
                op.create_table(
                    "tasks",
                    sa.Column("id", sa.Integer(), nullable=False),
                    sa.Column("target", sa.String(length=255), nullable=False),
                    sa.Column("category", sa.String(length=255), nullable=False),
                    sa.Column("timeout", sa.Integer(), server_default="0", nullable=False),
                    sa.Column("priority", sa.Integer(), server_default="1", nullable=False),
                    sa.Column("custom", sa.String(length=255), nullable=True),
                    sa.Column("machine", sa.String(length=255), nullable=True),
                    sa.Column("package", sa.String(length=255), nullable=True),
                    sa.Column("options", sa.String(length=255), nullable=True),
                    sa.Column("platform", sa.String(length=255), nullable=True),
                    sa.Column("memory", sa.Boolean(), nullable=False, default=False),
                    sa.Column("enforce_timeout", sa.Boolean(), nullable=False, default=False),
                    sa.Column("clock", sa.DateTime(timezone=False), default=datetime.now, nullable=False),
                    sa.Column("added_on", sa.DateTime(timezone=False), nullable=False),
                    sa.Column("started_on", sa.DateTime(timezone=False), nullable=True),
                    sa.Column("completed_on", sa.DateTime(timezone=False), nullable=True),
                    sa.Column("status", sa.Enum("pending", "running", "completed", "reported", "recovered", "failed_analysis", "failed_processing", name="status_type"), server_default="pending", nullable=False),
                    sa.Column("sample_id", sa.Integer, sa.ForeignKey("samples.id"), nullable=True),
                    sa.PrimaryKeyConstraint("id")
                )

            # Insert data.
            op.bulk_insert(db.Task.__table__, tasks_data)

def upgrade():
    _perform(upgrade=True)

def downgrade():
    _perform(upgrade=False)
