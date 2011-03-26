"""Database migration from Cuckoo 0.6 to Cuckoo 1.1.

Revision ID: 263a45963c72
Revises: None
Create Date: 2014-03-23 23:30:36.756792

"""

# Revision identifiers, used by Alembic.
revision = "263a45963c72"
down_revision = None

import sqlalchemy as sa
from alembic import op

import sys
sys.path.append("../..")

import lib.cuckoo.core.database as db
from lib.cuckoo.core.database import Base

def upgrade():
    # BEWARE: be prepared to really spaghetti code. To deal with SQLite limitations in Alembic we coded some workarounds.

    # Create secondary table used in association Machine - Tag.
    op.create_table(
        "machines_tags",
        sa.Column("machine_id", sa.Integer, sa.ForeignKey("machines.id")),
        sa.Column("tag_id", sa.Integer, sa.ForeignKey("tags.id")),
    )

    # Add columns to Machine.
    op.add_column("machines", sa.Column("interface", sa.String(length=255), nullable=True))
    op.add_column("machines", sa.Column("snapshot", sa.String(length=255), nullable=True))
    # TODO: change default value, be aware sqlite doesn't support that kind of ALTER statement.
    op.add_column("machines", sa.Column("resultserver_ip", sa.String(length=255), server_default="192.168.56.1", nullable=False))
    # TODO: change default value, be aware sqlite doesn't support that kind of ALTER statement.
    op.add_column("machines", sa.Column("resultserver_port", sa.String(length=255), server_default="2042", nullable=False))

    # Create table used by Tag.
    op.create_table(
        "tags",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False, unique=True),
    )
    # Add columns to Task.
    # We don"t provide a default value and leave the column as nullable because o further data migration.
    op.add_column("tasks", sa.Column("clock", sa.DateTime(timezone=False),nullable=True))

    # Edit task status enumeration in Task.
    # NOTE: To workaround limitations in SQLite we have to create a temporary table, create the new schema and copy data.
    db_mgr = db.Database()
    # Read data.
    tasks_data = []
    for item in db_mgr.Session().query(db.Task).all():
        d = {}
        for column in db.Task.__table__.columns:
            d[column.name] = item.__getattribute__(column.name)
        # Force clock. 
        # NOTE: We added this new column so we force clock time to the added_on for old analyses.
        d["clock"] = d["added_on"]
        # Enum migration, "success" isn"t a valid state now.
        if d["status"] == "success":
            d["status"] = db.TASK_COMPLETED
        tasks_data.append(d)

    # Rename original table.
    op.rename_table("tasks", "old_tasks")
    # Create new table with 1.0 schema.
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
        sa.Column("clock", sa.DateTime(timezone=False), server_default=sa.func.now(), nullable=False),
        sa.Column("added_on", sa.DateTime(timezone=False), nullable=False),
        sa.Column("started_on", sa.DateTime(timezone=False), nullable=True),
        sa.Column("completed_on", sa.DateTime(timezone=False), nullable=True),
        sa.Column("status", sa.Enum(db.TASK_PENDING, db.TASK_RUNNING, db.TASK_COMPLETED, db.TASK_REPORTED, db.TASK_RECOVERED, name="status_type"), server_default=db.TASK_PENDING, nullable=False),
        sa.Column("sample_id", sa.Integer, sa.ForeignKey("samples.id"), nullable=True),
        sa.PrimaryKeyConstraint("id")
    )

    # Insert data.
    op.bulk_insert(db.Task.__table__, tasks_data)
    # Drop old table.
    op.drop_table("old_tasks")

def downgrade():
    # We don"t support downgrade.
    pass
