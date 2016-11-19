# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""Cast Machine.resultserver_port to int (from Cuckoo 2.0-rc2 to 2.0.0)

Revision ID: 1f28e0e5aa6b
Revises: None

"""

# Revision identifiers, used by Alembic.
revision = "1f28e0e5aa6b"
down_revision = "cd31654d187"

import dateutil.parser
import logging
import sqlalchemy as sa
from alembic import op

import cuckoo.core.database as db

log = logging.getLogger(__name__)

machine_columns = (
    "id", "name", "label", "ip", "platform", "options", "interface",
    "snapshot", "locked", "locked_changed_on", "status", "status_changed_on",
    "resultserver_ip", "resultserver_port",
)

def upgrade():
    conn = op.get_bind()

    if conn.engine.driver == "psycopg2" or conn.engine.driver == "mysqldb":
        machines = conn.execute(
            "SELECT id, resultserver_port FROM machines"
        ).fetchall()

        op.drop_column("machines", "resultserver_port")
        op.add_column("machines", sa.Column("resultserver_port", sa.Integer()))

        for id_, resultserver_port in machines:
            if resultserver_port.isdigit():
                resultserver_port = int(resultserver_port)
            else:
                resultserver_port = 2042
                log.critical(
                    "Error parsing resultserver port (%s)! "
                    "Defaulting to 2042.", resultserver_port
                )

            op.execute(
                "UPDATE machines SET resultserver_port = %d WHERE id = %d" %
                (resultserver_port, id_)
            )
    elif conn.engine.driver == "pysqlite":
        old_machines = conn.execute(
            "SELECT %s FROM machines" % ",".join(machine_columns)
        ).fetchall()

        machines = []
        for machine in old_machines:
            machines.append(dict(zip(machine_columns, machine)))

            if machines[-1]["locked_changed_on"]:
                machines[-1]["locked_changed_on"] = dateutil.parser.parse(
                    machines[-1]["locked_changed_on"]
                )
            if machines[-1]["status_changed_on"]:
                machines[-1]["status_changed_on"] = dateutil.parser.parse(
                    machines[-1]["status_changed_on"]
                )

        op.rename_table("machines", "old_machines")
        op.drop_table("old_machines")
        op.create_table(
            "machines",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("label", sa.String(255), nullable=False),
            sa.Column("ip", sa.String(255), nullable=False),
            sa.Column("platform", sa.String(255), nullable=False),
            sa.Column("options", sa.String(255), nullable=True),
            sa.Column("interface", sa.String(255), nullable=True),
            sa.Column("snapshot", sa.String(255), nullable=True),
            sa.Column("locked", sa.Boolean(), nullable=False, default=False),
            sa.Column("locked_changed_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("status", sa.String(255), nullable=True),
            sa.Column("status_changed_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("resultserver_ip", sa.String(255), nullable=False),
            sa.Column("resultserver_port", sa.Integer(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.bulk_insert(db.Machine.__table__, machines)

def downgrade():
    pass
