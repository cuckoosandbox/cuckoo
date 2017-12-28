# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""submit table (from Cuckoo 2.0-rc2 to 2.0.0)

Revision ID: af16beb71aa7
Revises: 4384097916c2
Create Date: 2017-02-07 00:29:30.030173

"""

# Revision identifiers, used by Alembic.
revision = "af16beb71aa7"
down_revision = "796174689511"

from alembic import op
import sqlalchemy as sa

def upgrade():
    op.create_table(
        "submit",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tmp_path", sa.Text(), nullable=True),
        sa.Column("added", sa.DateTime(), nullable=False),
        sa.Column("submit_type", sa.String(length=16), nullable=True),
        sa.Column("data", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id")
    )

def downgrade():
    pass
