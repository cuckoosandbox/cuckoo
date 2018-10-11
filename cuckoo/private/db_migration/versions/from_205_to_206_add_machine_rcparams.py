# Copyright (C) 2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""add rcparams field to machine (from Cuckoo 2.0.5 to 2.0.6)

Revision ID: cb1024e614b7
Revises: 181be2111077
Create Date: 2018-02-05 11:09:15.947809

"""

# Revision identifiers, used by Alembic.
revision = "cb1024e614b7"
down_revision = "181be2111077"

from alembic import op
import sqlalchemy as sa

def upgrade():
    op.add_column("machines", sa.Column("rcparams", sa.Text(), nullable=True))

def downgrade():
    pass
