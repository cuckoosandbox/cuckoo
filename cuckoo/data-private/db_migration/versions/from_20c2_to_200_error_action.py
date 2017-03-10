# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""action element for error (from Cuckoo 2.0-rc2 to 2.0.0)

Revision ID: 181be2111077
Revises: ef1ecf216392
Create Date: 2017-02-23 15:11:39.711902

"""

# Revision identifiers, used by Alembic.
revision = "181be2111077"
down_revision = "ef1ecf216392"

from alembic import op
import sqlalchemy as sa

def upgrade():
    op.add_column(
        "errors", sa.Column("action", sa.String(length=64), nullable=True)
    )

def downgrade():
    pass
