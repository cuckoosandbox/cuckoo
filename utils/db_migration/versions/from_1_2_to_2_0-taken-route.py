# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""taken route

Revision ID: 1070cd314621
Revises: 4a04f40d4ab4
Create Date: 2015-11-21 23:10:04.724813

"""

# revision identifiers, used by Alembic.
revision = "1070cd314621"
down_revision = "4a04f40d4ab4"

from alembic import op
import sqlalchemy as sa

def upgrade():
    op.add_column("tasks", sa.Column("route", sa.String(length=16), nullable=True))

def downgrade():
    op.drop_column("tasks", "route")
