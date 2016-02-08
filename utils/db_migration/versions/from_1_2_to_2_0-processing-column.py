# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""processing column

Revision ID: 4a04f40d4ab4
Revises: 3aa42d870199
Create Date: 2015-11-15 00:57:32.068872

"""

# revision identifiers, used by Alembic.
revision = "4a04f40d4ab4"
down_revision = "3aa42d870199"

from alembic import op
import sqlalchemy as sa

def upgrade():
    op.add_column("tasks", sa.Column("processing", sa.String(length=16), nullable=True))

def downgrade():
    op.drop_column("tasks", "processing")
