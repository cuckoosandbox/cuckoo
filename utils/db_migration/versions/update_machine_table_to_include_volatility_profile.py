# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""update machine table to include volatility profile

Revision ID: 37d61512fbf7
Revises: 495d5a6edef3
Create Date: 2015-05-20 10:01:54.097856

"""

# revision identifiers, used by Alembic.
revision = '37d61512fbf7'
down_revision = '495d5a6edef3'

from alembic import op
import os.path
import sqlalchemy as sa
import sys

curdir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(curdir, "..", ".."))

import lib.cuckoo.core.database as db

def _perform(upgrade):
    op.add_column('machines', sa.Column('volatility_profile', sa.String(255)))

def upgrade():
    _perform(upgrade=True)

def downgrade():
    _perform(upgrade=False)
