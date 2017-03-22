"""node status timestamp index

Revision ID: 151400d38e03
Revises: 4d0a2590e997
Create Date: 2015-07-15 15:53:56.016839

"""

revision = "151400d38e03"
down_revision = "4d0a2590e997"
branch_labels = None
depends_on = None

from alembic import op

def upgrade():
    op.create_index("ix_node_status_timestamp", "node_status", ["timestamp"], unique=False)

def downgrade():
    op.drop_index("ix_node_status_timestamp", table_name="node_status")
