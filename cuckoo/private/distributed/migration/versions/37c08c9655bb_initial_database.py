"""initial database

Revision ID: 37c08c9655bb
Revises:
Create Date: 2015-03-30 16:55:03.404293

"""

revision = "37c08c9655bb"
down_revision = None
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa

def upgrade():
    op.create_table(
        "node",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name")
    )
    op.create_table(
        "machine",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("platform", sa.Text(), nullable=False),
        sa.Column("tags", sa.Text(), nullable=True),
        sa.Column("node_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["node_id"], ["node.id"]),
        sa.PrimaryKeyConstraint("id")
    )
    op.create_table(
        "task",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("path", sa.Text(), nullable=True),
        sa.Column("filename", sa.Text(), nullable=True),
        sa.Column("package", sa.Text(), nullable=True),
        sa.Column("timeout", sa.Integer(), nullable=True),
        sa.Column("priority", sa.Integer(), nullable=True),
        sa.Column("options", sa.Text(), nullable=True),
        sa.Column("machine", sa.Text(), nullable=True),
        sa.Column("platform", sa.Text(), nullable=True),
        sa.Column("tags", sa.Text(), nullable=True),
        sa.Column("custom", sa.Text(), nullable=True),
        sa.Column("owner", sa.Text(), nullable=True),
        sa.Column("memory", sa.Text(), nullable=True),
        sa.Column("clock", sa.Integer(), nullable=True),
        sa.Column("enforce_timeout", sa.Text(), nullable=True),
        sa.Column("node_id", sa.Integer(), nullable=True),
        sa.Column("task_id", sa.Integer(), nullable=True),
        sa.Column("finished", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["node_id"], ["node.id"]),
        sa.PrimaryKeyConstraint("id")
    )

def downgrade():
    op.drop_table("task")
    op.drop_table("machine")
    op.drop_table("node")
