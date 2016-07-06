# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""Database migration from Cuckoo 0.6 to Cuckoo 1.1.
Extend sample's file-type field.

Revision ID: 18eee46c6f81
Revises: 263a45963c72
Create Date: 2014-08-21 12:41:30.863956

"""

# Revision identifiers, used by Alembic.
revision = "18eee46c6f81"
down_revision = "263a45963c72"

from alembic import op
import os.path
import sqlalchemy as sa
import sys

curdir = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(curdir, "..", "..", ".."))

import lib.cuckoo.core.database as db

def _perform(upgrade):
    conn = op.get_bind()

    sample_list = conn.execute("SELECT id, file_size, file_type, md5, crc32, "
                               "sha1, sha256, sha512, ssdeep FROM samples")

    samples = []
    for sample in sample_list:
        samples.append({
            "id": sample[0],
            "file_size": sample[1],
            "file_type": sample[2],
            "md5": sample[3],
            "crc32": sample[4],
            "sha1": sample[5],
            "sha256": sample[6],
            "sha512": sample[7],
            "ssdeep": sample[8],
        })

    # PostgreSQL and MySQL have different names for the foreign key of
    # Task.sample_id -> Sample.id; for SQLite we don't drop/recreate the
    # foreign key.
    fkey_name = {
        "mysql": "tasks_ibfk_1",
        "postgresql": "tasks_sample_id_fkey",
    }

    fkey = fkey_name.get(db.Database(schema_check=False).engine.name)

    # First drop the foreign key.
    if fkey:
        op.drop_constraint(fkey, "tasks", type_="foreignkey")

    # Rename original table.
    op.rename_table("samples", "old_samples")

    # Drop old table.
    op.drop_table("old_samples")

    if upgrade:
        file_type = sa.Text()
    else:
        file_type = sa.String(255)

        # As downgrading implies trimming file_type's to 255 bytes we force
        # this for every available record.
        for sample in samples:
            sample["file_type"] = sample["file_type"][:255]

    # Create the new table with 1.2 schema.
    # Changelog:
    # * file_type changed its type from String(255) to Text().
    op.create_table(
        "samples",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=False),
        sa.Column("file_type", file_type, nullable=False),
        sa.Column("md5", sa.String(32), nullable=False),
        sa.Column("crc32", sa.String(8), nullable=False),
        sa.Column("sha1", sa.String(40), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("sha512", sa.String(128), nullable=False),
        sa.Column("ssdeep", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id")
    )

    # Insert data.
    op.bulk_insert(db.Sample.__table__, samples)

    # Restore the indices.
    op.create_index("hash_index", "samples",
                    ["md5", "crc32", "sha1", "sha256", "sha512"],
                    unique=True)

    # Create the foreign key.
    if fkey:
        op.create_foreign_key(fkey, "tasks", "samples", ["sample_id"], ["id"])

def upgrade():
    _perform(upgrade=True)

def downgrade():
    _perform(upgrade=False)
