from __future__ import with_statement
from alembic import context
from sqlalchemy import create_engine, pool

import os.path
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import settings

from distributed.db import db
target_metadata = db.metadata

config = context.config

def run_migrations():
    engine = create_engine(settings.SQLALCHEMY_DATABASE_URI,
                           poolclass=pool.NullPool)

    connection = engine.connect()
    context.configure(connection=connection, target_metadata=target_metadata)

    try:
        with context.begin_transaction():
            context.run_migrations()
    finally:
        connection.close()

run_migrations()
