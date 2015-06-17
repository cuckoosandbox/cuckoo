from __future__ import with_statement
from alembic import context
from sqlalchemy import create_engine, pool

import ConfigParser
import os.path
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from distributed.db import db
target_metadata = db.metadata

config = context.config

s = ConfigParser.ConfigParser()
s.read(config.get_main_option("distributed_config"))
url = s.get("distributed", "database")

def run_migrations():
    engine = create_engine(url, poolclass=pool.NullPool)

    connection = engine.connect()
    context.configure(connection=connection, target_metadata=target_metadata)

    try:
        with context.begin_transaction():
            context.run_migrations()
    finally:
        connection.close()

run_migrations()
