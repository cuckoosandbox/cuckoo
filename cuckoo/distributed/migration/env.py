from alembic import context
from sqlalchemy import create_engine, pool

from cuckoo.distributed.db import db
from cuckoo.distributed.misc import settings

config = context.config

def run_migrations():
    engine = create_engine(settings.SQLALCHEMY_DATABASE_URI,
                           poolclass=pool.NullPool)

    connection = engine.connect()
    context.configure(connection=connection, target_metadata=db.metadata)

    try:
        with context.begin_transaction():
            context.run_migrations()
    finally:
        connection.close()

run_migrations()
