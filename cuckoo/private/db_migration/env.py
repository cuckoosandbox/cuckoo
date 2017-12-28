# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import with_statement

from alembic import context
from sqlalchemy import create_engine, pool
from logging.config import fileConfig

# Interpret the config file for Python logging.
# This line sets up loggers basically.
fileConfig(context.config.config_file_name)

from cuckoo.core.database import Base, Database
from cuckoo.misc import set_cwd

set_cwd(context.get_x_argument(as_dictionary=True)["cwd"])
Database().connect(schema_check=False, create=False)

# Get database connection string from cuckoo configuration.
url = Database().engine.url.__to_string__(hide_password=False)
target_metadata = Base.metadata

def run_migrations_offline():
    """Run migrations in 'offline' mode.
    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.
    Calls to context.execute() here emit the given string to the
    script output.
    """
    context.configure(url=url)

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    """Run migrations in 'online' mode.
    In this scenario we need to create an Engine
    and associate a connection with the context.
    """
    engine = create_engine(url, poolclass=pool.NullPool)

    connection = engine.connect()
    context.configure(connection=connection, target_metadata=target_metadata)

    try:
        with context.begin_transaction():
            context.run_migrations()
    finally:
        connection.close()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
