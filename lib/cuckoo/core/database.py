# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import json
from datetime import datetime

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooDatabaseError, CuckooOperationalError, CuckooDependencyError
from lib.cuckoo.common.config import Config

try:
    from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Enum
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.sql import func
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.exc import SQLAlchemyError
    Base = declarative_base()
except ImportError:
    raise CuckooDependencyError("SQLAlchemy library not found. Please install it")


class Task(Base):
    """Analysis task queue."""
    __tablename__ = "tasks"

    id = Column(Integer(), primary_key=True)
    md5 = Column(String(32), nullable=True)
    file_path = Column(String(255))
    timeout = Column(Integer(), server_default="0")
    priority = Column(Integer(), server_default="1")
    custom = Column(String(255), nullable=True)
    machine = Column(String(255), nullable=True)
    package = Column(String(255), nullable=True)
    options = Column(String(255), nullable=True)
    platform = Column(String(255), nullable=True)
    added_on = Column(DateTime(timezone=False), default=datetime.now())
    completed_on = Column(DateTime(timezone=False), nullable=True)
    lock = Column(Boolean(), default=False)
    status = Column(Enum("pending", "failure", "success", name="status_type"), default="pending")

    def to_dict(self):
        """Converts object to dict.
        @return: dict
        """
        d = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            if isinstance(value, datetime):
                d[column.name] = value.strftime("%Y-%m-%d %H:%M:%S")
            else:
                d[column.name] = value
        return d

    def to_json(self):
        """Converts object to JSON.
        @return: JSON data
        """
        return json.dumps(self.to_dict())

    def __init__(self, file_path=None):
        self.file_path = file_path

    def __repr__(self):
        return "<Task('%s','%s')>" % (self.id, self.file_path)

class Database:
    """Analysis queue database."""

    def __init__(self, dsn=None):
        """@param dsn: database connection string."""
        cfg = Config()
        if dsn:
            engine = create_engine(dsn)
        elif cfg.cuckoo.database:
            engine = create_engine(cfg.cuckoo.database)
        else:
            engine = create_engine("sqlite:///%s" % os.path.join(CUCKOO_ROOT, "db", "cuckoo.db"))
        # Disable SQL logging. Turn it on for debugging.
        engine.echo = False
        # Connection timeout.
        if cfg.cuckoo.database_timeout:
            engine.pool_timeout = cfg.cuckoo.database_timeout
        else:
            engine.pool_timeout = 60
        # Create schema.
        try:
            Base.metadata.create_all(engine)
        except SQLAlchemyError as e:
            raise CuckooDatabaseError("Unable to create or connect to database: %s" % e)
        # Get db session.
        self.Session = sessionmaker(bind=engine)

    def add(self,
            file_path,
            md5=None,
            timeout=0,
            package=None,
            options=None,
            priority=1,
            custom=None,
            machine=None,
            platform=None):
        """Add a task to database.
        @param file_path: sample path.
        @param md5: sample MD5.
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param custom: custom options.
        @param machine: selected machine.
        @param platform: platform
        @return: cursor or None.
        """
        if not file_path or not os.path.exists(file_path):
            return None

        session = self.Session()
        task = Task(file_path)
        task.md5 = md5
        task.timeout = timeout
        task.package = package
        task.options = options
        task.priority = priority
        task.custom = custom
        task.machine = machine
        task.platform = platform
        session.add(task)
        try:
            session.commit()
        except:
            session.rollback()
            return None
        return task.id

    def fetch(self):
        """Fetch a task.
        @return: task dict or None.
        """
        session = self.Session()
        row = session.query(Task).filter(Task.lock == False, Task.status == "pending").order_by("priority desc, added_on").first()
        return row

    def lock(self, task_id):
        """Lock a task.
        @param task_id: task id.
        @return: operation status.
        """
        session = self.Session()
        session.query(Task).get(task_id).lock = True
        try:
            session.commit()
        except:
            session.rollback()
            return False

        return True

    def unlock(self, task_id):
        """Unlock a task.
        @param task_id: task id.
        @return: operation status.
        """
        session = self.Session()
        session.query(Task).get(task_id).lock = False
        try:
            session.commit()
        except:
            session.rollback()
            return False

        return True

    def complete(self, task_id, success=True):
        """Mark a task as completed.
        @param task_id: task id.
        @param success: completed with status.
        @return: operation status.
        """
        session = self.Session()
        task = session.query(Task).get(task_id)
        task.lock = False
        if success:
            task.status = "success"
        else:
            task.status = "failure"
        task.completed_on = datetime.now()
        try:
            session.commit()
        except:
            session.rollback()
            return False

        return True

    def list(self, limit=None):
        """Retrieve list of task.
        @param limit: specify a limit of entries.
        @return: list of tasks.
        """
        session = self.Session()
        if limit:
            tasks = session.query(Task).order_by("status, added_on, id desc").limit(limit)
        else:
            tasks = session.query(Task).order_by("status, added_on, id desc")
        return tasks