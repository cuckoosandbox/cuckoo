# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import json
from datetime import datetime

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooDatabaseError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import File, URL
from lib.cuckoo.common.utils import create_folder, Singleton

try:
    from sqlalchemy import create_engine, Column
    from sqlalchemy import Integer, String, Boolean, DateTime, Enum
    from sqlalchemy import ForeignKey, Text, Index
    from sqlalchemy.orm import sessionmaker, relationship
    from sqlalchemy.sql import func
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.exc import SQLAlchemyError, IntegrityError
    from sqlalchemy.pool import NullPool
    Base = declarative_base()
except ImportError:
    raise CuckooDependencyError("SQLAlchemy library not found, "
                                "verify your setup")

class Machine(Base):
    """Configured virtual machines to be used as guests."""
    __tablename__ = "machines"

    id = Column(Integer(), primary_key=True)
    name = Column(String(255), nullable=False)
    label = Column(String(255), nullable=False)
    ip = Column(String(255), nullable=False)
    platform = Column(String(255), nullable=False)
    locked = Column(Boolean(), nullable=False, default=False)
    locked_changed_on = Column(DateTime(timezone=False), nullable=True)
    status = Column(String(255), nullable=True)
    status_changed_on = Column(DateTime(timezone=False), nullable=True)

    def __repr__(self):
        return "<Machine('%s','%s')>" % (self.id, self.name)

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

    def __init__(self,
                 name,
                 label,
                 ip,
                 platform):
        self.name = name
        self.label = label
        self.ip = ip
        self.platform = platform

class Guest(Base):
    """Tracks guest run."""
    __tablename__ = "guests"

    id = Column(Integer(), primary_key=True)
    name = Column(String(255), nullable=False)
    label = Column(String(255), nullable=False)
    manager = Column(String(255), nullable=False)
    started_on = Column(DateTime(timezone=False),
                        default=datetime.now(),
                        nullable=False)
    shutdown_on = Column(DateTime(timezone=False), nullable=True)
    task_id = Column(Integer,
                     ForeignKey('tasks.id'),
                     nullable=False,
                     unique=True)

    def __repr__(self):
        return "<Guest('%s','%s')>" % (self.id, self.name)

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

    def __init__(self, name, label, manager):
        self.name = name
        self.label = label
        self.manager = manager

class Sample(Base):
    """Submitted files details."""
    __tablename__ = "samples"

    id = Column(Integer(), primary_key=True)
    file_size = Column(Integer(), nullable=False)
    file_type = Column(String(255), nullable=False)
    md5 = Column(String(32), nullable=False)
    crc32 = Column(String(8), nullable=False)
    sha1 = Column(String(40), nullable=False)
    sha256 = Column(String(64), nullable=False)
    sha512 = Column(String(128), nullable=False)
    ssdeep = Column(String(255), nullable=True)
    __table_args__ = (Index("hash_index",
                            "md5",
                            "crc32",
                            "sha1",
                            "sha256",
                            "sha512",
                            unique=True), )

    def __repr__(self):
        return "<Sample('%s','%s')>" % (self.id, self.sha256)

    def to_dict(self):
        """Converts object to dict.
        @return: dict
        """
        d = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            d[column.name] = value
        return d

    def to_json(self):
        """Converts object to JSON.
        @return: JSON data
        """
        return json.dumps(self.to_dict())

    def __init__(self,
                 md5,
                 crc32,
                 sha1,
                 sha256,
                 sha512,
                 file_size,
                 file_type=None,
                 ssdeep=None):
        self.md5 = md5
        self.sha1 = sha1
        self.crc32 = crc32
        self.sha256 = sha256
        self.sha512 = sha512
        self.file_size = file_size
        if file_type:
            self.file_type = file_type
        if ssdeep:
            self.ssdeep = ssdeep

class Error(Base):
    """Analysis errors."""
    __tablename__ = "errors"

    id = Column(Integer(), primary_key=True)
    message = Column(String(255), nullable=False)
    task_id = Column(Integer,
                     ForeignKey('tasks.id'),
                     nullable=False,
                     unique=True)

    def to_dict(self):
        """Converts object to dict.
        @return: dict
        """
        d = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            d[column.name] = value
        return d

    def to_json(self):
        """Converts object to JSON.
        @return: JSON data
        """
        return json.dumps(self.to_dict())

    def __init__(self, message, task_id):
        self.message = message
        self.task_id = task_id

    def __repr__(self):
        return "<Error('%s','%s','%s')>" % (self.id, self.message, self.task_id)

class Task(Base):
    """Analysis task queue."""
    __tablename__ = "tasks"

    id = Column(Integer(), primary_key=True)
    target = Column(Text(), nullable=False)
    category = Column(String(255), nullable=False)
    timeout = Column(Integer(), server_default="0", nullable=False)
    priority = Column(Integer(), server_default="1", nullable=False)
    custom = Column(String(255), nullable=True)
    machine = Column(String(255), nullable=True)
    package = Column(String(255), nullable=True)
    options = Column(String(255), nullable=True)
    platform = Column(String(255), nullable=True)
    memory = Column(Boolean, nullable=False, default=False)
    enforce_timeout = Column(Boolean, nullable=False, default=False)
    added_on = Column(DateTime(timezone=False),
                      default=datetime.now(),
                      nullable=False)
    completed_on = Column(DateTime(timezone=False), nullable=True)
    status = Column(Enum("pending",
                         "processing",
                         "failure",
                         "success",
                         name="status_type"),
                         server_default="pending",
                         nullable=False)
    sample_id = Column(Integer, ForeignKey("samples.id"), nullable=True)
    sample = relationship("Sample", backref="tasks")
    guest = relationship("Guest", uselist=False, backref="tasks")
    errors = relationship("Error", backref="tasks")

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

    def __init__(self, target=None):
        self.target = target

    def __repr__(self):
        return "<Task('%s','%s')>" % (self.id, self.target)

class Database(object):
    """Analysis queue database.

    This class handles the creation of the database user for internal queue
    management. It also provides some functions for interacting with it.
    """
    __metaclass__ = Singleton

    def __init__(self, dsn=None):
        """@param dsn: database connection string."""
        cfg = Config()

        if dsn:
            self.engine = create_engine(dsn, poolclass=NullPool)
        elif cfg.database.connection:
            self.engine = create_engine(cfg.database.connection, poolclass=NullPool)
        else:
            db_file = os.path.join(CUCKOO_ROOT, "db", "cuckoo.db")
            if not os.path.exists(db_file):
                db_dir = os.path.dirname(db_file)
                if not os.path.exists(db_dir):
                    try:
                        create_folder(folder=db_dir)
                    except CuckooOperationalError as e:
                        raise CuckooDatabaseError("Unable to create database "
                                                  "directory: %s" % e)
            self.engine = create_engine("sqlite:///%s" % db_file, poolclass=NullPool)

        # Disable SQL logging. Turn it on for debugging.
        self.engine.echo = False
        # Connection timeout.
        if cfg.database.timeout:
            self.engine.pool_timeout = cfg.database.timeout
        else:
            self.engine.pool_timeout = 60
        # Create schema.
        try:
            Base.metadata.create_all(self.engine)
        except SQLAlchemyError as e:
            raise CuckooDatabaseError("Unable to create or connect to "
                                      "database: %s" % e)

        # Get db session.
        self.Session = sessionmaker(bind=self.engine)

    def __del__(self):
        """Disconnects pool."""
        self.engine.dispose()

    def clean_machines(self):
        """Clean old stored machines."""
        session = self.Session()
        try:
            session.query(Machine).delete()
            session.commit()
        except SQLAlchemyError:
            session.rollback()

    def _set_status(self, task_id, status):
        """Set task status.
        @param task_id: task identifier
        @param status: status string
        @return: operation status
        """
        session = self.Session()
        try:
            session.query(Task).get(task_id).status = status
            session.commit()
        except SQLAlchemyError:
            session.rollback()
            return False

        return True

    def add_machine(self,
                    name,
                    label,
                    ip,
                    platform):
        """Add a guest machine.
        @param name: machine id
        @param labal: machine label
        @param ip: machine IP address
        @param platform: machine supported platform
        """
        session = self.Session()
        machine = Machine(name=name,
                          label=label,
                          ip=ip,
                          platform=platform)
        session.add(machine)
        try:
            session.commit()
        except SQLAlchemyError:
            session.rollback()

    def fetch(self):
        """Fetch a task.
        @return: task dict or None.
        """
        session = self.Session()
        try:
            row = session.query(Task).filter(Task.status == "pending").order_by("priority desc, added_on").first()
        except SQLAlchemyError:
            return None
        return row

    def process(self, task_id):
        """Set task status as processing.
        @param task_id: task identifier
        @return: operation status
        """
        return self._set_status(task_id, "processing")

    def fetch_and_process(self):
        """Fetches a task waiting to be processed and locks it for processing.
        @return: None or task
        """
        session = self.Session()
        try:
            row = session.query(Task).filter(Task.status == "pending").order_by("priority desc, added_on").first()
            if row:
               row.status = "processing"
            session.commit()
        except SQLAlchemyError:
            session.rollback()
            return None
        return row

    def complete(self, task_id, success=True):
        """Mark a task as completed.
        @param task_id: task id.
        @param success: completed with status.
        @return: operation status.
        """
        session = self.Session()
        try:
            task = session.query(Task).get(task_id)
        except SQLAlchemyError:
            return False

        if success:
            task.status = "success"
        else:
            task.status = "failure"

        task.completed_on = datetime.now()

        try:
            session.commit()
        except SQLAlchemyError:
            session.rollback()
            return False

        return True

    def guest_start(self, task_id, name, label, manager):
        """Logs guest start.
        @param task_id: task identifier
        @param name: vm name
        @param label: vm label
        @param manager: vm manager
        @return: guest row id
        """
        session = self.Session()
        guest = Guest(name, label, manager)
        guest.started_on = datetime.now()
        try:
            session.query(Task).get(task_id).guest = guest
            session.commit()
        except SQLAlchemyError:
            session.rollback()
            return None

        return guest.id

    def guest_stop(self, guest_id):
        """Logs guest stop.
        @param guest_id: guest log entry id
        """
        session = self.Session()
        try:
            session.query(Guest).get(guest_id).shutdown_on = datetime.now()
            session.commit()
        except SQLAlchemyError:
            session.rollback()

    def list_machines(self, locked=False):
        """Lists virtual machines.
        @return: list of virtual machines
        """
        session = self.Session()
        try:
            if locked:
                machines = session.query(Machine).filter(Machine.locked == True)
            else:
                machines = session.query(Machine)
        except SQLAlchemyError:
            return None
        return machines

    def lock_machine(self, name=None, platform=None):
        """Places a lock on a free virtual machine.
        @param name: optional virtual machine name
        @param platform: optional virtual machine platform
        @return: locked machine
        """
        session = self.Session()
        try:
            if name and platform:
                # Wrong usage.
                return None
            elif name:
                machine = session.query(Machine).filter(Machine.name == name).filter(Machine.locked == False).first()
            elif platform:
                machine = session.query(Machine).filter(Machine.platform == platform).filter(Machine.locked == False).first()
            else:
                machine = session.query(Machine).filter(Machine.locked == False).first()
        except SQLAlchemyError:
                return None

        if machine:
            machine.locked = True
            machine.locked_changed_on = datetime.now()
            try:
                session.commit()
            except SQLAlchemyError:
                session.rollback()
                return None
        return machine

    def unlock_machine(self, label):
        """Remove lock form a virtual machine.
        @param label: virtual machine label
        @return: unlocked machine
        """
        session = self.Session()
        try:
            machine = session.query(Machine).filter(Machine.label == label).first()
        except SQLAlchemyError:
            return None

        if machine:
            machine.locked = False
            machine.locked_changed_on = datetime.now()
            try:
                session.commit()
            except SQLAlchemyError:
                session.rollback()
                return None
        return machine

    def count_machines_available(self):
        """How many virtual machines are ready for analysis.
        @return: free virtual machines count
        """
        session = self.Session()
        try:
            machines_count = session.query(Machine).filter(Machine.locked == False).count()
        except SQLAlchemyError:
            return 0
        return machines_count

    def set_machine_status(self, label, status):
        """Set status for a virtual machine.
        @param label: virtual machine label
        @param status: new virtual machine status
        """
        session = self.Session()
        try:
            machine = session.query(Machine).filter(Machine.label == label).first()
        except SQLAlchemyError:
               return

        if machine:
            machine.status = status
            machine.status_changed_on = datetime.now()
            try:
                session.commit()
            except SQLAlchemyError:
                session.rollback()

    def add_error(self, message, task_id):
        """Add an error related to a task.
        @param message: error message
        @param task_id: ID of the related task
        """
        session = self.Session()
        error = Error(message=message, task_id=task_id)
        session.add(error)
        try:
            session.commit()
        except SQLAlchemyError:
            session.rollback()

    # The following functions are mostly used by external utils.

    def add(self,
            obj,
            timeout=0,
            package=None,
            options=None,
            priority=1,
            custom=None,
            machine=None,
            platform=None,
            memory=False,
            enforce_timeout=False):
        """Add a task to database.
        @param file_path: sample path.
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param custom: custom options.
        @param machine: selected machine.
        @param platform: platform.
        @param memory: toggle full memory dump.
        @param enforce_timeout: toggle full timeout execution.
        @return: cursor or None.
        """
        session = self.Session()

        if isinstance(obj, File):
            sample = Sample(md5=obj.get_md5(),
                            crc32=obj.get_crc32(),
                            sha1=obj.get_sha1(),
                            sha256=obj.get_sha256(),
                            sha512=obj.get_sha512(),
                            file_size=obj.get_size(),
                            file_type=obj.get_type(),
                            ssdeep=obj.get_ssdeep())
            session.add(sample)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                try:
                    sample = session.query(Sample).filter(Sample.md5 == obj.get_md5()).first()
                except SQLAlchemyError:
                    return None
            except SQLAlchemyError:
                return None

            task = Task(obj.file_path)
            task.sample_id = sample.id
        elif isinstance(obj, URL):
            task = Task(obj.url)

        task.category = obj.__class__.__name__.lower()
        task.timeout = timeout
        task.package = package
        task.options = options
        task.priority = priority
        task.custom = custom
        task.machine = machine
        task.platform = platform
        task.memory = memory
        task.enforce_timeout = enforce_timeout
        session.add(task)

        try:
            session.commit()
        except SQLAlchemyError:
            session.rollback()
            return None

        return task.id

    def add_path(self,
                 file_path,
                 timeout=0,
                 package=None,
                 options=None,
                 priority=1,
                 custom=None,
                 machine=None,
                 platform=None,
                 memory=False,
                 enforce_timeout=False):
        """Add a task to database from file path.
        @param file_path: sample path.
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param custom: custom options.
        @param machine: selected machine.
        @param platform: platform.
        @param memory: toggle full memory dump.
        @param enforce_timeout: toggle full timeout execution.
        @return: cursor or None.
        """
        if not file_path or not os.path.exists(file_path):
            return None

        return self.add(File(file_path),
                        timeout,
                        package,
                        options,
                        priority,
                        custom,
                        machine,
                        platform,
                        memory,
                        enforce_timeout)

    def add_url(self,
                url,
                timeout=0,
                package=None,
                options=None,
                priority=1,
                custom=None,
                machine=None,
                platform=None,
                memory=False,
                enforce_timeout=False):
        """Add a task to database from url.
        @param url: url.
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param custom: custom options.
        @param machine: selected machine.
        @param platform: platform.
        @param memory: toggle full memory dump.
        @param enforce_timeout: toggle full timeout execution.
        @return: cursor or None.
        """
        return self.add(URL(url),
                        timeout,
                        package,
                        options,
                        priority,
                        custom,
                        machine,
                        platform,
                        memory,
                        enforce_timeout)

    def list_tasks(self, limit=None):
        """Retrieve list of task.
        @param limit: specify a limit of entries.
        @return: list of tasks.
        """
        session = self.Session()
        try:
            tasks = session.query(Task).order_by("added_on desc").limit(limit)
        except SQLAlchemyError:
            return None
        return tasks

    def view_task(self, task_id):
        """Retrieve information on a task.
        @param task_id: ID of the task to query.
        @return: details on the task.
        """
        session = self.Session()
        try:
            task = session.query(Task).get(task_id)
        except SQLAlchemyError:
            return None
        return task

    def view_sample(self, sample_id):
        """Retrieve information on a sample.
        @param sample_id: ID of the sample to query.
        @return: details on the sample.
        """
        session = self.Session()
        try:
            sample = session.query(Sample).get(sample_id)
        except SQLAlchemyError:
            return None
        return sample

    def find_sample(self, md5=None, sha256=None):
        """Search samples by MD5.
        @param md5: md5 string
        @return: matches list
        """
        session = self.Session()
        try:
            if md5:
                sample = session.query(Sample).filter(Sample.md5 == md5).first()
            elif sha256:
                sample = sesison.query(Sample).fitler(Sample.sha256 == sha256).first()
        except SQLAlchemyError:
            return None
        return sample

    def view_machine(self, name):
        """Show virtual machine.
        @params name: virtual machine name
        @return: virtual machine's details
        """
        session = self.Session()
        try:
            machine = session.query(Machine).filter(Machine.name == name).first()
        except SQLAlchemyError:
            return None
        return machine

    def view_errors(self, task_id):
        """Get all errors related to a task.
        @param task_id: ID of task associated to the errors
        @return: list of errors.
        """
        session = self.Session()
        try:
            errors = session.query(Error).filter(Error.task_id == task_id)
        except SQLAlchemyError:
            return None
        return errors
