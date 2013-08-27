# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import json
import logging
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
    from sqlalchemy import ForeignKey, Text, Index, Table
    from sqlalchemy.orm import sessionmaker, relationship, joinedload, backref
    from sqlalchemy.sql import func
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.exc import SQLAlchemyError, IntegrityError
    from sqlalchemy.pool import NullPool
    Base = declarative_base()
except ImportError:
    raise CuckooDependencyError("SQLAlchemy library not found, verify your setup")

log = logging.getLogger(__name__)

TASK_PENDING = "pending"
TASK_RUNNING = "running"
TASK_COMPLETED = "completed"
TASK_REPORTED = "reported"

# Secondary table used in association Machine - Tag.
machines_tags = Table("machines_tags", Base.metadata,
    Column("machine_id", Integer, ForeignKey("machines.id")),
    Column("tag_id", Integer, ForeignKey("tags.id"))
)

# Secondary table used in association Task - Tag.
tasks_tags = Table("tasks_tags", Base.metadata,
    Column("task_id", Integer, ForeignKey("tasks.id")),
    Column("tag_id", Integer, ForeignKey("tags.id"))
)

class Machine(Base):
    """Configured virtual machines to be used as guests."""
    __tablename__ = "machines"

    id = Column(Integer(), primary_key=True)
    name = Column(String(255), nullable=False)
    label = Column(String(255), nullable=False)
    ip = Column(String(255), nullable=False)
    platform = Column(String(255), nullable=False)
    tags = relationship("Tag", secondary=machines_tags, cascade="all, delete",
                        single_parent=True, backref=backref("machine", cascade="all"))
    interface = Column(String(255), nullable=True)
    snapshot = Column(String(255), nullable=True)
    locked = Column(Boolean(), nullable=False, default=False)
    locked_changed_on = Column(DateTime(timezone=False), nullable=True)
    status = Column(String(255), nullable=True)
    status_changed_on = Column(DateTime(timezone=False), nullable=True)
    resultserver_ip = Column(String(255), nullable=False)
    resultserver_port = Column(String(255), nullable=False)

    def __repr__(self):
        return "<Machine('{0}','{1}')>".format(self.id, self.name)

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

        # Tags are a relation so no column to iterate.
        d["tags"] = [tag.name for tag in self.tags]

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
                 platform,
                 interface,
                 snapshot,
                 resultserver_ip,
                 resultserver_port):
        self.name = name
        self.label = label
        self.ip = ip
        self.platform = platform
        self.interface = interface
        self.snapshot = snapshot
        self.resultserver_ip = resultserver_ip
        self.resultserver_port = resultserver_port

class Tag(Base):
    """Tag describing anything you want."""
    __tablename__ = "tags"

    id = Column(Integer(), primary_key=True)
    name = Column(String(255), nullable=False, unique=True)

    def __repr__(self):
        return "<Tag('{0}','{1}')>".format(self.id, self.name)

    def __init__(self,
                 name):
        self.name = name

class Guest(Base):
    """Tracks guest run."""
    __tablename__ = "guests"

    id = Column(Integer(), primary_key=True)
    name = Column(String(255), nullable=False)
    label = Column(String(255), nullable=False)
    manager = Column(String(255), nullable=False)
    started_on = Column(DateTime(timezone=False),
                        default=datetime.now,
                        nullable=False)
    shutdown_on = Column(DateTime(timezone=False), nullable=True)
    task_id = Column(Integer,
                     ForeignKey("tasks.id"),
                     nullable=False,
                     unique=True)

    def __repr__(self):
        return "<Guest('{0}','{1}')>".format(self.id, self.name)

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
        return "<Sample('{0}','{1}')>".format(self.id, self.sha256)

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
                     ForeignKey("tasks.id"),
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
        return "<Error('{0}','{1}','{2}')>".format(self.id, self.message, self.task_id)

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
    tags = relationship("Tag", secondary=tasks_tags, cascade="all, delete",
                        single_parent=True, backref=backref("task", cascade="all"),
                        lazy="subquery")
    options = Column(String(255), nullable=True)
    platform = Column(String(255), nullable=True)
    memory = Column(Boolean, nullable=False, default=False)
    enforce_timeout = Column(Boolean, nullable=False, default=False)
    clock = Column(DateTime(timezone=False),
                   default=datetime.now,
                   nullable=False)
    added_on = Column(DateTime(timezone=False),
                      default=datetime.now,
                      nullable=False)
    started_on = Column(DateTime(timezone=False), nullable=True)
    completed_on = Column(DateTime(timezone=False), nullable=True)
    status = Column(Enum(TASK_PENDING,
                         TASK_RUNNING,
                         TASK_COMPLETED,
                         TASK_REPORTED,
                         name="status_type"),
                         server_default=TASK_PENDING,
                         nullable=False)
    sample_id = Column(Integer, ForeignKey("samples.id"), nullable=True)
    sample = relationship("Sample", backref="tasks")
    guest = relationship("Guest", uselist=False, backref="tasks", cascade="save-update, delete")
    errors = relationship("Error", backref="tasks", cascade="save-update, delete")

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

        # Tags are a relation so no column to iterate.
        d["tags"] = [tag.name for tag in self.tags]

        return d

    def to_json(self):
        """Converts object to JSON.
        @return: JSON data
        """
        return json.dumps(self.to_dict())

    def __init__(self, target=None):
        self.target = target

    def __repr__(self):
        return "<Task('{0}','{1}')>".format(self.id, self.target)

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
                        raise CuckooDatabaseError("Unable to create database directory: {0}".format(e))

            self.engine = create_engine("sqlite:///{0}".format(db_file), poolclass=NullPool)

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
            raise CuckooDatabaseError("Unable to create or connect to database: {0}".format(e))

        # Get db session.
        self.Session = sessionmaker(bind=self.engine)

    def __del__(self):
        """Disconnects pool."""
        self.engine.dispose()

    def _get_or_create(self, session, model, **kwargs):
        """Get an ORM instance or create it if not exist.
        @param session: SQLAlchemy session object
        @param model: model to query
        @return: row instance
        """
        instance = session.query(model).filter_by(**kwargs).first()
        if instance:
            return instance
        else:
            instance = model(**kwargs)
            return instance

    def clean_machines(self):
        """Clean old stored machines and related tables."""
        session = self.Session()
        try:
            session.query(Machine).delete()
            session.commit()
        except SQLAlchemyError:
            session.rollback()
        finally:
            session.close()
        # Secondary table.
        # TODO: this is better done via cascade delete.
        self.engine.execute(machines_tags.delete())

    def add_machine(self,
                    name,
                    label,
                    ip,
                    platform,
                    tags,
                    interface,
                    snapshot,
                    resultserver_ip,
                    resultserver_port):
        """Add a guest machine.
        @param name: machine id
        @param label: machine label
        @param ip: machine IP address
        @param platform: machine supported platform
        @param interface: sniffing interface for this machine
        @param snapshot: snapshot name to use instead of the current one, if configured
        @param resultserver_ip: IP address of the Result Server
        @param resultserver_port: port of the Result Server
        """
        session = self.Session()
        machine = Machine(name=name,
                          label=label,
                          ip=ip,
                          platform=platform,
                          interface=interface,
                          snapshot=snapshot,
                          resultserver_ip=resultserver_ip,
                          resultserver_port=resultserver_port)
        # Deal with tags format (i.e. foo,bar,baz)
        if tags:
            for tag in tags.replace(" ","").split(","):
                machine.tags.append(self._get_or_create(session, Tag, name=tag))
        session.add(machine)

        try:
            session.commit()
        except SQLAlchemyError:
            session.rollback()
        finally:
            session.close()

    def set_status(self, task_id, status):
        """Set task status.
        @param task_id: task identifier
        @param status: status string
        @return: operation status
        """
        session = self.Session()
        try:
            row = session.query(Task).get(task_id)
            row.status = status

            if status == TASK_RUNNING:
                row.started_on = datetime.now()
            elif status == TASK_COMPLETED:
                row.completed_on = datetime.now()

            session.commit()
        except SQLAlchemyError:
            session.rollback()
        finally:
            session.close()

    def fetch(self, lock=True):
        """Fetches a task waiting to be processed and locks it for running.
        @return: None or task
        """
        session = self.Session()

        try:
            row = session.query(Task).filter(Task.status == TASK_PENDING).order_by("priority desc, added_on").first()

            if not row:
                return None

            if lock:
                self.set_status(task_id=row.id, status=TASK_RUNNING)
                session.refresh(row)
        except SQLAlchemyError:
            session.rollback()
        finally:
            session.close()

        return row

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
        try:
            session.query(Task).get(task_id).guest = guest
            session.commit()
            session.refresh(guest)
        except SQLAlchemyError:
            session.rollback()
            return None
        finally:
            session.close()
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
        finally:
            session.close()

    def list_machines(self, locked=False):
        """Lists virtual machines.
        @return: list of virtual machines
        """
        session = self.Session()
        try:
            if locked:
                machines = session.query(Machine).options(joinedload("tags")).filter(Machine.locked == True).all()
            else:
                machines = session.query(Machine).options(joinedload("tags")).all()
        except SQLAlchemyError:
            return None
        finally:
            session.close()
        return machines

    def lock_machine(self, name=None, platform=None, tags=None):
        """Places a lock on a free virtual machine.
        @param name: optional virtual machine name
        @param platform: optional virtual machine platform
        @param tags: optional tags required (list)
        @return: locked machine
        """
        session = self.Session()

        # Preventive checks.
        if name and platform:
            # Wrong usage.
            log.error("You can select machine only by name or by platform.")
            return None
        elif name and tags:
            # Also wrong usage
            log.error("You can select machine only by name or by tags.")
            return None

        try:
            machines = session.query(Machine)
            if name:
                machines = machines.filter(Machine.name == name)
            if platform:
                machines = machines.filter(Machine.platform == platform)
            if tags:
                for tag in tags:
                    machines = machines.filter(Machine.tags.any(name=tag.name))
            # Check if there machines that they satisfy selection requirements.
            if machines.count() == 0:
                raise CuckooOperationalError("No machines match selection criteria")

            # Get only free machines.
            machines = machines.filter(Machine.locked == False)
            # Get only one.
            machine = machines.first()
        except SQLAlchemyError:
            session.close()
            return None

        if machine:
            machine.locked = True
            machine.locked_changed_on = datetime.now()
            try:
                session.commit()
                session.refresh(machine)
            except SQLAlchemyError:
                session.rollback()
                return None
            finally:
                session.close()

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
            session.close()
            return None

        if machine:
            machine.locked = False
            machine.locked_changed_on = datetime.now()
            try:
                session.commit()
                session.refresh(machine)
            except SQLAlchemyError:
                session.rollback()
                return None
            finally:
                session.close()

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
        finally:
            session.close()
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
            session.close()
            return

        if machine:
            machine.status = status
            machine.status_changed_on = datetime.now()
            try:
                session.commit()
                session.refresh(machine)
            except SQLAlchemyError:
                session.rollback()
            finally:
                session.close()
        else:
            session.close()

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
        finally:
            session.close()

    # The following functions are mostly used by external utils.

    def add(self,
            obj,
            timeout=0,
            package="",
            options="",
            priority=1,
            custom="",
            machine="",
            platform="",
            tags=None,
            memory=False,
            enforce_timeout=False,
            clock=None):
        """Add a task to database.
        @param obj: object to add (File or URL).
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param custom: custom options.
        @param machine: selected machine.
        @param platform: platform.
        @param tags: optional tags that must be set for machine selection
        @param memory: toggle full memory dump.
        @param enforce_timeout: toggle full timeout execution.
        @param clock: virtual machine clock time
        @return: cursor or None.
        """
        session = self.Session()

        # Convert empty strings and None values to a valid int
        if not timeout:
            timeout = 0
        if not priority:
            priority = 1

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
                    session.close()
                    return None
            except SQLAlchemyError:
                session.close()
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

        # Deal with tags format (i.e. foo,bar,baz)
        if tags:
            for tag in tags.replace(" ","").split(","):
                task.tags.append(self._get_or_create(session, Tag, name=tag))

        if clock:
            if isinstance(clock, str) or isinstance(clock, unicode):
                try:
                    task.clock = datetime.strptime(clock, "%m-%d-%Y %H:%M:%S")
                except ValueError:
                    log.warning("The date you specified has an invalid format, using current timestamp")
                    task.clock = datetime.now()
            else:
                task.clock = clock

        session.add(task)

        try:
            session.commit()
            task_id = task.id
        except SQLAlchemyError:
            session.rollback()
            return None
        finally:
            session.close()

        return task_id

    def add_path(self,
                 file_path,
                 timeout=0,
                 package="",
                 options="",
                 priority=1,
                 custom="",
                 machine="",
                 platform="",
                 tags=None,
                 memory=False,
                 enforce_timeout=False,
                 clock=None):
        """Add a task to database from file path.
        @param file_path: sample path.
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param custom: custom options.
        @param machine: selected machine.
        @param platform: platform.
        @param tags: Tags required in machine selection
        @param memory: toggle full memory dump.
        @param enforce_timeout: toggle full timeout execution.
        @param clock: virtual machine clock time
        @return: cursor or None.
        """
        if not file_path or not os.path.exists(file_path):
            return None
        
        # Convert empty strings and None values to a valid int
        if not timeout:
            timeout = 0
        if not priority:
            priority = 1

        return self.add(File(file_path),
                        timeout,
                        package,
                        options,
                        priority,
                        custom,
                        machine,
                        platform,
                        tags,
                        memory,
                        enforce_timeout,
                        clock)

    def add_url(self,
                url,
                timeout=0,
                package="",
                options="",
                priority=1,
                custom="",
                machine="",
                platform="",
                tags=None,
                memory=False,
                enforce_timeout=False,
                clock=None):
        """Add a task to database from url.
        @param url: url.
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param custom: custom options.
        @param machine: selected machine.
        @param platform: platform.
        @param tags: tags for machine selection
        @param memory: toggle full memory dump.
        @param enforce_timeout: toggle full timeout execution.
        @param clock: virtual machine clock time
        @return: cursor or None.
        """
        
        # Convert empty strings and None values to a valid int
        if not timeout:
            timeout = 0
        if not priority:
            priority = 1
        
        return self.add(URL(url),
                        timeout,
                        package,
                        options,
                        priority,
                        custom,
                        machine,
                        platform,
                        tags,
                        memory,
                        enforce_timeout,
                        clock)

    def reschedule(self, task_id):
        """Reschedule a task.
        @param task_id: ID of the task to reschedule.
        @return: ID of the newly created task.
        """
        task = self.view_task(task_id)
        if not task:
            return None

        if task.category == "file":
            add = self.add_path
        elif task.category == "url":
            add = self.add_url

        return add(task.target,
                   task.timeout,
                   task.package,
                   task.options,
                   task.priority,
                   task.custom,
                   task.machine,
                   task.platform,
                   task.memory,
                   task.enforce_timeout,
                   task.clock)

    def list_tasks(self, limit=None, details=False, category=None, offset=None):
        """Retrieve list of task.
        @param limit: specify a limit of entries.
        @param details: if details about must be included
        @param category: filter by category
        @param offset: list offset
        @return: list of tasks.
        """
        session = self.Session()
        try:
            search = session.query(Task)

            if category:
                search = search.filter(Task.category == category)
            if details:
                search = search.options(joinedload("guest"), joinedload("errors"), joinedload("tags"))

            tasks = search.order_by("added_on desc").limit(limit).offset(offset).all()
        except SQLAlchemyError:
            return None
        finally:
            session.close()
        return tasks

    def count_tasks(self, status=None):
        """Count tasks in the database
        @param status: apply a filter according to the task status
        @return: number of tasks found
        """
        session = self.Session()
        try:
            if status:
                tasks_count = session.query(Task).filter(Task.status == status).count()
            else:
                tasks_count = session.query(Task).count()
        except SQLAlchemyError:
            return 0
        finally:
            session.close()
        return tasks_count

    def view_task(self, task_id, details=False):
        """Retrieve information on a task.
        @param task_id: ID of the task to query.
        @return: details on the task.
        """
        session = self.Session()
        try:
            if details:
                task = session.query(Task).options(joinedload("guest"), joinedload("errors"), joinedload("tags")).get(task_id)
            else:
                task = session.query(Task).get(task_id)
        except SQLAlchemyError:
            return None
        else:
            if task:
                session.expunge(task)
        finally:
            session.close()
        return task

    def delete_task(self, task_id):
        """Delete information on a task.
        @param task_id: ID of the task to query.
        @return: operation status.
        """
        session = self.Session()
        try:
            task = session.query(Task).get(task_id)
            session.delete(task)
            session.commit()
        except SQLAlchemyError:
            session.rollback()
            return False
        finally:
            session.close()
        return True

    def view_sample(self, sample_id):
        """Retrieve information on a sample given a sample id.
        @param sample_id: ID of the sample to query.
        @return: details on the sample used in sample: sample_id.
        """
        session = self.Session()
        try:
            sample = session.query(Sample).get(sample_id)
        except (SQLAlchemyError, AttributeError):
            return None
        else:
            if sample:
                session.expunge(sample)
        finally:
            session.close()

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
                sample = session.query(Sample).filter(Sample.sha256 == sha256).first()
        except SQLAlchemyError:
            return None
        else:
            if sample:
                session.expunge(sample)
        finally:
            session.close()
        return sample

    def view_machine(self, name):
        """Show virtual machine.
        @params name: virtual machine name
        @return: virtual machine's details
        """
        session = self.Session()
        try:
            machine = session.query(Machine).options(joinedload("tags")).filter(Machine.name == name).first()
        except SQLAlchemyError:
            return None
        else:
            if machine:
                session.expunge(machine)
        finally:
            session.close()
        return machine

    def view_machine_by_label(self, label):
        """Show virtual machine.
        @params label: virtual machine label
        @return: virtual machine's details
        """
        session = self.Session()
        try:
            machine = session.query(Machine).options(joinedload("tags")).filter(Machine.label == label).first()
        except SQLAlchemyError:
            return None
        else:
            if machine:
                session.expunge(machine)
        finally:
            session.close()
        return machine

    def view_errors(self, task_id):
        """Get all errors related to a task.
        @param task_id: ID of task associated to the errors
        @return: list of errors.
        """
        session = self.Session()
        try:
            errors = session.query(Error).filter(Error.task_id == task_id).all()
        except SQLAlchemyError:
            return None
        finally:
            session.close()
        return errors
