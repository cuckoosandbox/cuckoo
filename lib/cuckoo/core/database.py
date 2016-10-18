# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import logging
from datetime import datetime

from lib.cuckoo.common.config import Config, parse_options, emit_options
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooDatabaseError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.objects import File, URL, Dictionary
from lib.cuckoo.common.utils import create_folder, Singleton, classlock, SuperLock, json_encode

try:
    from sqlalchemy import create_engine, Column, not_
    from sqlalchemy import Integer, String, Boolean, DateTime, Enum, func
    from sqlalchemy import ForeignKey, Text, Index, Table
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.exc import SQLAlchemyError, IntegrityError
    from sqlalchemy.orm import sessionmaker, relationship, joinedload
    from sqlalchemy.ext.hybrid import hybrid_property
    Base = declarative_base()
except ImportError:
    raise CuckooDependencyError(
        "Unable to import sqlalchemy (install with `pip install sqlalchemy`)"
    )

log = logging.getLogger(__name__)

SCHEMA_VERSION = "cd31654d187"
TASK_PENDING = "pending"
TASK_RUNNING = "running"
TASK_COMPLETED = "completed"
TASK_RECOVERED = "recovered"
TASK_REPORTED = "reported"
TASK_FAILED_ANALYSIS = "failed_analysis"
TASK_FAILED_PROCESSING = "failed_processing"
TASK_FAILED_REPORTING = "failed_reporting"

# Secondary table used in association Machine - Tag.
machines_tags = Table(
    "machines_tags", Base.metadata,
    Column("machine_id", Integer, ForeignKey("machines.id")),
    Column("tag_id", Integer, ForeignKey("tags.id"))
)

# Secondary table used in association Task - Tag.
tasks_tags = Table(
    "tasks_tags", Base.metadata,
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
    tags = relationship("Tag", secondary=machines_tags, single_parent=True,
                        backref="machine")
    options = Column(String(255), nullable=True)
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

    def is_analysis(self):
        """Is this an analysis machine? Generally speaking all machines are
        analysis machines, however, this is not the case for service VMs.
        Please refer to the services auxiliary module."""
        for tag in self.tags:
            if tag.name == "service":
                return
        return True

    def __init__(self, name, label, ip, platform, options, interface,
                 snapshot, resultserver_ip, resultserver_port):
        self.name = name
        self.label = label
        self.ip = ip
        self.platform = platform
        self.options = options
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

    def __init__(self, name):
        self.name = name

class Guest(Base):
    """Tracks guest run."""
    __tablename__ = "guests"

    id = Column(Integer(), primary_key=True)
    # TODO Replace the guest.status with a more generic Task.status solution.
    status = Column(String(16), nullable=False)
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
    file_type = Column(Text(), nullable=False)
    md5 = Column(String(32), nullable=False)
    crc32 = Column(String(8), nullable=False)
    sha1 = Column(String(40), nullable=False)
    sha256 = Column(String(64), nullable=False)
    sha512 = Column(String(128), nullable=False)
    ssdeep = Column(String(255), nullable=True)
    __table_args__ = Index("hash_index", "md5", "crc32", "sha1",
                           "sha256", "sha512", unique=True),

    def __repr__(self):
        return "<Sample('{0}','{1}')>".format(self.id, self.sha256)

    def to_dict(self):
        """Converts object to dict.
        @return: dict
        """
        d = {}
        for column in self.__table__.columns:
            d[column.name] = getattr(self, column.name)
        return d

    def to_json(self):
        """Converts object to JSON.
        @return: JSON data
        """
        return json.dumps(self.to_dict())

    def __init__(self, md5, crc32, sha1, sha256, sha512,
                 file_size, file_type=None, ssdeep=None):
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
    task_id = Column(Integer, ForeignKey("tasks.id"), nullable=False)

    def to_dict(self):
        """Converts object to dict.
        @return: dict
        """
        d = {}
        for column in self.__table__.columns:
            d[column.name] = getattr(self, column.name)
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
    owner = Column(String(64), nullable=True)
    machine = Column(String(255), nullable=True)
    package = Column(String(255), nullable=True)
    tags = relationship("Tag", secondary=tasks_tags, single_parent=True,
                        backref="task", lazy="subquery")
    _options = Column("options", String(255), nullable=True)
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
    status = Column(Enum(TASK_PENDING, TASK_RUNNING, TASK_COMPLETED,
                         TASK_REPORTED, TASK_RECOVERED, TASK_FAILED_ANALYSIS,
                         TASK_FAILED_PROCESSING, TASK_FAILED_REPORTING, name="status_type"),
                    server_default=TASK_PENDING,
                    nullable=False)
    sample_id = Column(Integer, ForeignKey("samples.id"), nullable=True)
    processing = Column(String(16), nullable=True)
    route = Column(String(16), nullable=True)
    sample = relationship("Sample", backref="tasks")
    guest = relationship("Guest", uselist=False, backref="tasks", cascade="save-update, delete")
    errors = relationship("Error", backref="tasks", cascade="save-update, delete")

    def duration(self):
        if self.started_on and self.completed_on:
            return (self.completed_on - self.started_on).seconds
        return -1

    @hybrid_property
    def options(self):
        if not self._options:
            return {}
        return parse_options(self._options)

    @options.setter
    def options(self, value):
        self._options = value

    def to_dict(self):
        """Converts object to dict.
        @return: dict
        """
        d = Dictionary()
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            d[column.name] = value

        # Tags are a relation so no column to iterate.
        d["tags"] = [tag.name for tag in self.tags]
        d["duration"] = self.duration()
        d["guest"] = {}

        if self.guest:
            # Get machine description.
            d["guest"] = machine = self.guest.to_dict()
            # Remove superfluous fields.
            del machine["task_id"]
            del machine["id"]

        return d

    def to_json(self):
        """Converts object to JSON.
        @return: JSON data
        """
        return json_encode(self.to_dict())

    def __init__(self, target=None):
        self.target = target

    def __repr__(self):
        return "<Task('{0}','{1}')>".format(self.id, self.target)

class AlembicVersion(Base):
    """Table used to pinpoint actual database schema release."""
    __tablename__ = "alembic_version"

    version_num = Column(String(32), nullable=False, primary_key=True)

class Database(object):
    """Analysis queue database.

    This class handles the creation of the database user for internal queue
    management. It also provides some functions for interacting with it.
    """
    __metaclass__ = Singleton

    def __init__(self, dsn=None, schema_check=True, echo=False):
        """
        @param dsn: database connection string.
        @param schema_check: disable or enable the db schema version check.
        @param echo: echo sql queries.
        """
        self._lock = SuperLock()
        cfg = Config()

        if dsn:
            self._connect_database(dsn)
        elif hasattr(cfg, "database") and cfg.database.connection:
            self._connect_database(cfg.database.connection)
        else:
            db_file = os.path.join(CUCKOO_ROOT, "db", "cuckoo.db")
            if not os.path.exists(db_file):
                db_dir = os.path.dirname(db_file)
                if not os.path.exists(db_dir):
                    try:
                        create_folder(folder=db_dir)
                    except CuckooOperationalError as e:
                        raise CuckooDatabaseError("Unable to create database directory: {0}".format(e))

            self._connect_database("sqlite:///%s" % db_file)

        # Disable SQL logging. Turn it on for debugging.
        self.engine.echo = echo

        # Connection timeout.
        if hasattr(cfg, "database") and cfg.database.timeout:
            self.engine.pool_timeout = cfg.database.timeout
        else:
            self.engine.pool_timeout = 60

        # Let's emit a warning just in case.
        if not hasattr(cfg, "database"):
            log.warning("It appears you don't have a valid `database` "
                        "section in conf/cuckoo.conf, using sqlite3 instead.")

        # Create schema.
        try:
            Base.metadata.create_all(self.engine)
        except SQLAlchemyError as e:
            raise CuckooDatabaseError("Unable to create or connect to database: {0}".format(e))

        # Get db session.
        self.Session = sessionmaker(bind=self.engine)

        # Deal with schema versioning.
        # TODO: it's a little bit dirty, needs refactoring.
        tmp_session = self.Session()
        if not tmp_session.query(AlembicVersion).count():
            # Set database schema version.
            tmp_session.add(AlembicVersion(version_num=SCHEMA_VERSION))
            try:
                tmp_session.commit()
            except SQLAlchemyError as e:
                raise CuckooDatabaseError("Unable to set schema version: {0}".format(e))
                tmp_session.rollback()
            finally:
                tmp_session.close()
        else:
            # Check if db version is the expected one.
            last = tmp_session.query(AlembicVersion).first()
            tmp_session.close()
            if last.version_num != SCHEMA_VERSION and schema_check:
                raise CuckooDatabaseError(
                    "DB schema version mismatch: found %s, expected %s. "
                    "Try to apply all migrations (cd utils/db_migration/ && "
                    "alembic upgrade head)." %
                    (last.version_num, SCHEMA_VERSION)
                )

    def __del__(self):
        """Disconnects pool."""
        self.engine.dispose()

    def _connect_database(self, connection_string):
        """Connect to a Database.
        @param connection_string: Connection string specifying the database
        """
        try:
            # TODO: this is quite ugly, should improve.
            if connection_string.startswith("sqlite"):
                # Using "check_same_thread" to disable sqlite safety check on multiple threads.
                self.engine = create_engine(connection_string, connect_args={"check_same_thread": False})
            elif connection_string.startswith("postgres"):
                # Disabling SSL mode to avoid some errors using sqlalchemy and multiprocesing.
                # See: http://www.postgresql.org/docs/9.0/static/libpq-ssl.html#LIBPQ-SSL-SSLMODE-STATEMENTS
                self.engine = create_engine(connection_string, connect_args={"sslmode": "disable"})
            else:
                self.engine = create_engine(connection_string)
        except ImportError as e:
            lib = e.message.split()[-1]
            raise CuckooDependencyError(
                "Missing database driver, unable to import %s (install with "
                "`pip install %s`)" % (lib, lib)
            )

    def _get_or_create(self, session, model, **kwargs):
        """Get an ORM instance or create it if not exist.
        @param session: SQLAlchemy session object
        @param model: model to query
        @return: row instance
        """
        instance = session.query(model).filter_by(**kwargs).first()
        return instance or model(**kwargs)

    @classlock
    def drop(self):
        """Drop all tables."""
        try:
            Base.metadata.drop_all(self.engine)
        except SQLAlchemyError as e:
            raise CuckooDatabaseError("Unable to create or connect to database: {0}".format(e))

    @classlock
    def clean_machines(self):
        """Clean old stored machines and related tables."""
        # Secondary table.
        # TODO: this is better done via cascade delete.
        self.engine.execute(machines_tags.delete())

        session = self.Session()
        try:
            session.query(Machine).delete()
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error cleaning machines: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    @classlock
    def add_machine(self, name, label, ip, platform, options, tags, interface,
                    snapshot, resultserver_ip, resultserver_port):
        """Add a guest machine.
        @param name: machine id
        @param label: machine label
        @param ip: machine IP address
        @param platform: machine supported platform
        @param tags: list of comma separated tags
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
                          options=options,
                          interface=interface,
                          snapshot=snapshot,
                          resultserver_ip=resultserver_ip,
                          resultserver_port=resultserver_port)

        # Deal with tags format (i.e., foo,bar,baz)
        if tags:
            for tag in tags.split(","):
                if tag.strip():
                    tag = self._get_or_create(session, Tag, name=tag.strip())
                    machine.tags.append(tag)
        session.add(machine)

        try:
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error adding machine: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    @classlock
    def set_status(self, task_id, status):
        """Set task status.
        @param task_id: task identifier
        @param status: status string
        @return: operation status
        """
        session = self.Session()
        try:
            row = session.query(Task).get(task_id)
            if not row:
                return

            row.status = status

            if status == TASK_RUNNING:
                row.started_on = datetime.now()
            elif status == TASK_COMPLETED:
                row.completed_on = datetime.now()

            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error setting status: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    @classlock
    def set_route(self, task_id, route):
        """Set the taken route of this task.
        @param task_id: task identifier
        @param route: route string
        @return: operation status
        """
        session = self.Session()
        try:
            row = session.query(Task).get(task_id)
            if not row:
                return

            row.route = route
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error setting route: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    @classlock
    def fetch(self, machine=None, service=True):
        """Fetches a task waiting to be processed and locks it for running.
        @return: None or task
        """
        session = self.Session()
        try:
            q = session.query(Task).filter_by(status=TASK_PENDING)

            if machine:
                q = q.filter_by(machine=machine)

            if not service:
                q = q.filter(not_(Task.tags.any(name="service")))

            row = q.order_by(Task.priority.desc(), Task.added_on).first()
            if row:
                self.set_status(task_id=row.id, status=TASK_RUNNING)
                session.refresh(row)

            return row
        except SQLAlchemyError as e:
            log.debug("Database error fetching task: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    @classlock
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
            guest.status = "init"
            session.query(Task).get(task_id).guest = guest
            session.commit()
            session.refresh(guest)
            return guest.id
        except SQLAlchemyError as e:
            log.debug("Database error logging guest start: {0}".format(e))
            session.rollback()
            return None
        finally:
            session.close()

    @classlock
    def guest_get_status(self, task_id):
        """Logs guest start.
        @param task_id: task id
        @return: guest status
        """
        session = self.Session()
        try:
            guest = session.query(Guest).filter_by(task_id=task_id).first()
            return guest.status if guest else None
        except SQLAlchemyError as e:
            log.debug("Database error logging guest start: {0}".format(e))
            session.rollback()
            return
        finally:
            session.close()

    @classlock
    def guest_set_status(self, task_id, status):
        """Logs guest start.
        @param task_id: task identifier
        @param status: status
        """
        session = self.Session()
        try:
            guest = session.query(Guest).filter_by(task_id=task_id).first()
            guest.status = status
            session.commit()
            session.refresh(guest)
        except SQLAlchemyError as e:
            log.debug("Database error logging guest start: {0}".format(e))
            session.rollback()
            return None
        finally:
            session.close()

    @classlock
    def guest_remove(self, guest_id):
        """Removes a guest start entry."""
        session = self.Session()
        try:
            guest = session.query(Guest).get(guest_id)
            session.delete(guest)
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error logging guest remove: {0}".format(e))
            session.rollback()
            return None
        finally:
            session.close()

    @classlock
    def guest_stop(self, guest_id):
        """Logs guest stop.
        @param guest_id: guest log entry id
        """
        session = self.Session()
        try:
            guest = session.query(Guest).get(guest_id)
            guest.status = "stopped"
            guest.shutdown_on = datetime.now()
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error logging guest stop: {0}".format(e))
            session.rollback()
        except TypeError:
            log.warning("Data inconsistency in guests table detected, it might be a crash leftover. Continue")
            session.rollback()
        finally:
            session.close()

    @classlock
    def list_machines(self, locked=False):
        """Lists virtual machines.
        @return: list of virtual machines
        """
        session = self.Session()
        try:
            if locked:
                machines = session.query(Machine).options(joinedload("tags")).filter_by(locked=True).all()
            else:
                machines = session.query(Machine).options(joinedload("tags")).all()
            return machines
        except SQLAlchemyError as e:
            log.debug("Database error listing machines: {0}".format(e))
            return []
        finally:
            session.close()

    @classlock
    def lock_machine(self, label=None, platform=None, tags=None):
        """Places a lock on a free virtual machine.
        @param label: optional virtual machine label
        @param platform: optional virtual machine platform
        @param tags: optional tags required (list)
        @return: locked machine
        """
        session = self.Session()

        # Preventive checks.
        if label and platform:
            # Wrong usage.
            log.error("You can select machine only by label or by platform.")
            return None
        elif label and tags:
            # Also wrong usage.
            log.error("You can select machine only by label or by tags.")
            return None

        try:
            machines = session.query(Machine)
            if label:
                machines = machines.filter_by(label=label)
            if platform:
                machines = machines.filter_by(platform=platform)
            if tags:
                for tag in tags:
                    machines = machines.filter(Machine.tags.any(name=tag))

            # Check if there are any machines that satisfy the
            # selection requirements.
            if not machines.count():
                raise CuckooOperationalError("No machines match selection criteria.")

            # Get the first free machine.
            machine = machines.filter_by(locked=False).first()
        except SQLAlchemyError as e:
            log.debug("Database error locking machine: {0}".format(e))
            session.close()
            return None

        if machine:
            machine.locked = True
            machine.locked_changed_on = datetime.now()
            try:
                session.commit()
                session.refresh(machine)
            except SQLAlchemyError as e:
                log.debug("Database error locking machine: {0}".format(e))
                session.rollback()
                return None
            finally:
                session.close()
        else:
            session.close()

        return machine

    @classlock
    def unlock_machine(self, label):
        """Remove lock form a virtual machine.
        @param label: virtual machine label
        @return: unlocked machine
        """
        session = self.Session()
        try:
            machine = session.query(Machine).filter_by(label=label).first()
        except SQLAlchemyError as e:
            log.debug("Database error unlocking machine: {0}".format(e))
            session.close()
            return None

        if machine:
            machine.locked = False
            machine.locked_changed_on = datetime.now()
            try:
                session.commit()
                session.refresh(machine)
            except SQLAlchemyError as e:
                log.debug("Database error locking machine: {0}".format(e))
                session.rollback()
                return None
            finally:
                session.close()

        return machine

    @classlock
    def count_machines_available(self):
        """How many virtual machines are ready for analysis.
        @return: free virtual machines count
        """
        session = self.Session()
        try:
            machines_count = session.query(Machine).filter_by(locked=False).count()
            return machines_count
        except SQLAlchemyError as e:
            log.debug("Database error counting machines: {0}".format(e))
            return 0
        finally:
            session.close()

    @classlock
    def get_available_machines(self):
        """  Which machines are available
        @return: free virtual machines
        """
        session = self.Session()
        try:
            machines = session.query(Machine).options(joinedload("tags")).filter_by(locked=False).all()
            return machines
        except SQLAlchemyError as e:
            log.debug("Database error getting available machines: {0}".format(e))
            return []
        finally:
            session.close()

    @classlock
    def set_machine_status(self, label, status):
        """Set status for a virtual machine.
        @param label: virtual machine label
        @param status: new virtual machine status
        """
        session = self.Session()
        try:
            machine = session.query(Machine).filter_by(label=label).first()
        except SQLAlchemyError as e:
            log.debug("Database error setting machine status: {0}".format(e))
            session.close()
            return

        if machine:
            machine.status = status
            machine.status_changed_on = datetime.now()
            try:
                session.commit()
                session.refresh(machine)
            except SQLAlchemyError as e:
                log.debug("Database error setting machine status: {0}".format(e))
                session.rollback()
            finally:
                session.close()
        else:
            session.close()

    @classlock
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
        except SQLAlchemyError as e:
            log.debug("Database error adding error log: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    # The following functions are mostly used by external utils.

    @classlock
    def add(self, obj, timeout=0, package="", options="", priority=1,
            custom="", owner="", machine="", platform="", tags=None,
            memory=False, enforce_timeout=False, clock=None, category=None):
        """Add a task to database.
        @param obj: object to add (File or URL).
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param custom: custom options.
        @param owner: task owner.
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
                    sample = session.query(Sample).filter_by(md5=obj.get_md5()).first()
                except SQLAlchemyError as e:
                    log.debug("Error querying sample for hash: {0}".format(e))
                    session.close()
                    return None
            except SQLAlchemyError as e:
                log.debug("Database error adding task: {0}".format(e))
                session.close()
                return None

            task = Task(obj.file_path)
            task.sample_id = sample.id
        elif isinstance(obj, URL):
            task = Task(obj.url)
        else:
            task = Task("none")

        task.category = category
        task.timeout = timeout
        task.package = package
        task.options = options
        task.priority = priority
        task.custom = custom
        task.owner = owner
        task.machine = machine
        task.platform = platform
        task.memory = memory
        task.enforce_timeout = enforce_timeout

        # Deal with tags format (i.e., foo,bar,baz)
        if tags:
            for tag in tags.split(","):
                tag = self._get_or_create(session, Tag, name=tag.strip())
                task.tags.append(tag)

        if clock:
            if isinstance(clock, str) or isinstance(clock, unicode):
                try:
                    task.clock = datetime.strptime(clock, "%m-%d-%Y %H:%M:%S")
                except ValueError:
                    log.warning("The date you specified has an invalid format, using current timestamp.")
                    task.clock = datetime.now()
            else:
                task.clock = clock

        session.add(task)

        try:
            session.commit()
            task_id = task.id
        except SQLAlchemyError as e:
            log.debug("Database error adding task: {0}".format(e))
            session.rollback()
            return None
        finally:
            session.close()

        return task_id

    def add_path(self, file_path, timeout=0, package="", options="",
                 priority=1, custom="", owner="", machine="", platform="",
                 tags=None, memory=False, enforce_timeout=False, clock=None):
        """Add a task to database from file path.
        @param file_path: sample path.
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param custom: custom options.
        @param owner: task owner.
        @param machine: selected machine.
        @param platform: platform.
        @param tags: Tags required in machine selection
        @param memory: toggle full memory dump.
        @param enforce_timeout: toggle full timeout execution.
        @param clock: virtual machine clock time
        @return: cursor or None.
        """
        if not file_path or not os.path.exists(file_path):
            log.warning("File does not exist: %s.", file_path)
            return None

        # Convert empty strings and None values to a valid int
        if not timeout:
            timeout = 0
        if not priority:
            priority = 1

        return self.add(File(file_path), timeout, package, options, priority,
                        custom, owner, machine, platform, tags, memory,
                        enforce_timeout, clock, "file")

    def add_url(self, url, timeout=0, package="", options="", priority=1,
                custom="", owner="", machine="", platform="", tags=None,
                memory=False, enforce_timeout=False, clock=None):
        """Add a task to database from url.
        @param url: url.
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param custom: custom options.
        @param owner: task owner.
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

        return self.add(URL(url), timeout, package, options, priority,
                        custom, owner, machine, platform, tags, memory,
                        enforce_timeout, clock, "url")

    def add_baseline(self, timeout=0, owner="", machine="", memory=False):
        """Add a baseline task to database.
        @param timeout: selected timeout.
        @param owner: task owner.
        @param machine: selected machine.
        @param memory: toggle full memory dump.
        @return: cursor or None.
        """
        return self.add(None, timeout=timeout or 0, priority=999, owner=owner,
                        machine=machine, memory=memory, category="baseline")

    def add_service(self, timeout, owner, tags):
        """Add a service task to database.
        @param timeout: selected timeout.
        @param owner: task owner.
        @param tags: task tags.
        @return: cursor or None.
        """
        return self.add(None, timeout=timeout, priority=999, owner=owner,
                        tags=tags, category="service")

    def add_reboot(self, task_id, timeout=0, options="", priority=1,
                   owner="", machine="", platform="", tags=None, memory=False,
                   enforce_timeout=False, clock=None):
        """Add a reboot task to database from an existing analysis.
        @param task_id: task id of existing analysis.
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param owner: task owner.
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

        task = self.view_task(task_id)
        if not task or not os.path.exists(task.target):
            log.error(
                "Unable to add reboot analysis as the original task or its "
                "sample has already been deleted."
            )
            return

        # TODO Integrate the Reboot screen with the submission portal and
        # pass the parent task ID through as part of the "options".
        custom = "%s" % task_id

        return self.add(File(task.target), timeout, "reboot", options,
                        priority, custom, owner, machine, platform, tags,
                        memory, enforce_timeout, clock, "file")

    @classlock
    def reschedule(self, task_id, priority=None):
        """Reschedule a task.
        @param task_id: ID of the task to reschedule.
        @return: ID of the newly created task.
        """
        task = self.view_task(task_id)
        if not task:
            return

        if task.category == "file":
            add = self.add_path
        elif task.category == "url":
            add = self.add_url
        else:
            return

        # Change status to recovered.
        session = self.Session()
        session.query(Task).get(task_id).status = TASK_RECOVERED
        try:
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error rescheduling task: {0}".format(e))
            session.rollback()
            return False
        finally:
            session.close()

        # Normalize tags.
        if task.tags:
            tags = ",".join(tag.name for tag in task.tags)
        else:
            tags = task.tags

        # Assign a new priority.
        if priority:
            task.priority = priority

        options = emit_options(task.options)
        return add(task.target, task.timeout, task.package, options,
                   task.priority, task.custom, task.owner, task.machine,
                   task.platform, tags, task.memory, task.enforce_timeout,
                   task.clock)

    def list_tasks(self, limit=None, details=True, category=None, owner=None,
                   offset=None, status=None, sample_id=None, not_status=None,
                   completed_after=None, order_by=None):
        """Retrieve list of task.
        @param limit: specify a limit of entries.
        @param details: if details about must be included
        @param category: filter by category
        @param owner: task owner
        @param offset: list offset
        @param status: filter by task status
        @param sample_id: filter tasks for a sample
        @param not_status: exclude this task status from filter
        @param completed_after: only list tasks completed after this timestamp
        @param order_by: definition which field to sort by
        @return: list of tasks.
        """
        session = self.Session()
        try:
            search = session.query(Task)

            if status:
                search = search.filter_by(status=status)
            if not_status:
                search = search.filter(Task.status != not_status)
            if category:
                search = search.filter_by(category=category)
            if owner:
                search = search.filter_by(owner=owner)
            if details:
                search = search.options(joinedload("guest"), joinedload("errors"), joinedload("tags"))
            if sample_id is not None:
                search = search.filter_by(sample_id=sample_id)
            if completed_after:
                search = search.filter(Task.completed_on > completed_after)

            if order_by is not None:
                search = search.order_by(order_by)
            else:
                search = search.order_by(Task.added_on.desc())

            tasks = search.limit(limit).offset(offset).all()
            return tasks
        except SQLAlchemyError as e:
            log.debug("Database error listing tasks: {0}".format(e))
            return []
        finally:
            session.close()

    def minmax_tasks(self):
        """Find tasks minimum and maximum
        @return: unix timestamps of minimum and maximum
        """
        session = self.Session()
        try:
            _min = session.query(func.min(Task.started_on).label("min")).first()
            _max = session.query(func.max(Task.completed_on).label("max")).first()
            return int(_min[0].strftime("%s")), int(_max[0].strftime("%s"))
        except SQLAlchemyError as e:
            log.debug("Database error counting tasks: {0}".format(e))
            return 0
        finally:
            session.close()

    @classlock
    def count_tasks(self, status=None):
        """Count tasks in the database
        @param status: apply a filter according to the task status
        @return: number of tasks found
        """
        session = self.Session()
        try:
            if status:
                tasks_count = session.query(Task).filter_by(status=status).count()
            else:
                tasks_count = session.query(Task).count()
            return tasks_count
        except SQLAlchemyError as e:
            log.debug("Database error counting tasks: {0}".format(e))
            return 0
        finally:
            session.close()

    @classlock
    def view_task(self, task_id, details=True):
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
        except SQLAlchemyError as e:
            log.debug("Database error viewing task: {0}".format(e))
            return None
        else:
            if task:
                session.expunge(task)
            return task
        finally:
            session.close()

    @classlock
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
        except SQLAlchemyError as e:
            log.debug("Database error deleting task: {0}".format(e))
            session.rollback()
            return False
        finally:
            session.close()
        return True

    @classlock
    def view_sample(self, sample_id):
        """Retrieve information on a sample given a sample id.
        @param sample_id: ID of the sample to query.
        @return: details on the sample used in sample: sample_id.
        """
        session = self.Session()
        try:
            sample = session.query(Sample).get(sample_id)
        except AttributeError:
            return None
        except SQLAlchemyError as e:
            log.debug("Database error viewing task: {0}".format(e))
            return None
        else:
            if sample:
                session.expunge(sample)
        finally:
            session.close()

        return sample

    @classlock
    def find_sample(self, md5=None, sha256=None):
        """Search samples by MD5.
        @param md5: md5 string
        @return: matches list
        """
        session = self.Session()
        try:
            if md5:
                sample = session.query(Sample).filter_by(md5=md5).first()
            elif sha256:
                sample = session.query(Sample).filter_by(sha256=sha256).first()
        except SQLAlchemyError as e:
            log.debug("Database error searching sample: {0}".format(e))
            return None
        else:
            if sample:
                session.expunge(sample)
        finally:
            session.close()
        return sample

    @classlock
    def count_samples(self):
        """Counts the amount of samples in the database."""
        session = self.Session()
        try:
            sample_count = session.query(Sample).count()
        except SQLAlchemyError as e:
            log.debug("Database error counting samples: {0}".format(e))
            return 0
        finally:
            session.close()
        return sample_count

    @classlock
    def view_machine(self, name):
        """Show virtual machine.
        @params name: virtual machine name
        @return: virtual machine's details
        """
        session = self.Session()
        try:
            machine = session.query(Machine).options(joinedload("tags")).filter_by(name=name).first()
        except SQLAlchemyError as e:
            log.debug("Database error viewing machine: {0}".format(e))
            return None
        else:
            if machine:
                session.expunge(machine)
        finally:
            session.close()
        return machine

    @classlock
    def view_machine_by_label(self, label):
        """Show virtual machine.
        @params label: virtual machine label
        @return: virtual machine's details
        """
        session = self.Session()
        try:
            machine = session.query(Machine).options(joinedload("tags")).filter_by(label=label).first()
        except SQLAlchemyError as e:
            log.debug("Database error viewing machine by label: {0}".format(e))
            return None
        else:
            if machine:
                session.expunge(machine)
        finally:
            session.close()
        return machine

    @classlock
    def view_errors(self, task_id):
        """Get all errors related to a task.
        @param task_id: ID of task associated to the errors
        @return: list of errors.
        """
        session = self.Session()
        try:
            errors = session.query(Error).filter_by(task_id=task_id).all()
        except SQLAlchemyError as e:
            log.debug("Database error viewing errors: {0}".format(e))
            return []
        finally:
            session.close()
        return errors

    def processing_get_task(self, instance):
        """Get an available task for processing."""
        session = self.Session()

        # Please feel free to sqlalchemize the following query, but I didn't
        # get that far. This seems to be doing a fine job for avoiding race
        # conditions - especially with the session.commit() thing. But any
        # improvements are welcome.
        # TODO We can get rid of the `processing` column once again by
        # introducing a "reporting" status, but this requires annoying
        # database migrations, so leaving that for another day.
        query = """
            UPDATE tasks SET processing = :instance
            WHERE id IN (
                SELECT id FROM tasks
                WHERE status = :status AND processing IS NULL
                ORDER BY priority DESC, id ASC LIMIT 1 FOR UPDATE
            )
            RETURNING id
        """

        try:
            params = {
                "instance": instance,
                "status": TASK_COMPLETED,
            }
            task = session.execute(query, params).first()
            session.commit()
            return task[0] if task else None
        except SQLAlchemyError as e:
            log.debug("Database error getting new processing tasks: %s", e)
        finally:
            session.close()
