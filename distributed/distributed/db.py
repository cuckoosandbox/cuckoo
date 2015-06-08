# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from datetime import datetime
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.inspection import inspect

db = SQLAlchemy(session_options=dict(autoflush=True))
ALEMBIC_VERSION = "3d1d8fd2cdbb"

class Serializer(object):
    """Serialize a query result object."""
    def to_dict(self):
        ret = {}
        for key in inspect(self).attrs.keys():
            ret[key] = getattr(self, key)
        return ret

class StringList(db.TypeDecorator):
    """List of comma-separated strings as field."""
    impl = db.Text

    def process_bind_param(self, value, dialect):
        return ", ".join(value)

    def process_result_value(self, value, dialect):
        return value.split(", ")

class Node(db.Model):
    """Cuckoo node database model."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False, unique=True)
    url = db.Column(db.Text, nullable=False)
    enabled = db.Column(db.Boolean, nullable=False)
    machines = db.relationship("Machine", backref="node", lazy="dynamic")

    def __init__(self, name, url, enabled=True):
        self.name = name
        self.url = url
        self.enabled = enabled

class Machine(db.Model):
    """Machine database model related to a Cuckoo node."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    platform = db.Column(db.Text, nullable=False)
    tags = db.Column(StringList)
    node_id = db.Column(db.Integer, db.ForeignKey("node.id"))

    def __init__(self, name, platform, tags):
        self.name = name
        self.platform = platform
        self.tags = tags

class Task(db.Model, Serializer):
    """Analysis task database model."""
    PENDING = "pending"
    PROCESSING = "processing"
    FINISHED = "finished"
    DELETED = "deleted"
    task_status = db.Enum(PENDING, PROCESSING, FINISHED, DELETED,
                          name="task_status_type")

    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.Text)
    filename = db.Column(db.Text)
    package = db.Column(db.Text)
    timeout = db.Column(db.Integer)
    priority = db.Column(db.Integer)
    options = db.Column(db.Text)
    machine = db.Column(db.Text)
    platform = db.Column(db.Text)
    tags = db.Column(db.Text)
    custom = db.Column(db.Text)
    owner = db.Column(db.Text)
    memory = db.Column(db.Text)
    clock = db.Column(db.Integer)
    enforce_timeout = db.Column(db.Text)

    # Cuckoo node and Task ID this has been submitted to.
    node_id = db.Column(db.Integer, db.ForeignKey("node.id"))
    task_id = db.Column(db.Integer)
    status = db.Column(task_status, server_default=PENDING, nullable=False)

    # Timestamps for this task. When it was submitted, when it was delegated
    # to a Cuckoo node, when the analysis started, and when we retrieved
    # the report.
    submitted = db.Column(db.DateTime(timezone=False), default=datetime.now)
    delegated = db.Column(db.DateTime(timezone=False), nullable=True)
    started = db.Column(db.DateTime(timezone=False), nullable=True)
    completed = db.Column(db.DateTime(timezone=False), nullable=True)

    def __init__(self, path, filename, package, timeout, priority, options,
                 machine, platform, tags, custom, owner, memory, clock,
                 enforce_timeout):
        self.path = path
        self.filename = filename
        self.package = package
        self.timeout = timeout
        self.priority = priority
        self.options = options
        self.machine = machine
        self.platform = platform
        self.tags = tags
        self.custom = custom
        self.owner = owner
        self.memory = memory
        self.clock = clock
        self.enforce_timeout = enforce_timeout
        self.node_id = None
        self.task_id = None
        self.status = Task.PENDING

class NodeStatus(db.Model):
    """Node status monitoring database model."""
    id = db.Column(db.Integer, primary_key=True)
    node_id = db.Column(db.Integer, db.ForeignKey("node.id"))
    timestamp = db.Column(db.DateTime(timezone=False), nullable=False)
    status = db.Column(db.Text, nullable=False)

    def __init__(self, node_id, timestamp, status):
        self.node_id = node_id
        self.timestamp = timestamp
        self.status = status

class AlembicVersion(db.Model):
    """Support model for keeping track of the alembic revision identifier."""
    VERSION = ALEMBIC_VERSION
    version_num = db.Column(db.String, nullable=False, primary_key=True)

    def __init__(self, version_num):
        self.version_num = version_num
