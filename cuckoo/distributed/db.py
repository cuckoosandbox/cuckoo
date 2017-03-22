# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import json

from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.inspection import inspect

db = SQLAlchemy(session_options=dict(autoflush=True))
ALEMBIC_VERSION = "4b86bc0d40aa"

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

class JsonType(db.TypeDecorator):
    """List of comma-separated strings as field."""
    impl = db.Text

    def process_bind_param(self, value, dialect):
        return json.dumps(value)

    def process_result_value(self, value, dialect):
        return json.loads(value)

class Node(db.Model):
    """Cuckoo node database model."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False, unique=False)
    url = db.Column(db.Text, nullable=False)
    mode = db.Column(db.Text, nullable=False)
    enabled = db.Column(db.Boolean, nullable=False)
    machines = db.relationship("Machine", backref="node", lazy="dynamic")

    def __init__(self, name, url, mode, enabled=True):
        self.name = name
        self.url = url
        self.mode = mode
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
    ASSIGNED = "assigned"
    PROCESSING = "processing"
    FINISHED = "finished"
    DELETED = "deleted"

    task_status = db.Enum(PENDING, ASSIGNED, PROCESSING, FINISHED, DELETED,
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
    status = db.Column(task_status, nullable=False)

    # Timestamps for this task. When it was submitted, when it was delegated
    # to a Cuckoo node, when the analysis started, and when we retrieved
    # the report.
    submitted = db.Column(
        db.DateTime(timezone=False), default=datetime.datetime.now
    )
    delegated = db.Column(db.DateTime(timezone=False), nullable=True)
    started = db.Column(db.DateTime(timezone=False), nullable=True)
    completed = db.Column(db.DateTime(timezone=False), nullable=True)

    __table_args__ = db.Index("ix_node_task", node_id, task_id),

    def __init__(self, path=None, filename=None, package=None, timeout=None,
                 priority=None, options=None, machine=None, platform=None,
                 tags=None, custom=None, owner=None, memory=None, clock=None,
                 enforce_timeout=None, node_id=None, task_id=None,
                 status=PENDING):
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
        self.node_id = node_id
        self.task_id = task_id
        self.status = status

class NodeStatus(db.Model, Serializer):
    """Node status monitoring database model."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime(timezone=False), nullable=False,
                          index=True)
    status = db.Column(JsonType, nullable=False)

    def __init__(self, name, timestamp, status):
        self.name = name
        self.timestamp = timestamp
        self.status = status

class AlembicVersion(db.Model):
    """Support model for keeping track of the alembic revision identifier."""
    VERSION = ALEMBIC_VERSION
    version_num = db.Column(db.String(32), nullable=False, primary_key=True)

    def __init__(self, version_num):
        self.version_num = version_num
