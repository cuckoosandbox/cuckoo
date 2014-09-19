#!/usr/bin/env python
# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import datetime
import hashlib
import json
import logging
import os.path
import sys
import tempfile
import threading
import time


def required(package):
    sys.exit("The %s package is required: pip install %s" %
             (package, package))

try:
    from flask import Flask, request
except ImportError:
    required("flask")

try:
    import requests
except ImportError:
    required("requests")

try:
    from flask.ext.restful import abort, reqparse
    from flask.ext.restful import Api as RestApi, Resource as RestResource
except ImportError:
    required("flask-restful")

try:
    from flask.ext.sqlalchemy import SQLAlchemy
    db = SQLAlchemy(session_options=dict(autoflush=True))
except ImportError:
    required("flask-sqlalchemy")


def sha256(path):
    """Returns the SHA256 hash for a file."""
    f = open(path, "rb")
    h = hashlib.sha256()
    while True:
        buf = f.read(1024 * 1024)
        if not buf:
            break

        h.update(buf)
    return h.hexdigest()


class StringList(db.TypeDecorator):
    """List of comma-separated strings as field."""
    impl = db.String

    def process_bind_param(self, value, dialect):
        return ", ".join(value)

    def process_result_value(self, value, dialect):
        return value.split(", ")


class Node(db.Model):
    """Cuckoo node database model."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, unique=True)
    url = db.Column(db.Text, unique=True)
    machines = db.relationship("Machine", backref="node", lazy="dynamic")

    def __init__(self, name, url):
        self.name = name
        self.url = url

    def list_machines(self):
        try:
            r = requests.get(os.path.join(self.url, "machines", "list"))

            for machine in r.json()["machines"]:
                yield Machine(name=machine["name"],
                              platform=machine["platform"],
                              tags=machine["tags"])
        except Exception as e:
            abort(404, message="Invalid Cuckoo node (%s): %s" % (self.url, e))

    def status(self):
        try:
            r = requests.get(os.path.join(self.url, "cuckoo", "status"))
            return r.json()["tasks"]
        except Exception as e:
            log.critical("Possible invalid Cuckoo node (%s): %s", self.url, e)

    def submit_task(self, task):
        try:
            url = os.path.join(self.url, "tasks", "create", "file")
            data = dict(
                package=task.package, timeout=task.timeout,
                priority=task.priority, options=task.options,
                machine=task.machine, platform=task.platform,
                tags=task.tags, custom=task.custom,
                memory=task.memory, clock=task.clock,
                enforce_timeout=task.enforce_timeout,
            )
            files = dict(file=open(task.path, "rb"))
            r = requests.post(url, data=data, files=files)
            task.node_id = self.id
            task.task_id = r.json()["task_id"]
        except Exception as e:
            log.critical("Error submitting task (task #%d, node %s): %s",
                         task.id, self.url, e)

    def get_report(self, task_id, fmt):
        try:
            url = os.path.join(self.url, "tasks", "report",
                               "%d" % task_id, fmt)
            return requests.get(url).content
        except Exception as e:
            log.critical("Error fetching report (task #%d, node %s): %s",
                         task_id, self.url, e)


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


class Task(db.Model):
    """Analysis task database model."""
    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.Text)
    package = db.Column(db.Text)
    timeout = db.Column(db.Integer)
    priority = db.Column(db.Integer)
    options = db.Column(db.Text)
    machine = db.Column(db.Text)
    platform = db.Column(db.Text)
    tags = db.Column(db.Text)
    custom = db.Column(db.Text)
    memory = db.Column(db.Text)
    clock = db.Column(db.Integer)
    enforce_timeout = db.Column(db.Text)

    # Cuckoo node and Task ID this has been submitted to.
    node_id = db.Column(db.Integer, db.ForeignKey("node.id"))
    task_id = db.Column(db.Integer)

    def __init__(self, path, package, timeout, priority, options, machine,
                 platform, tags, custom, memory, clock, enforce_timeout):
        self.path = path
        self.package = package
        self.timeout = timeout
        self.priority = priority
        self.options = options
        self.machine = machine
        self.platform = platform
        self.tags = tags
        self.custom = custom
        self.memory = memory
        self.clock = clock
        self.enforce_timeout = enforce_timeout
        self.node_id = None
        self.task_id = None


class StatusThread(threading.Thread):
    def run(self):
        while RUNNING:
            with app.app_context():
                start = datetime.datetime.now()
                statuses = {}

                # Request a status update on all Cuckoo nodes.
                for node in Node.query.all():
                    status = node.status()
                    if not status:
                        continue

                    log.debug("Status.. %s -> %s", node.name, status)

                    statuses[node.name] = status

                    if status["pending"] < 500:
                        # Only get nodes that have not been pushed yet.
                        q = Task.query.filter_by(node_id=None)

                        # Order by task ID.
                        q = q.order_by(Task.id)

                        # Only handle priority one cases here. TODO Other
                        # priorities are handled right away upon submission.
                        q = q.filter_by(priority=1)

                        # TODO Select only the tasks with appropriate tags
                        # selection.

                        for task in q.limit(500).all():
                            node.submit_task(task)

                db.session.commit()

                # Dump the uptime.
                if app.config["UPTIME_LOGFILE"] is not None:
                    with open(app.config["UPTIME_LOGFILE"], "ab") as f:
                        t = int(datetime.datetime.now().strftime("%s"))
                        c = json.dumps(dict(timestamp=t, status=statuses))
                        print>>f, c

                # Sleep until roughly a minute has gone by.
                diff = (datetime.datetime.now() - start).seconds
                if diff < 60:
                    time.sleep(60 - diff)


class NodeBaseApi(RestResource):
    def __init__(self, *args, **kwargs):
        RestResource.__init__(self, *args, **kwargs)

        self._parser = reqparse.RequestParser()
        self._parser.add_argument("name", type=str)
        self._parser.add_argument("url", type=str)


class NodeRootApi(NodeBaseApi):
    def get(self):
        nodes = {}
        for node in Node.query.all():
            machines = []
            for machine in node.machines.all():
                machines.append(dict(
                    name=machine.name,
                    platform=machine.platform,
                    tags=machine.tags,
                ))

            nodes[node.name] = dict(
                name=node.name,
                url=node.url,
                machines=machines,
            )
        return dict(nodes=nodes)

    def post(self):
        args = self._parser.parse_args()
        node = Node(name=args["name"], url=args["url"])

        machines = []
        for machine in node.list_machines():
            machines.append(dict(
                name=machine.name,
                platform=machine.platform,
                tags=machine.tags,
            ))
            node.machines.append(machine)
            db.session.add(machine)

        db.session.add(node)
        db.session.commit()
        return dict(name=node.name, machines=machines)


class NodeApi(NodeBaseApi):
    def get(self, name):
        node = Node.query.filter_by(name=name).first()
        return dict(name=node.name, url=node.url)

    def put(self, name):
        args = self._parser.parse_args()
        node = Node.query.filter_by(name=name)
        node.name = args["name"]
        node.url = args["url"]
        db.session.commit()

    def delete(self, name):
        node = Node.query.filter_by(name=name).first()
        db.session.delete(node)
        db.session.commit()


class TaskBaseApi(RestResource):
    def __init__(self, *args, **kwargs):
        RestResource.__init__(self, *args, **kwargs)

        self._parser = reqparse.RequestParser()
        self._parser.add_argument("package", type=str)
        self._parser.add_argument("timeout", type=int)
        self._parser.add_argument("priority", type=int, default=1)
        self._parser.add_argument("options", type=str)
        self._parser.add_argument("machine", type=str)
        self._parser.add_argument("platform", type=str, default="windows")
        self._parser.add_argument("tags", type=str)
        self._parser.add_argument("custom", type=str)
        self._parser.add_argument("memory", type=str)
        self._parser.add_argument("clock", type=int)
        self._parser.add_argument("enforce_timeout", type=bool)


class TaskApi(TaskBaseApi):
    def get(self, task_id):
        task = Task.query.get(task_id)

        return dict(tasks={task.id: dict(
            task_id=task.id, path=task.path, package=task.package,
            timeout=task.timeout, priority=task.priority,
            options=task.options, machine=task.machine,
            platform=task.platform, tags=task.tags,
            custom=task.custom, memory=task.memory,
            clock=task.clock, enforce_timeout=task.enforce_timeout
        )})


class TaskRootApi(TaskBaseApi):
    def get(self):
        tasks = Task.query.all()

        ret = {}
        for task in tasks:
            ret[task.id] = dict(
                task_id=task.id, path=task.path, package=task.package,
                timeout=task.timeout, priority=task.priority,
                options=task.options, machine=task.machine,
                platform=task.platform, tags=task.tags,
                custom=task.custom, memory=task.memory,
                clock=task.clock, enforce_timeout=task.enforce_timeout
            )
        return dict(tasks=ret)

    def post(self):
        args = self._parser.parse_args()
        f = request.files["file"]

        _, path = tempfile.mkstemp(dir=app.config["SAMPLES_DIRECTORY"])
        f.save(path)

        task = Task(path=path, **args)
        db.session.add(task)
        db.session.commit()
        return dict(task_id=task.id)


class ReportApi(RestResource):
    def get(self, task_id):
        # TODO Check whether the analysis has actually finished.
        task = Task.query.get(task_id)
        if not task:
            abort(404, message="Task not found")

        node = Node.query.get(task.node_id)
        r = node.get_report(task.task_id, "json")
        # TODO Only json.loads() for the JSON reporting format.
        return json.loads(r)


def create_app(database_connection, debug=False, samples_directory=None,
               uptime_logfile=None):
    app = Flask("Distributed Cuckoo")
    app.debug = debug
    app.config["SQLALCHEMY_DATABASE_URI"] = database_connection
    app.config["SECRET_KEY"] = 'A'*32
    app.config["SAMPLES_DIRECTORY"] = samples_directory
    app.config["UPTIME_LOGFILE"] = uptime_logfile

    restapi = RestApi(app)
    restapi.add_resource(NodeRootApi, "/node")
    restapi.add_resource(NodeApi, "/node/<string:name>")
    restapi.add_resource(TaskRootApi, "/task")
    restapi.add_resource(TaskApi, "/task/<int:task_id>")
    restapi.add_resource(ReportApi, "/report/<int:task_id>")

    db.init_app(app)

    with app.app_context():
        db.create_all()

    return app


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("host", nargs="?", default="0.0.0.0", help="Host to listen on")
    p.add_argument("port", nargs="?", type=int, default=9003, help="Port to listen on")
    p.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    p.add_argument("--db", type=str, default="sqlite:///dist.db", help="Database connection string")
    p.add_argument("--samples-directory", type=str, help="Database connection string")
    p.add_argument("--uptime-logfile", type=str, help="Database connection string")
    args = p.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    log = logging.getLogger("cuckoo.distributed")

    if args.samples_directory is None:
        args.samples_directory = tempfile.mkdtemp()

    RUNNING = True
    app = create_app(database_connection=args.db, debug=args.debug,
                     samples_directory=args.samples_directory,
                     uptime_logfile=args.uptime_logfile)

    t = StatusThread()
    t.daemon = True
    t.start()

    app.run(host=args.host, port=args.port)
