#!/usr/bin/env python
# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
from datetime import datetime
import hashlib
import json
import logging
import os.path
import sys
import tempfile
import threading
import time

INTERVAL = 30
MINIMUMQUEUE = 500


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
    name = db.Column(db.Text, nullable=False)
    url = db.Column(db.Text, nullable=False)
    enabled = db.Column(db.Boolean, nullable=False)
    last_check = db.Column(db.DateTime(timezone=False))
    machines = db.relationship("Machine", backref="node", lazy="dynamic")

    def __init__(self, name, url, enabled=True):
        self.name = name
        self.url = url
        self.enabled = enabled

    def list_machines(self):
        try:
            r = requests.get(os.path.join(self.url, "machines", "list"))

            for machine in r.json()["machines"]:
                yield Machine(name=machine["name"],
                              platform=machine["platform"],
                              tags=machine["tags"])
        except Exception as e:
            abort(404,
                  message="Invalid Cuckoo node (%s): %s" % (self.name, e))

    def status(self):
        try:
            r = requests.get(os.path.join(self.url, "cuckoo", "status"))
            return r.json()["tasks"]
        except Exception as e:
            log.critical("Possible invalid Cuckoo node (%s): %s",
                         self.name, e)

        return {}

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
                         task.id, self.name, e)

    def completed_tasks(self, since=None):
        try:
            url = os.path.join(self.url, "tasks", "list")
            params = dict(completed_after=since)
            r = requests.get(url, params=params)
            return r.json()["tasks"]
        except Exception as e:
            log.critical("Error listing completed tasks (node %s): %s",
                         self.name, e)

        return []

    def get_report(self, task_id, fmt, stream=False):
        try:
            url = os.path.join(self.url, "tasks", "report",
                               "%d" % task_id, fmt)
            return requests.get(url, stream=stream)
        except Exception as e:
            log.critical("Error fetching report (task #%d, node %s): %s",
                         task_id, self.url, e)

    def delete_task(self, task_id):
        try:
            url = os.path.join(self.url, "tasks", "delete", "%d" % task_id)
            return requests.get(url).status_code == 200
        except Exception as e:
            log.critical("Error deleting task (task #%d, node %s): %s",
                         task_id, self.name, e)


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
    finished = db.Column(db.Boolean, nullable=False)

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
        self.finished = False


class StatusThread(threading.Thread):
    def submit_tasks(self, node):
        # Only get nodes that have not been pushed yet.
        q = Task.query.filter_by(node_id=None)

        # Order by task ID.
        q = q.order_by(Task.id)

        # Only handle priority one cases here. TODO Other
        # priorities are handled right away upon submission.
        q = q.filter_by(priority=1)

        # TODO Select only the tasks with appropriate tags selection.

        for task in q.limit(MINIMUMQUEUE).all():
            node.submit_task(task)

    def fetch_latest_reports(self, node, last_check):
        # Fetch the latest reports.
        for task in node.completed_tasks(since=last_check):
            q = Task.query.filter_by(node_id=node.id, task_id=task["id"])
            t = q.first()

            # Update the last_check value of the Node for the next
            # iteration.
            completed_on = datetime.strptime(task["completed_on"],
                                             "%Y-%m-%d %H:%M:%S")
            if not node.last_check or completed_on > node.last_check:
                node.last_check = completed_on

            dirpath = os.path.join(app.config["REPORTS_DIRECTORY"],
                                   "%d" % t.id)

            if not os.path.isdir(dirpath):
                os.makedirs(dirpath)

            # Fetch each requested report.
            for report_format in app.config["REPORT_FORMATS"]:
                report = node.get_report(t.task_id, report_format,
                                         stream=True)
                if report is None:
                    continue

                path = os.path.join(dirpath, "report.%s" % report_format)
                with open(path, "wb") as f:
                    for chunk in report.iter_content(chunk_size=1024*1024):
                        f.write(chunk)

            t.finished = True

            # Delete the task and all its associated files.
            # (It will still remain in the nodes' database, though.)
            node.delete_task(t.task_id)

    def run(self):
        while RUNNING:
            with app.app_context():
                start = datetime.now()
                statuses = {}

                # Request a status update on all Cuckoo nodes.
                for node in Node.query.filter_by(enabled=True).all():
                    status = node.status()
                    if not status:
                        continue

                    log.debug("Status.. %s -> %s", node.name, status)

                    statuses[node.name] = status

                    if status["pending"] < MINIMUMQUEUE:
                        self.submit_tasks(node)

                    self.fetch_latest_reports(node, node.last_check or 0)

                # The last_check field of each node object has been updated as
                # well as the finished field for each task that has been
                # completed.
                db.session.commit()

                # Dump the uptime.
                if app.config["UPTIME_LOGFILE"] is not None:
                    with open(app.config["UPTIME_LOGFILE"], "ab") as f:
                        t = int(start.strftime("%s"))
                        c = json.dumps(dict(timestamp=t, status=statuses))
                        print>>f, c

                # Sleep until roughly half a minute (configurable through
                # INTERVAL) has gone by.
                diff = (datetime.now() - start).seconds
                if diff < INTERVAL:
                    time.sleep(INTERVAL - diff)


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
        node.enabled = False
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

        if not task.finished:
            abort(404, message="Task not finished yet")

        node = Node.query.get(task.node_id)
        r = node.get_report(task.task_id, "json")
        # TODO Only json.loads() for the JSON reporting format.
        return json.loads(r.content) if r else None


def create_app(database_connection, debug=False):
    app = Flask("Distributed Cuckoo")
    app.debug = debug
    app.config["SQLALCHEMY_DATABASE_URI"] = database_connection
    app.config["SECRET_KEY"] = os.urandom(32)

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
    p.add_argument("--samples-directory", type=str, required=True, help="Samples directory")
    p.add_argument("--uptime-logfile", type=str, help="Uptime logfile path")
    p.add_argument("--report-formats", type=str, required=True, help="Reporting formats to fetch")
    p.add_argument("--reports-directory", type=str, required=True, help="Reports directory")
    args = p.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    log = logging.getLogger("cuckoo.distributed")

    report_formats = []
    for report_format in args.report_formats.split(","):
        report_formats.append(report_format.strip())

    if not os.path.isdir(args.samples_directory):
        os.makedirs(args.samples_directory)

    if not os.path.isdir(args.reports_directory):
        os.makedirs(args.reports_directory)

    RUNNING = True
    app = create_app(database_connection=args.db, debug=args.debug)
    app.config["SAMPLES_DIRECTORY"] = args.samples_directory
    app.config["UPTIME_LOGFILE"] = args.uptime_logfile
    app.config["REPORT_FORMATS"] = report_formats
    app.config["REPORTS_DIRECTORY"] = args.reports_directory

    t = StatusThread()
    t.daemon = True
    t.start()

    app.run(host=args.host, port=args.port)
