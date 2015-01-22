#!/usr/bin/env python
# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import ConfigParser
import datetime
import hashlib
import json
import logging
import multiprocessing
import os
import sys
import tempfile
import threading
import time

RESET_LASTCHECK = 50


def required(package):
    sys.exit("The %s package is required: pip install %s" %
             (package, package))

try:
    from flask import Flask, request, make_response
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
                package=task.package,
                timeout=task.timeout,
                priority=task.priority,
                options=task.options,
                machine=task.machine,
                platform=task.platform,
                tags=task.tags,
                custom=task.custom,
                owner=task.owner,
                memory=task.memory,
                clock=task.clock,
                enforce_timeout=task.enforce_timeout,
            )

            # If the file does not exist anymore, ignore it and move on
            # to the next file.
            if not os.path.isfile(task.path):
                task.finished = True
                db.session.commit()
                db.session.refresh(task)
                return

            files = {'file': (task.filename, open(task.path, "rb"))}
            r = requests.post(url, data=data, files=files)
            task.node_id = self.id
            task.task_id = r.json()["task_id"]

            # We have to refresh() the task object because otherwise we get
            # the unmodified object back in further sql queries..
            # TODO Commit once, refresh() all at once. This could potentially
            # become a bottleneck.
            db.session.commit()
            db.session.refresh(task)
        except Exception as e:
            log.critical("Error submitting task (task #%d, node %s): %s",
                         task.id, self.name, e)

    def fetch_tasks(self, status, since=None):
        try:
            url = os.path.join(self.url, "tasks", "list")
            params = dict(completed_after=since, status=status)
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
    finished = db.Column(db.Boolean, nullable=False)

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
        self.finished = False


class NodeHandler(object):
    def __init__(self, node):
        self.name = node.name
        self.node = node

        multiprocessing.log_to_stderr()
        self.log = multiprocessing.get_logger()

        if app.config["VERBOSE"]:
            self.log.setLevel(logging.DEBUG)
        else:
            self.log.setLevel(logging.INFO)

    def submit_tasks(self, node):
        # Only get nodes that have not been pushed yet.
        q = Task.query.filter_by(node_id=None, finished=False)

        # Order by task ID.
        q = q.order_by(Task.id)

        # Only handle priority one cases here. TODO Other
        # priorities are handled right away upon submission.
        q = q.filter_by(priority=1)

        # TODO Select only the tasks with appropriate tags selection.

        for task in q.limit(app.config["BATCH_SIZE"]).all():
            node.submit_task(task)

    def fetch_latest_reports(self, node, last_check):
        # Fetch the latest reports.
        for task in node.fetch_tasks("reported", since=last_check):
            q = Task.query.filter_by(node_id=node.id, task_id=task["id"])
            t = q.first()

            if t is None:
                self.log.debug("Node %s task #%d has not been submitted "
                               "by us!", node.name, task["id"])
                continue

            # Update the last_check value of the Node for the next iteration.
            completed_on = datetime.datetime.strptime(task["completed_on"],
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
                if report is None or report.status_code != 200:
                    self.log.debug("Error fetching %s report for task #%d",
                                   report_format, t.task_id)
                    continue

                path = os.path.join(dirpath, "report.%s" % report_format)
                with open(path, "wb") as f:
                    for chunk in report.iter_content(chunk_size=1024*1024):
                        f.write(chunk)

            t.finished = True

            # Delete the task and all its associated files.
            # (It will still remain in the nodes' database, though.)
            node.delete_task(t.task_id)

            db.session.commit()
            db.session.refresh(t)

    def process(self):
        start = int(datetime.datetime.now().strftime("%s"))

        status = self.node.status()
        if not status:
            return start, self.name, None

        self.log.debug("Status.. %s -> %s", self.node.name, status)

        if status["pending"] < app.config["BATCH_SIZE"]:
            self.submit_tasks(self.node)

        if self.node.last_check:
            last_check = int(self.node.last_check.strftime("%s"))
        else:
            last_check = 0

        self.fetch_latest_reports(self.node, last_check)

        # We just fetched all the "latest" tasks. However, it is for some
        # reason possible that some reports are never fetched, and therefore
        # we reset the "last_check" parameter when more than 50 tasks have not
        # been fetched, thus preventing running out of diskspace.
        status = self.node.status()
        if status and status["reported"] > RESET_LASTCHECK:
            self.log.debug("Reached reset-lastcheck threshold, "
                           "resetting last-check.")
            self.node.last_check = None

        # The last_check field of each node object has been updated as well as
        # the finished field for each task that has been completed.
        db.session.commit()
        db.session.refresh(self.node)
        return start, self.name, status


def process_node(node):
    return NodeHandler(node).process()


class NodeBaseApi(RestResource):
    def __init__(self, *args, **kwargs):
        RestResource.__init__(self, *args, **kwargs)

        self._parser = reqparse.RequestParser()
        self._parser.add_argument("name", type=str)
        self._parser.add_argument("url", type=str)
        self._parser.add_argument("ip", type=str)

    def _resolve_url(self, args):
        if "url" not in args and "ip" not in args:
            abort(404, "Node address not found")

        if "ip" in args:
            return "http://%s:8090/" % args["ip"]

        return args["url"]


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

        if "name" not in args:
            abort(404, "Cuckoo node name not found")

        node = Node(name=args["name"], url=self._resolve_url(args))

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
        node = Node.query.filter_by(name=name).first()
        node.name = args["name"]
        node.url = self._resolve_url(args)
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
        self._parser.add_argument("owner", type=str)
        self._parser.add_argument("memory", type=str)
        self._parser.add_argument("clock", type=int)
        self._parser.add_argument("enforce_timeout", type=bool)


class TaskApi(TaskBaseApi):
    def get(self, task_id):
        task = Task.query.get(task_id)
        if task is None:
            abort(404, message="Task not found")

        return dict(tasks={task.id: dict(
            task_id=task.id,
            path=task.path,
            filename=task.filename,
            package=task.package,
            timeout=task.timeout,
            priority=task.priority,
            options=task.options,
            machine=task.machine,
            platform=task.platform,
            tags=task.tags,
            custom=task.custom,
            owner=task.owner,
            memory=task.memory,
            clock=task.clock,
            enforce_timeout=task.enforce_timeout,
        )})

    def delete(self, task_id):
        task = Task.query.get(task_id)
        if task is None:
            abort(404, "Task not found")

        # Remove all available reports.
        dirpath = os.path.join(app.config["REPORTS_DIRECTORY"],
                               "%d" % task_id)
        for report_format in app.config["REPORT_FORMATS"]:
            path = os.path.join(dirpath, "report.%s" % report_format)
            if os.path.isfile(path):
                os.unlink(path)

        # Remove the sample related to this task.
        if os.path.isfile(task.path):
            os.unlink(task.path)

        # TODO Don't delete the task, but instead change its state to deleted.
        db.session.delete(task)
        db.session.commit()


class TaskRootApi(TaskBaseApi):
    def get(self):
        offset = request.args.get("offset")
        limit = request.args.get("limit")
        finished = request.args.get("finished")
        owner = request.args.get("owner")

        q = Task.query

        if finished is not None:
            q = q.filter_by(finished=bool(int(finished)))

        if offset is not None:
            q = q.offset(int(offset))

        if limit is not None:
            q = q.limit(int(limit))

        if owner:
            q = q.filter_by(owner=owner)

        tasks = q.all()

        ret = {}
        for task in tasks:
            ret[task.id] = dict(
                id=task.id,
                path=task.path,
                filename=task.filename,
                package=task.package,
                timeout=task.timeout,
                priority=task.priority,
                options=task.options,
                machine=task.machine,
                platform=task.platform,
                tags=task.tags,
                custom=task.custom,
                owner=task.owner,
                memory=task.memory,
                clock=task.clock,
                enforce_timeout=task.enforce_timeout,
                task_id=task.task_id,
                node_id=task.node_id,
            )
        return dict(tasks=ret)

    def post(self):
        args = self._parser.parse_args()
        f = request.files["file"]

        fd, path = tempfile.mkstemp(dir=app.config["SAMPLES_DIRECTORY"])
        f.save(path)
        os.close(fd)

        task = Task(path=path, filename=os.path.basename(f.filename), **args)
        db.session.add(task)
        db.session.commit()
        return dict(task_id=task.id)


class ReportApi(RestResource):
    REPORT_FORMATS = {
        "json": "json",
    }

    def get(self, task_id, report="json"):
        task = Task.query.get(task_id)
        if not task:
            abort(404, message="Task not found")

        if not task.finished:
            abort(420, message="Task not finished yet")

        path = os.path.join(app.config["REPORTS_DIRECTORY"],
                            "%d" % task_id, "report.%s" % report)
        if not os.path.isfile(path):
            abort(404, message="Report format not found")

        f = open(path, "rb")

        if self.REPORT_FORMATS[report] == "json":
            return json.load(f)

        if self.REPORT_FORMATS[report] == "xml":
            return f.read()

        abort(404, message="Invalid report format")


class StatusRootApi(RestResource):
    def get(self):
        null = None

        tasks = Task.query.filter(Task.node_id != null)

        tasks = dict(
            processing=tasks.filter_by(finished=False).count(),
            processed=tasks.filter_by(finished=True).count(),
            pending=Task.query.filter_by(node_id=None).count(),
        )
        return dict(nodes=app.config["STATUSES"], tasks=tasks)


def output_json(data, code, headers=None):
    resp = make_response(json.dumps(data), code)
    resp.headers.extend(headers or {})
    return resp


def output_xml(data, code, headers=None):
    resp = make_response(data, code)
    resp.headers.extend(headers or {})
    return resp


class DistRestApi(RestApi):
    def __init__(self, *args, **kwargs):
        RestApi.__init__(self, *args, **kwargs)
        self.representations = {
            "application/xml": output_xml,
            "application/json": output_json,
        }


class SchedulerThread(threading.Thread):
    def _callback(self, (start, name, status)):
        app.config["STATUSES"][name] = status

        # If available, we'll want to dump the uptime.
        if app.config["UPTIME_LOGFILE"]:
            try:
                with open(app.config["UPTIME_LOGFILE"], "ab") as f:
                    c = json.dumps(dict(timestamp=start, name=name,
                                        status=status))
                    print>>f, c
            except Exception as e:
                log.warning("Error dumping uptime for node %r: %s", name, e)

    def run(self):
        m = multiprocessing.Pool(processes=app.config["WORKER_PROCESSES"])
        nodes = []

        while app.config["RUNNING"]:
            t = time.time()

            # We resolve the nodes every iteration, that way new nodes may
            # be added on-the-fly.
            with app.app_context():
                for node in Node.query.filter_by(enabled=True).all():
                    if node.name not in nodes:
                        nodes.append(node.name)
                        log.info("Detected Cuckoo node '%s': %s",
                                 node.name, node.url)

                    # Detach the object from the session. Probably required
                    # for SQLite3 as this object will be used in a
                    # different process.
                    db.make_transient(node)

                    m.apply_async(process_node, (node,),
                                  callback=self._callback)

            if t + app.config["INTERVAL"] > time.time():
                time.sleep(t + app.config["INTERVAL"] - time.time())

        m.close()


def create_app(database_connection):
    app = Flask("Distributed Cuckoo")
    app.config["SQLALCHEMY_DATABASE_URI"] = database_connection
    app.config["SECRET_KEY"] = os.urandom(32)

    restapi = DistRestApi(app)
    restapi.add_resource(NodeRootApi, "/node")
    restapi.add_resource(NodeApi, "/node/<string:name>")
    restapi.add_resource(TaskRootApi, "/task")
    restapi.add_resource(TaskApi, "/task/<int:task_id>")
    restapi.add_resource(ReportApi,
                         "/report/<int:task_id>",
                         "/report/<int:task_id>/<string:report>")
    restapi.add_resource(StatusRootApi, "/status")

    db.init_app(app)

    with app.app_context():
        db.create_all()

    return app


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("host", nargs="?", default="127.0.0.1", help="Host to listen on")
    p.add_argument("port", nargs="?", type=int, default=9003, help="Port to listen on")
    p.add_argument("-s", "--settings", type=str, help="Settings file.")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = p.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    log = logging.getLogger("cuckoo.distributed")

    if not args.settings:
        dirpath = os.path.abspath(os.path.dirname(__file__))
        conf_path = os.path.join(dirpath, "..", "conf", "distributed.conf")
        args.settings = conf_path

    s = ConfigParser.ConfigParser()
    s.read(args.settings)

    if not s.get("distributed", "database"):
        sys.exit("Please configure a database connection.")

    app = create_app(database_connection=s.get("distributed", "database"))

    report_formats = []
    for report_format in s.get("distributed", "report_formats").split(","):
        report_formats.append(report_format.strip())

    app.config["REPORT_FORMATS"] = report_formats

    app.config["SAMPLES_DIRECTORY"] = \
        s.get("distributed", "samples_directory")

    if not app.config["SAMPLES_DIRECTORY"]:
        sys.exit("Please configure a samples directory path.")

    if not os.path.isdir(app.config["SAMPLES_DIRECTORY"]):
        os.makedirs(app.config["SAMPLES_DIRECTORY"])

    app.config["REPORTS_DIRECTORY"] = \
        s.get("distributed", "reports_directory")

    if not app.config["REPORTS_DIRECTORY"]:
        sys.exit("Please configure a reports directory path.")

    if not os.path.isdir(app.config["REPORTS_DIRECTORY"]):
        os.makedirs(app.config["REPORTS_DIRECTORY"])

    app.config["RUNNING"] = True
    app.config["STATUSES"] = {}
    app.config["VERBOSE"] = args.verbose
    app.config["WORKER_PROCESSES"] = \
        s.getint("distributed", "worker_processes")
    app.config["UPTIME_LOGFILE"] = s.get("distributed", "uptime_logfile")
    app.config["INTERVAL"] = s.getint("distributed", "interval")
    app.config["BATCH_SIZE"] = s.getint("distributed", "batch_size")

    t = SchedulerThread()
    t.daemon = True
    t.start()

    app.run(host=args.host, port=args.port)
